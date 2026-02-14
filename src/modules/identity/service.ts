// src/modules/identity/service.ts
// ============================================================================
// Identity-Service (RLS-aware)
// ----------------------------------------------------------------------------
// Verantwortlichkeiten:
// - Login mit E-Mail/Passwort
// - Refresh über opaques Refresh-Token (Rotation)
// - JWT Access Token ist identity-first:
//   * tenant_id ist optional (global user Modell)
//   * Tenant-Zugehörigkeit wird bei Bedarf via Membership geprüft (Gateway/internal verify)
//
// WICHTIG (RLS):
// - Alle DB-Operationen laufen über den pro-Request DbClient (PoolClient),
//   der durch tenant-db-context.ts vorbereitet wurde:
//     BEGIN;
//     SET LOCAL ROLE app_auth;
// ============================================================================

import { randomUUID } from "node:crypto";
import type { DbClient } from "../../libs/db.js";
import { hashOpaqueToken, verifyPassword } from "../../libs/crypto.js";
import { signAccessToken } from "../../libs/jwt.js";

import {
  deleteRefreshTokenById,
  findLoginCandidateByEmail,
  findRefreshTokenByHash,
  createSession,
  createRefreshTokenRecord,
  markRefreshTokenRotated,
  resolveUserAuthContext,
  revokeRefreshFamily,
} from "./repository.js";

import type { LoginInput, LoginResult, RefreshInput, RefreshResult } from "./types.js";

// ---------------------------------------------------------------------------
// TTL-Konstanten
// - später idealerweise via env.ts (JWT_ACCESS_TTL / REFRESH_TTL etc.)
// ---------------------------------------------------------------------------

const ACCESS_TTL_SEC = 60 * 15;            // 15 Minuten
const REFRESH_TTL_SEC = 60 * 60 * 24 * 30; // 30 Tage
const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,t=3,p=1$IrPUm8rK8bWhiyu2hAQnIg$H2ht46hQgLVOe5TZB6EPU2nlPJ6jYFEbJgNUiLUbk9M";

export class RefreshFailedError extends Error {
  constructor() {
    super("refresh_failed");
    this.name = "RefreshFailedError";
  }
}

export class LoginFailedError extends Error {
  constructor() {
    super("invalid_credentials");
    this.name = "LoginFailedError";
  }
}

export class RefreshReuseDetectedError extends Error {
  constructor() {
    super("refresh_reuse_detected");
    this.name = "RefreshReuseDetectedError";
  }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export async function loginWithEmailPassword(
  db: DbClient,
  params: LoginInput,
): Promise<LoginResult> {
  const user = await findLoginCandidateByEmail(db, {
    email: params.email,
    requestedTenantId: params.requestedTenantId,
  });

  // Timing-Hardening: auch bei unbekanntem User wird eine Verifikation ausgefuehrt.
  const passwordHash = user?.password_hash ?? DUMMY_PASSWORD_HASH;
  const ok = await verifyPassword(passwordHash, params.password);

  // bewusst generisch: keine Info, ob User existiert / aktiv ist
  if (!user || !user.is_active || !user.verified_at || !ok) {
    throw new LoginFailedError();
  }

  const ctx = await resolveUserAuthContext(db, {
    userId: user.id,
    requestedTenantId: params.requestedTenantId,
  });
  const primaryRole = ctx.role;
  const plan = ctx.plan || "free";
  const tenantId = ctx.tenantId;
  const sessionId = randomUUID();

  // Session (Audit/Monitoring). TTL ist hier an ACCESS gekoppelt – ok als Default.
  await createSession(db, {
    sessionId,
    userId: user.id,
    ttlSec: ACCESS_TTL_SEC,
  });

  // JWT Access Token: tenant_id optional (global identity)
  const { token: accessToken, exp: accessExp } = await signAccessToken(
    user.id,
    tenantId,
    ACCESS_TTL_SEC,
    {
      sid: sessionId,
      ver: 1,
      role: primaryRole,
      roles: ctx.roles,
      plan,
    },
  );

  // Refresh Token: opaques Token (UUID) in DB gespeichert (Rotation über DB Record)
  const refreshToken = randomUUID();
  const refreshTokenHash = hashOpaqueToken(refreshToken);
  await createRefreshTokenRecord(db, {
    userId: user.id,
    tokenHash: refreshTokenHash,
    ttlSec: REFRESH_TTL_SEC,
    familyId: sessionId,
  });

  const nowSec = Math.floor(Date.now() / 1000);
  const refreshTokenExpiresAt = nowSec + REFRESH_TTL_SEC;

  return {
    user: {
      id: user.id,
      email: user.email,
      ...(tenantId ? { tenantId } : {}),
      role: primaryRole,
      roles: ctx.roles,
      plan,
    },
    sessionId,
    accessToken,
    accessTokenExpiresAt: accessExp,
    refreshToken,
    refreshTokenExpiresAt,
  };
}

// ---------------------------------------------------------------------------
// Refresh (Rotation)
// ---------------------------------------------------------------------------

export async function refreshWithToken(
  db: DbClient,
  params: RefreshInput,
): Promise<RefreshResult> {
  const incomingTokenHash = hashOpaqueToken(params.refreshToken);

  const stored = await findRefreshTokenByHash(db, incomingTokenHash);
  if (!stored) {
    throw new RefreshFailedError();
  }

  if (stored.replaced_by) {
    await revokeRefreshFamily(db, stored.family_id);
    throw new RefreshReuseDetectedError();
  }

  const isExpired = new Date(stored.expires_at).getTime() <= Date.now();
  if (stored.revoked_at || isExpired) {
    throw new RefreshFailedError();
  }

  const userId = stored.user_id;
  const ctx = await resolveUserAuthContext(db, {
    userId,
    requestedTenantId: params.requestedTenantId,
  });
  const tenantId = ctx.tenantId;
  const roles = ctx.roles?.length ? ctx.roles : ["member"];
  const primaryRole = ctx.role || roles[0] || "member";
  const plan = ctx.plan || "free";

  // Neues Refresh-Token erzeugen (gleiche Family für Replay-Defense-Workflows)
  const newRefreshToken = randomUUID();
  const newRefreshTokenHash = hashOpaqueToken(newRefreshToken);
  const rotated = await createRefreshTokenRecord(db, {
    userId,
    tokenHash: newRefreshTokenHash,
    ttlSec: REFRESH_TTL_SEC,
    familyId: stored.family_id,
  });

  // Rotation finalisieren: altes Token atomar als ersetzt markieren.
  const oldTokenRotated = await markRefreshTokenRotated(db, {
    tokenId: stored.id,
    replacedById: rotated.id,
  });
  if (!oldTokenRotated) {
    // Defensiv: neues Token aufraeumen, wenn altes nicht mehr aktiv war (race/replay).
    await deleteRefreshTokenById(db, rotated.id);
    throw new RefreshFailedError();
  }

  // Neues Access-Token (inkl. tenant_id)
  const { token: newAccessToken, exp: newAccessExp } = await signAccessToken(
    userId,
    tenantId,
    ACCESS_TTL_SEC,
    {
      sid: stored.family_id,
      ver: 1,
      role: primaryRole,
      roles,
      plan,
    },
  );

  const nowSec = Math.floor(Date.now() / 1000);
  const newRefreshExp = nowSec + REFRESH_TTL_SEC;

  return {
    accessToken: newAccessToken,
    accessTokenExpiresAt: newAccessExp,
    refreshToken: newRefreshToken,
    refreshTokenExpiresAt: newRefreshExp,
  };
}
