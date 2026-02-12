// src/modules/magic-link/service.ts
// ============================================================================
// Business-Logik fuer Magic-Link-Login (db-auth26)
// ============================================================================

import { randomUUID } from "node:crypto";
import type { DbClient } from "../../libs/db.js";
import { dbHealth } from "../../libs/db.js";
import { hashOpaqueToken } from "../../libs/crypto.js";
import { signAccessToken } from "../../libs/jwt.js";

import {
  createMagicLinkTokenRecord,
  deleteMagicLinkTokenById,
  findMagicLinkTokenByRawToken,
  findUserByEmailRow,
  findUserById,
} from "./repository.js";

import { createRefreshTokenRecord, createSession } from "../identity/repository.js";

import type {
  MagicLinkConsumeInput,
  MagicLinkConsumeResult,
  MagicLinkHealth,
  MagicLinkRequestInput,
  MagicLinkRequestResult,
} from "./types.js";

const MAGIC_LINK_TTL_SEC = 60 * 15; // 15m
const ACCESS_TTL_SEC = 60 * 15; // 15m
const REFRESH_TTL_SEC = 60 * 60 * 24 * 30; // 30d

export class InvalidMagicLinkTokenError extends Error {
  statusCode = 400;

  constructor(message = "Invalid magic link token") {
    super(message);
    this.name = "InvalidMagicLinkTokenError";
  }
}

export class ExpiredMagicLinkTokenError extends Error {
  statusCode = 410;

  constructor(message = "Magic link token has expired") {
    super(message);
    this.name = "ExpiredMagicLinkTokenError";
  }
}

export async function requestMagicLink(
  db: DbClient,
  input: MagicLinkRequestInput,
): Promise<MagicLinkRequestResult> {
  const email = input.email.trim().toLowerCase();
  const user = await findUserByEmailRow(db, email);

  if (!user || !user.is_active) {
    return { requestAccepted: true };
  }

  const token = randomUUID();
  await createMagicLinkTokenRecord(db, {
    userId: user.id,
    token,
    ttlSec: MAGIC_LINK_TTL_SEC,
  });

  return { requestAccepted: true };
}

export async function consumeMagicLink(
  db: DbClient,
  input: MagicLinkConsumeInput,
): Promise<MagicLinkConsumeResult> {
  const rawToken = input.token.trim();
  if (!rawToken) {
    throw new InvalidMagicLinkTokenError("Empty magic link token");
  }

  const tokenRow = await findMagicLinkTokenByRawToken(db, rawToken);
  if (!tokenRow) {
    throw new InvalidMagicLinkTokenError("Magic link token not found");
  }

  if (tokenRow.expires_at.getTime() <= Date.now()) {
    await deleteMagicLinkTokenById(db, tokenRow.id);
    throw new ExpiredMagicLinkTokenError();
  }

  const user = await findUserById(db, tokenRow.user_id);
  if (!user || !user.is_active) {
    await deleteMagicLinkTokenById(db, tokenRow.id);
    throw new InvalidMagicLinkTokenError("User for magic link not found/active");
  }

  await deleteMagicLinkTokenById(db, tokenRow.id);

  const sessionId = randomUUID();
  await createSession(db, {
    sessionId,
    tenantId: user.tenant_id,
    userId: user.id,
    ttlSec: ACCESS_TTL_SEC,
  });

  const { token: accessToken, exp: accessExp } = await signAccessToken(
    user.id,
    user.tenant_id,
    ACCESS_TTL_SEC,
    {
      sid: sessionId,
      ver: 1,
    },
  );

  const refreshToken = randomUUID();
  const refreshTokenHash = hashOpaqueToken(refreshToken);
  await createRefreshTokenRecord(db, {
    tenantId: user.tenant_id,
    userId: user.id,
    tokenHash: refreshTokenHash,
    ttlSec: REFRESH_TTL_SEC,
    familyId: sessionId,
  });

  return {
    user: {
      id: user.id,
      email: user.email,
      tenantId: user.tenant_id,
    },
    accessToken,
    accessTokenExpiresAt: accessExp,
    refreshToken,
    refreshTokenExpiresAt: Math.floor(Date.now() / 1000) + REFRESH_TTL_SEC,
  };
}

export async function getMagicLinkHealth(): Promise<MagicLinkHealth> {
  try {
    const { ok, error } = await dbHealth();
    return {
      healthy: ok,
      db: {
        ok,
        error: error ?? null,
      },
    };
  } catch (err: any) {
    return {
      healthy: false,
      db: {
        ok: false,
        error: err?.message ?? "Unknown DB error",
      },
    };
  }
}
