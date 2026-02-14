// src/modules/identity/repository.ts
// ============================================================================
// Identity-Repository
// ----------------------------------------------------------------------------
// - Zugriff auf auth.users/auth.credentials, auth.sessions, auth.refresh_tokens
// - RLS-aware: arbeitet nur mit dem pro-Request-DB-Client (DbClient)
// - KEINE Business-Logik, nur Datenzugriff
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import type {
  LoginCandidateRow,
  RefreshTokenRow,
  SessionRow,
  UserRow,
} from "./types.js";

// ---------------------------------------------------------------------------
// User + Credentials
// ---------------------------------------------------------------------------

export async function findLoginCandidateByEmail(
  client: DbClient,
  opts: {
    email: string;
    requestedTenantId?: string;
  },
): Promise<LoginCandidateRow | null> {
  const { rows } = await client.query<LoginCandidateRow>(
    `
      SELECT
        user_id AS id,
        tenant_id,
        email,
        password_hash,
        is_active,
        verified_at
      FROM auth.resolve_login_candidate($1::extensions.citext, $2::uuid)
      LIMIT 1;
    `,
    [opts.email.toLowerCase(), opts.requestedTenantId ?? null],
  );

  return rows[0] ?? null;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export async function createSession(
  client: DbClient,
  opts: {
    userId: string;
    ttlSec: number;
    sessionId?: string;
  },
): Promise<SessionRow> {
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<SessionRow>(
    `
      INSERT INTO auth.sessions (id, user_id, expires_at)
      VALUES (COALESCE($1::uuid, extensions.gen_random_uuid()), $2, $3)
      RETURNING
        id,
        user_id,
        created_at,
        expires_at,
        revoked_at;
    `,
    [opts.sessionId ?? null, opts.userId, expires],
  );

  return rows[0];
}

export async function revokeSessionByIdForUser(
  client: DbClient,
  opts: {
    sessionId: string;
    userId: string;
  },
): Promise<boolean> {
  const res = await client.query(
    `
      UPDATE auth.sessions
      SET revoked_at = now()
      WHERE id = $1
        AND user_id = $2
        AND revoked_at IS NULL;
    `,
    [opts.sessionId, opts.userId],
  );

  return (res.rowCount ?? 0) > 0;
}

export async function revokeAllSessionsForUser(
  client: DbClient,
  userId: string,
): Promise<number> {
  const res = await client.query(
    `
      UPDATE auth.sessions
      SET revoked_at = now()
      WHERE user_id = $1
        AND revoked_at IS NULL;
    `,
    [userId],
  );

  return res.rowCount ?? 0;
}

// ---------------------------------------------------------------------------
// Refresh Tokens (hash-only + rotation)
// ---------------------------------------------------------------------------

export async function createRefreshTokenRecord(
  client: DbClient,
  opts: {
    userId: string;
    tokenHash: string;
    ttlSec: number;
    familyId?: string;
  },
): Promise<RefreshTokenRow> {
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<RefreshTokenRow>(
    `
      INSERT INTO auth.refresh_tokens (
        user_id,
        token_hash,
        family_id,
        expires_at
      )
      VALUES (
        $1,
        $2,
        COALESCE($3::uuid, extensions.gen_random_uuid()),
        $4
      )
      RETURNING
        id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at;
    `,
    [opts.userId, opts.tokenHash, opts.familyId ?? null, expires],
  );

  return rows[0];
}

export async function findActiveRefreshTokenByHash(
  client: DbClient,
  tokenHash: string,
): Promise<RefreshTokenRow | null> {
  const { rows } = await client.query<RefreshTokenRow>(
    `
      SELECT
        id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at
      FROM auth.refresh_tokens
      WHERE token_hash = $1
        AND revoked_at IS NULL
        AND expires_at > now()
      LIMIT 1;
    `,
    [tokenHash],
  );

  return rows[0] ?? null;
}

export async function findRefreshTokenByHash(
  client: DbClient,
  tokenHash: string,
): Promise<RefreshTokenRow | null> {
  const { rows } = await client.query<RefreshTokenRow>(
    `
      SELECT
        id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at
      FROM auth.refresh_tokens
      WHERE token_hash = $1
      LIMIT 1;
    `,
    [tokenHash],
  );

  return rows[0] ?? null;
}

export async function markRefreshTokenRotated(
  client: DbClient,
  opts: {
    tokenId: string;
    replacedById: string;
  },
): Promise<boolean> {
  const res = await client.query(
    `
      UPDATE auth.refresh_tokens
      SET
        revoked_at = now(),
        replaced_by = $2
      WHERE id = $1
        AND revoked_at IS NULL;
    `,
    [opts.tokenId, opts.replacedById],
  );

  return (res.rowCount ?? 0) === 1;
}

export async function deleteRefreshTokenById(
  client: DbClient,
  tokenId: string,
): Promise<void> {
  await client.query(
    `
      DELETE FROM auth.refresh_tokens
      WHERE id = $1;
    `,
    [tokenId],
  );
}

export async function revokeRefreshFamily(
  client: DbClient,
  familyId: string,
): Promise<number> {
  const result = await client.query(
    `
      UPDATE auth.refresh_tokens
      SET revoked_at = now()
      WHERE family_id = $1
        AND revoked_at IS NULL;
    `,
    [familyId],
  );

  return result.rowCount ?? 0;
}

export async function revokeAllRefreshTokensForUser(
  client: DbClient,
  userId: string,
): Promise<number> {
  const result = await client.query(
    `
      UPDATE auth.refresh_tokens
      SET revoked_at = now()
      WHERE user_id = $1
        AND revoked_at IS NULL;
    `,
    [userId],
  );

  return result.rowCount ?? 0;
}

export async function resolveUserAuthContext(
  client: DbClient,
  opts: {
    userId: string;
    requestedTenantId?: string;
  },
): Promise<{
  tenantId?: string;
  role: string;
  roles: string[];
  plan: string;
}> {
  const { rows } = await client.query<{
    tenant_id: string | null;
    role: string | null;
    plan_code: string | null;
    role_names: string[] | null;
  }>(
    `
      SELECT
        tenant_id,
        role,
        plan_code,
        role_names
      FROM auth.resolve_user_auth_context($1, $2);
    `,
    [opts.userId, opts.requestedTenantId ?? null],
  );

  const row = rows[0];
  if (!row) {
    throw new Error("resolve_user_auth_context_failed");
  }

  const rolesFromDb = Array.isArray(row.role_names)
    ? row.role_names.filter((value) => typeof value === "string" && value.trim().length > 0)
    : [];

  const role = (row.role ?? rolesFromDb[0] ?? "member").trim() || "member";
  const roles = rolesFromDb.length > 0 ? rolesFromDb : [role];

  return {
    tenantId: row.tenant_id ?? undefined,
    role,
    roles,
    plan: row.plan_code ?? "free",
  };
}
