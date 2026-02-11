// src/modules/identity/repository.ts
// ============================================================================
// Identity-Repository
// ----------------------------------------------------------------------------
// - Zugriff auf auth.users/auth.credentials, auth.sessions, auth.refresh_tokens
// - RLS-aware: arbeitet nur mit dem pro-Request-DB-Client (DbClient)
// - KEINE Business-Logik, nur Datenzugriff
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import type { RefreshTokenRow, SessionRow, UserRow } from "./types.js";

// ---------------------------------------------------------------------------
// User + Credentials
// ---------------------------------------------------------------------------

export async function findUserByEmail(
  client: DbClient,
  email: string,
): Promise<UserRow | null> {
  const { rows } = await client.query<UserRow>(
    `
      SELECT
        u.id,
        u.tenant_id,
        u.email,
        c.password_hash,
        u.is_active,
        u.verified_at,
        u.created_at,
        u.updated_at
      FROM auth.users u
      JOIN auth.credentials c
        ON c.user_id = u.id
       AND c.tenant_id = u.tenant_id
      WHERE u.email = $1
      LIMIT 1;
    `,
    [email.toLowerCase()],
  );

  return rows[0] ?? null;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export async function createSession(
  client: DbClient,
  opts: {
    tenantId: string;
    userId: string;
    ttlSec: number;
  },
): Promise<SessionRow> {
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<SessionRow>(
    `
      INSERT INTO auth.sessions (tenant_id, user_id, expires_at)
      VALUES ($1, $2, $3)
      RETURNING
        id,
        tenant_id,
        user_id,
        created_at,
        expires_at,
        revoked_at;
    `,
    [opts.tenantId, opts.userId, expires],
  );

  return rows[0];
}

// ---------------------------------------------------------------------------
// Refresh Tokens (hash-only + rotation)
// ---------------------------------------------------------------------------

export async function createRefreshTokenRecord(
  client: DbClient,
  opts: {
    tenantId: string;
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
        tenant_id,
        user_id,
        token_hash,
        family_id,
        expires_at
      )
      VALUES (
        $1,
        $2,
        $3,
        COALESCE($4::uuid, extensions.gen_random_uuid()),
        $5
      )
      RETURNING
        id,
        tenant_id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at;
    `,
    [opts.tenantId, opts.userId, opts.tokenHash, opts.familyId ?? null, expires],
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
        tenant_id,
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
        tenant_id,
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
