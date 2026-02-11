// src/modules/email-verify/repository.ts
// ============================================================================
// Repository fuer E-Mail-Verifikation (db-auth26)
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { hashOpaqueToken } from "../../libs/crypto.js";
import type { TokenRow, UserRow } from "./types.js";

export async function findUserByEmailRow(
  db: DbClient,
  email: string,
): Promise<UserRow | null> {
  const { rows } = await db.query<UserRow>(
    `
      SELECT
        id,
        tenant_id,
        email,
        is_active,
        verified_at,
        created_at,
        updated_at
      FROM auth.users
      WHERE email = $1
      LIMIT 1;
    `,
    [email.toLowerCase()],
  );

  return rows[0] ?? null;
}

export async function findUserById(
  db: DbClient,
  id: string,
): Promise<UserRow | null> {
  const { rows } = await db.query<UserRow>(
    `
      SELECT
        id,
        tenant_id,
        email,
        is_active,
        verified_at,
        created_at,
        updated_at
      FROM auth.users
      WHERE id = $1
      LIMIT 1;
    `,
    [id],
  );

  return rows[0] ?? null;
}

export async function markUserVerifiedById(
  db: DbClient,
  userId: string,
): Promise<UserRow> {
  const { rows } = await db.query<UserRow>(
    `
      UPDATE auth.users
      SET
        verified_at = now(),
        is_active = true,
        updated_at = now()
      WHERE id = $1
      RETURNING
        id,
        tenant_id,
        email,
        is_active,
        verified_at,
        created_at,
        updated_at;
    `,
    [userId],
  );

  if (!rows[0]) {
    throw new Error(`User not found for verification: ${userId}`);
  }

  return rows[0];
}

export async function createEmailVerifyTokenRecord(
  db: DbClient,
  opts: {
    userId: string;
    token: string;
    ttlSec: number;
  },
): Promise<TokenRow> {
  const tokenHash = hashOpaqueToken(opts.token);
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await db.query<TokenRow>(
    `
      INSERT INTO auth.tokens (tenant_id, user_id, type, token_hash, expires_at)
      VALUES (meta.require_tenant_id(), $1, 'verify_email', $2, $3)
      RETURNING
        id,
        tenant_id,
        user_id,
        type,
        token_hash,
        expires_at,
        created_at;
    `,
    [opts.userId, tokenHash, expires],
  );

  return rows[0];
}

export async function findVerifyTokenByRawToken(
  db: DbClient,
  token: string,
): Promise<TokenRow | null> {
  const tokenHash = hashOpaqueToken(token);
  const { rows } = await db.query<TokenRow>(
    `
      SELECT
        id,
        tenant_id,
        user_id,
        type,
        token_hash,
        expires_at,
        created_at
      FROM auth.tokens
      WHERE token_hash = $1
        AND type = 'verify_email'
      LIMIT 1;
    `,
    [tokenHash],
  );

  return rows[0] ?? null;
}

export async function deleteVerifyTokenById(
  db: DbClient,
  id: string,
): Promise<void> {
  await db.query(`DELETE FROM auth.tokens WHERE id = $1;`, [id]);
}
