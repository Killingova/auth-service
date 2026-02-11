// src/modules/password/repository.ts
// ============================================================================
// Passwort-Repository fuer db-auth26
// ----------------------------------------------------------------------------
// - Passwort liegt in auth.credentials (nicht in auth.users)
// - Reset-Tokens liegen in auth.tokens(type='password_reset', token_hash)
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { hashOpaqueToken } from "../../libs/crypto.js";
import type { CredentialRow, TokenRow, UserRow } from "./types.js";

export async function findUserByEmailRow(
  client: DbClient,
  email: string,
): Promise<UserRow | null> {
  const res = await client.query<UserRow>(
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

  return res.rows[0] ?? null;
}

export async function findUserById(
  client: DbClient,
  id: string,
): Promise<UserRow | null> {
  const res = await client.query<UserRow>(
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

  return res.rows[0] ?? null;
}

export async function findCredentialByUserId(
  client: DbClient,
  userId: string,
): Promise<CredentialRow | null> {
  const res = await client.query<CredentialRow>(
    `
      SELECT
        id,
        tenant_id,
        user_id,
        password_hash,
        password_changed_at,
        created_at
      FROM auth.credentials
      WHERE user_id = $1
      LIMIT 1;
    `,
    [userId],
  );

  return res.rows[0] ?? null;
}

export async function updateCredentialPasswordByUserId(
  client: DbClient,
  opts: { userId: string; passwordHash: string },
): Promise<CredentialRow> {
  const res = await client.query<CredentialRow>(
    `
      UPDATE auth.credentials
      SET
        password_hash = $2,
        password_changed_at = now()
      WHERE user_id = $1
      RETURNING
        id,
        tenant_id,
        user_id,
        password_hash,
        password_changed_at,
        created_at;
    `,
    [opts.userId, opts.passwordHash],
  );

  if (!res.rows[0]) {
    throw new Error(`Credentials not found for password update: ${opts.userId}`);
  }

  return res.rows[0];
}

export async function createPasswordResetTokenRecord(
  client: DbClient,
  opts: {
    userId: string;
    token: string;
    ttlSec: number;
  },
): Promise<TokenRow> {
  const tokenHash = hashOpaqueToken(opts.token);
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const res = await client.query<TokenRow>(
    `
      INSERT INTO auth.tokens (tenant_id, user_id, type, token_hash, expires_at)
      VALUES (meta.require_tenant_id(), $1, 'password_reset', $2, $3)
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

  return res.rows[0];
}

export async function findPasswordResetTokenByRawToken(
  client: DbClient,
  token: string,
): Promise<TokenRow | null> {
  const tokenHash = hashOpaqueToken(token);
  const res = await client.query<TokenRow>(
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
        AND type = 'password_reset'
      LIMIT 1;
    `,
    [tokenHash],
  );

  return res.rows[0] ?? null;
}

export async function deletePasswordResetTokenById(
  client: DbClient,
  id: string,
): Promise<void> {
  await client.query(
    `
      DELETE FROM auth.tokens
      WHERE id = $1;
    `,
    [id],
  );
}
