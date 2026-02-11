// src/modules/magic-link/repository.ts
// ============================================================================
// Magic-Link Repository fuer db-auth26
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { hashOpaqueToken } from "../../libs/crypto.js";
import type { TokenRow, UserRow } from "./types.js";

export async function findUserByEmailRow(
  client: DbClient,
  email: string,
): Promise<UserRow | null> {
  const { rows } = await client.query<UserRow>(
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
  client: DbClient,
  id: string,
): Promise<UserRow | null> {
  const { rows } = await client.query<UserRow>(
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

export async function createMagicLinkTokenRecord(
  client: DbClient,
  opts: {
    userId: string;
    token: string;
    ttlSec: number;
  },
): Promise<TokenRow> {
  const tokenHash = hashOpaqueToken(opts.token);
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<TokenRow>(
    `
      INSERT INTO auth.tokens (tenant_id, user_id, type, token_hash, expires_at)
      VALUES (meta.require_tenant_id(), $1, 'magic_link', $2, $3)
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

export async function findMagicLinkTokenByRawToken(
  client: DbClient,
  token: string,
): Promise<TokenRow | null> {
  const tokenHash = hashOpaqueToken(token);
  const { rows } = await client.query<TokenRow>(
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
        AND type = 'magic_link'
      LIMIT 1;
    `,
    [tokenHash],
  );

  return rows[0] ?? null;
}

export async function deleteMagicLinkTokenById(
  client: DbClient,
  id: string,
): Promise<void> {
  await client.query(`DELETE FROM auth.tokens WHERE id = $1;`, [id]);
}
