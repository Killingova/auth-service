// src/modules/otp/repository.ts
// ============================================================================
// Persistence fuer OTP ueber auth.tokens(type='otp', token_hash)
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { hashOtpCode, hashOtpCodeCandidates } from "../../libs/crypto.js";
import type { OtpRecordRow } from "./types.js";

interface OtpUserRow {
  id: string;
  tenant_id: string;
  email: string;
  is_active: boolean;
}

export async function findUserByEmail(
  client: DbClient,
  email: string,
): Promise<OtpUserRow | null> {
  const { rows } = await client.query<OtpUserRow>(
    `
      SELECT
        id,
        tenant_id,
        email,
        is_active
      FROM auth.users
      WHERE email = $1
      LIMIT 1;
    `,
    [email.toLowerCase()],
  );

  return rows[0] ?? null;
}

export async function deleteOtpByUserId(
  client: DbClient,
  userId: string,
): Promise<void> {
  await client.query(
    `
      DELETE FROM auth.tokens
      WHERE user_id = $1
        AND type = 'otp';
    `,
    [userId],
  );
}

export async function createOtpRecord(
  client: DbClient,
  opts: {
    userId: string;
    code: string;
    ttlSec: number;
  },
): Promise<OtpRecordRow> {
  const tokenHash = hashOtpCode(opts.code);
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<OtpRecordRow>(
    `
      INSERT INTO auth.tokens (tenant_id, user_id, type, token_hash, expires_at)
      VALUES (meta.require_tenant_id(), $1, 'otp', $2, $3)
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

export async function consumeOtpByCode(
  client: DbClient,
  opts: {
    userId: string;
    code: string;
  },
): Promise<boolean> {
  const tokenHashes = hashOtpCodeCandidates(opts.code);
  const { rowCount } = await client.query(
    `
      DELETE FROM auth.tokens
      WHERE user_id = $1
        AND type = 'otp'
        AND token_hash = ANY($2::text[])
        AND expires_at > now();
    `,
    [opts.userId, tokenHashes],
  );

  return (rowCount ?? 0) === 1;
}
