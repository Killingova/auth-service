// src/modules/tokens/repository.ts
// ============================================================================
// Token-Repository fuer db-auth26 (auth.tokens)
// ----------------------------------------------------------------------------
// - Tabelle: auth.tokens(tenant_id, user_id, type, token_hash, expires_at, created_at)
// - One-time Verbrauch erfolgt ueber DELETE (kein consumed_at Feld).
// ============================================================================

import type { DbClient } from "../../libs/db.js";

export async function deleteExpiredTokens(
  client: DbClient,
  tokenType: string,
): Promise<number> {
  const res = await client.query(
    `
      DELETE FROM auth.tokens
      WHERE type = $1
        AND expires_at < now();
    `,
    [tokenType],
  );

  return res.rowCount ?? 0;
}
