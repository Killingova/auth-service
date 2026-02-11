// src/modules/tokens/service.ts
// ============================================================================
// Token-Service (Maintenance)
// ----------------------------------------------------------------------------
// Dieses Modul verwaltet nur Cleanup auf auth.tokens.
// Ausgabe/Validierung von One-time-Tokens erfolgt in den jeweiligen Fachmodulen.
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { deleteExpiredTokens } from "./repository.js";

export async function cleanupTokens(
  db: DbClient,
  tokenType: string,
): Promise<number> {
  return deleteExpiredTokens(db, tokenType);
}
