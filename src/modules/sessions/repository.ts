// src/modules/sessions/repository.ts
// ============================================================================
// Persistence-Layer für Session-Management
// ----------------------------------------------------------------------------
// - Direkter SQL-Zugriff auf auth.sessions (über DbClient)
// - KEINE Business-Logik, nur Datenzugriff
// - RLS-aware: im HTTP-Flow immer req.db verwenden
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import type { SessionRow } from "./types.js";

// ---------------------------------------------------------------------------
// Sessions lesen
// ---------------------------------------------------------------------------

/**
 * Alle Sessions eines Users laden (RLS-aware).
 *
 * Wichtige Punkte:
 * - Zusätzlich zu RLS filtern wir explizit auf user_id,
 *   damit auch bei falscher RLS-Konfiguration kein Fremdzugriff möglich ist.
 */
export async function listSessionsByUserId(
  client: DbClient,
  userId: string,
  limit = 20,
): Promise<SessionRow[]> {
  const res = await client.query<SessionRow>(
    `
      SELECT
        id,
        tenant_id,
        user_id,
        created_at,
        expires_at,
        revoked_at
      FROM auth.sessions
      WHERE user_id = $1
      ORDER BY created_at DESC
      LIMIT $2;
    `,
    [userId, limit],
  );

  return res.rows;
}

// ---------------------------------------------------------------------------
// Session löschen
// ---------------------------------------------------------------------------

/**
 * Löscht eine Session eines Users.
 *
 * - Zusätzliche Absicherung über user_id in der WHERE-Bedingung.
 * - Rückgabe: Anzahl der gelöschten Zeilen.
 */
export async function deleteSessionByIdForUser(
  client: DbClient,
  sessionId: string,
  userId: string,
): Promise<number> {
  const res = await client.query(
    `
      UPDATE auth.sessions
      SET revoked_at = now()
      WHERE id = $1
        AND user_id = $2
        AND revoked_at IS NULL;
    `,
    [sessionId, userId],
  );

  return res.rowCount ?? 0;
}
