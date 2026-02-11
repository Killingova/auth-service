// src/libs/db.ts
// ============================================================================
// PostgreSQL Connector
// - Ein zentraler Connection-Pool pro Prozess
// - Typsicheres query<T>() für einfache SELECT/INSERT/UPDATE-Operationen
// - Healthcheck-Funktionen für /health & Startup-Checks
// - Graceful Shutdown für geordnetes Beenden (z. B. bei SIGTERM)
// ============================================================================

import pg, { type QueryResultRow } from "pg";
import { env } from "./env.js";

const { Pool } = pg;

// ============================================================================
// Typen
// ============================================================================

/**
 * DbClient
 * - Wird verwendet, wenn du einen dedizierten Client pro Request brauchst
 *   (z. B. im RLS-Plugin mit BEGIN/COMMIT).
 * - Für einfache, stateless Queries reicht query<T>(), ohne diesen Typ.
 */
export type DbClient = pg.PoolClient;

// ============================================================================
// Connection-Pool
// ----------------------------------------------------------------------------
// EIN Pool pro Prozess. Alle Module teilen sich diesen Pool.
// Die Verbindungskonfiguration kommt aus env.DATABASE_URL.
// ============================================================================

/**
 * Globaler PostgreSQL Connection-Pool.
 *
 * Hinweise:
 * - max: maximale Anzahl gleichzeitiger Verbindungen im Pool
 * - idleTimeoutMillis: wie lange ein ungenutzter Client offen bleibt
 * - connectionTimeoutMillis: Timeout für Verbindungsaufbau
 */
export const pool = new Pool({
  connectionString: env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 5_000,
});

// ============================================================================
// Generisches, typisiertes query<T>
// ----------------------------------------------------------------------------
// - Liefert direkt T[] zurück (kein .rows im Aufrufer nötig)
// - Optional typisierbar: query<User>("SELECT * FROM auth.users WHERE ...")
// - Geeignet für einfache, stateless DB-Zugriffe (ohne RLS-Kontext).
// ============================================================================

/**
 * Führt ein SQL-Statement mit optionalen Parametern aus und gibt die
 * Ergebniszeilen als typisiertes Array zurück.
 *
 * @example
 *   type User = { id: string; email: string };
 *   const users = await query<User>(
 *     "SELECT id, email FROM auth.users WHERE is_active = $1",
 *     [true],
 *   );
 *
 * @param sql    SQL-Statement mit Platzhaltern ($1, $2, …)
 * @param params Werte für die Platzhalter
 * @returns      Array von Ergebniszeilen als Typ T
 */
export async function query<T extends QueryResultRow = QueryResultRow>(
  sql: string,
  params: unknown[] = [],
): Promise<T[]> {
  const res = await pool.query(sql, params);
  return res.rows as T[];
}

// ============================================================================
// Healthcheck für /health & /health/db
// ----------------------------------------------------------------------------
// - dbHealth(): gibt ein Objekt { ok, error? } zurück, ideal für REST-Responses
// - checkDb(): wirft im Fehlerfall eine Exception (für Startup/Ready-Checks)
// ============================================================================

/**
 * Führt einen einfachen Healthcheck gegen die Datenbank aus.
 *
 * @returns { ok: true } wenn die DB erreichbar ist,
 *          { ok: false, error: string } bei Fehler
 */
export async function dbHealth(): Promise<{ ok: boolean; error?: string }> {
  try {
    await pool.query("SELECT 1;");
    return { ok: true };
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "unknown database error";

    return {
      ok: false,
      error: message,
    };
  }
}

/**
 * checkDb()
 * - Führt dbHealth() aus und wirft einen Error, wenn der Check fehlschlägt.
 * - Ideal für:
 *   - Startup-Checks (z. B. in buildApp() vor dem Listen)
 *   - Readiness-Checks in komplexeren Szenarien
 *
 * @throws Error wenn die Datenbank nicht erreichbar ist
 */
export async function checkDb(): Promise<void> {
  const { ok, error } = await dbHealth();
  if (!ok) {
    throw new Error(`[DB] Healthcheck failed: ${error ?? "unknown"}`);
  }
}

// ============================================================================
// Graceful Shutdown
// ----------------------------------------------------------------------------
// - Sollte beim geordneten Shutdown des Services aufgerufen werden
//   (z. B. in app.close() oder in einem globalen Shutdown-Handler).
// - Schließt den Pool und damit alle aktiven Verbindungen.
// ============================================================================

/**
 * Beendet den globalen Connection-Pool.
 *
 * - Wartet, bis alle ausgeliehenen Clients zurück im Pool sind
 *   (oder deren Zeit abgelaufen ist).
 * - Danach werden alle Verbindungen zur Datenbank geschlossen.
 */
export async function closeDb(): Promise<void> {
  await pool.end();
}
