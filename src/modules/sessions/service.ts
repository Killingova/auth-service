// src/modules/sessions/service.ts
// ============================================================================
// Session-Management (Business Logic)
// ----------------------------------------------------------------------------
// UseCases:
// - getUserSessions:        aktive Sessions eines Users listen (RLS-aware)
// - revokeSessionForUser:   Session des Users widerrufen (löschen)
// - getSessionsHealth:      Modul-Healthcheck (DB only)
// ============================================================================

import { dbHealth, type DbClient } from "../../libs/db.js";

import {
  listSessionsByUserId,
  deleteSessionByIdForUser,
} from "./repository.js";

import type {
  SessionsListInput,
  SessionsListResult,
  SessionRevokeInput,
  SessionRevokeResult,
  SessionsHealth,
  PublicSession,
} from "./types.js";

// ---------------------------------------------------------------------------
// UseCase: Sessions des Users listen
// ---------------------------------------------------------------------------

export async function getUserSessions(
  db: DbClient,
  input: SessionsListInput,
): Promise<SessionsListResult> {
  // defensive limits (DoS-sicher, DB-freundlich)
  const requested = typeof input.limit === "number" ? input.limit : 20;
  const limit = Math.min(Math.max(requested, 1), 100);

  const rows = await listSessionsByUserId(db, input.userId, limit);

  const sessions: PublicSession[] = rows.map((row) => ({
    id: row.id,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
  }));

  return { sessions };
}

// ---------------------------------------------------------------------------
// UseCase: Session des Users widerrufen
// ---------------------------------------------------------------------------

/**
 * Widerruft (löscht) eine Session für den gegebenen User.
 *
 * Security:
 * - Durch RLS + SQL-Filter wird sichergestellt, dass nur eigene Sessions
 *   manipuliert werden können.
 *
 * Hinweis:
 * - Diese Funktion löscht aktuell nur den Eintrag in auth.sessions.
 * - Token-Invalidierung ist separat (z.B. Redis blacklist / logout flow).
 */
export async function revokeSessionForUser(
  db: DbClient,
  input: SessionRevokeInput,
): Promise<SessionRevokeResult> {
  const deleted = await deleteSessionByIdForUser(db, input.sessionId, input.userId);
  return { revoked: deleted > 0 };
}

// ---------------------------------------------------------------------------
// Modul-Healthcheck für /auth/sessions/health
// ---------------------------------------------------------------------------

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown DB error";
}

export async function getSessionsHealth(): Promise<SessionsHealth> {
  try {
    const { ok, error } = await dbHealth();

    return {
      healthy: ok,
      db: {
        ok,
        error: error ?? null,
      },
    };
  } catch (err: unknown) {
    return {
      healthy: false,
      db: {
        ok: false,
        error: errMessage(err),
      },
    };
  }
}
