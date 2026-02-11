// src/modules/sessions/types.ts
// ============================================================================
// Typen für Session-Management
// ----------------------------------------------------------------------------
// - Intern: SessionRow (DB-Level, auth.sessions)
// - Extern: PublicSession für API-Responses
// ============================================================================

// ---------------------------------------------------------------------------
// DB-Row-Typ (direkt aus auth.sessions)
// ---------------------------------------------------------------------------

export interface SessionRow {
  id: string;
  tenant_id: string;
  user_id: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
}

// ---------------------------------------------------------------------------
// Öffentliche Typen (DTOs für Services / Routes)
// ---------------------------------------------------------------------------

/**
 * Öffentliche Sicht auf eine Session.
 * (Tenant-Isolation erfolgt über RLS + AccessToken-sub)
 */
export interface PublicSession {
  id: string;
  createdAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

/**
 * Eingabe für getUserSessions()-Service.
 */
export interface SessionsListInput {
  userId: string;
  limit?: number;
}

/**
 * Ergebnis von getUserSessions().
 */
export interface SessionsListResult {
  sessions: PublicSession[];
}

/**
 * Eingabe für revokeSessionForUser().
 */
export interface SessionRevokeInput {
  userId: string;
  sessionId: string;
}

/**
 * Ergebnis von revokeSessionForUser().
 */
export interface SessionRevokeResult {
  revoked: boolean;
}

// ---------------------------------------------------------------------------
// Modul-spezifischer Healthcheck für /auth/sessions/health
// ---------------------------------------------------------------------------

export interface SessionsHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
