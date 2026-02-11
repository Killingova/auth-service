// src/modules/register/types.ts
// ============================================================================
// Typen für Registrierung / Tenant-Anlage / Tokens
// ----------------------------------------------------------------------------
// DSGVO/ISO-orientiert:
// - Trennung zwischen DB-Row-Typen (intern) und Public-DTOs (extern)
// - Keine Passwörter oder Hashes in Public-Typen
// - RLS-aware: Tenant-Id bleibt intern, Public-Typen sind datensparsam
// ============================================================================

// ---------------------------------------------------------------------------
// DB-Row-Typen (direkt aus PostgreSQL)
// ---------------------------------------------------------------------------

export interface TenantRow {
  id: string;
  name: string;
  slug: string;
  created_at: Date;
}

export interface UserRow {
  id: string;
  tenant_id: string;
  email: string;
  is_active: boolean;
  verified_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * TokenKind:
 * - muss mit dem DB-Constraint (tokens_kind_check) übereinstimmen.
 * - In deinem Setup erlaubt: 'refresh', 'reset', 'verify'
 *   → plus optionale weitere Typen wie 'magic_link', 'other'.
 */
export type TokenKind =
  | "verify_email"
  | "password_reset"
  | "magic_link"
  | "otp";

export interface TokenRow {
  id: string;
  tenant_id: string;
  user_id: string;
  type: TokenKind;
  token_hash: string;
  expires_at: Date;
  created_at: Date;
}

// ---------------------------------------------------------------------------
// Öffentliche Typen (DTOs für Routes / Services)
// ---------------------------------------------------------------------------

/**
 * Öffentliche Sicht auf einen User.
 * Wichtig:
 * - Keine sensiblen Felder (kein password_hash, keine tenant_id).
 * - createdAt als Date-Objekt, kann im HTTP-Layer bei Bedarf serialisiert werden.
 */
export interface PublicUser {
  id: string;
  email: string;
  createdAt: Date;
}

/**
 * Öffentliche Sicht auf einen Tenant (z. B. für spätere Mandanten-Funktionalität).
 * Tenant-spezifische Details können im HTTP-Layer weiter reduziert werden.
 */
export interface PublicTenant {
  id: string;
  name: string;
  slug: string;
}

/**
 * Request-Body von /auth/register (HTTP-Ebene).
 *
 * Wichtig:
 * - Nur Felder, die der Client senden darf.
 * - IP/User-Agent kommen aus der Transport-Schicht (Fastify-Request),
 *   nicht aus dem Body.
 */
export interface RegisterRequestBody {
  email: string;
  password: string;
  /**
   * Optionaler Tenant-Name – falls ein eigener Mandant angelegt werden soll.
   * Kann später genutzt werden, um bei der Registrierung automatisch
   * einen Tenant zu erzeugen.
   */
  tenantName?: string;
}

/**
 * Interne Service-Eingabe für den Register-UseCase.
 * Kann genutzt werden, falls du IP/User-Agent im Service auswerten möchtest.
 * (Aktuell optional, da registerUser primär mit DB-Client + Body arbeitet.)
 */
export interface RegisterInput extends RegisterRequestBody {
  ip?: string;
  ua?: string;
}

/**
 * Ergebnis eines erfolgreichen Register-UseCases (aktueller Minimal-Flow).
 * Wird von service.ts verwendet und von der Route nach außen serialisiert.
 */
export interface RegisterResult {
  user: PublicUser;
}

/**
 * Erweiterte Variante für spätere Multi-Tenant/Verify-Logik.
 * Noch nicht im aktiven Flow genutzt, aber vorbereitet, um die API
 * stabil zu halten, wenn Tenant-Handling erweitert wird.
 */
export interface RegisterWithTenantResult {
  user: {
    id: string;
    email: string;
    tenantId: string;
  };
  tenant: PublicTenant;
  emailVerificationPlanned: boolean; // true = Verify-Token wurde erzeugt
}

/**
 * Infos zu einem E-Mail-Verifikationstoken.
 * Wird intern für Mailversand/Worker genutzt, nicht im HTTP-Response.
 */
export interface EmailVerificationTokenInfo {
  token: string;
  expiresAt: number; // Unix-Timestamp (Sekunden)
}

// ---------------------------------------------------------------------------
// Modul-spezifischer Healthcheck für /auth/register/health
// ---------------------------------------------------------------------------

export interface RegisterHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
