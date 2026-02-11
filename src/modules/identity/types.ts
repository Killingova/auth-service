// src/modules/identity/types.ts
// ============================================================================
// Typen für Identity / Auth (an dein authdb-Schema angelehnt)
// ---------------------------------------------------------------------------
// - DB-Row-Typen spiegeln 1:1 die Tabellen in auth.tenants/auth.users/... wider
// - DTOs sind die "externen" Formen für Service & Routes
// ============================================================================

// -----------------------------
// DB-Row-Typen (Rohdaten aus Postgres)
// -----------------------------
//
// Hinweis:
// - Zeitspalten sind hier als string typisiert, da pg sie standardmäßig
//   als ISO-8601-Strings liefert (z. B. "2025-12-02T07:30:00.000Z").
// - Wenn du im Service lieber Date-Objekte möchtest, kannst du dort konvertieren.
//

export interface UserRow {
  id: string;
  tenant_id: string;
  email: string;
  password_hash: string;
  is_active: boolean;
  verified_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface SessionRow {
  id: string;
  tenant_id: string;
  user_id: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface RefreshTokenRow {
  id: string;
  tenant_id: string;
  user_id: string;
  token_hash: string;
  family_id: string;
  replaced_by: string | null;
  revoked_at: string | null;
  created_at: string;
  expires_at: string;
}

// -----------------------------
// DTOs für Service / Routes
// -----------------------------
//
// Diese Typen sind bewusst vom DB-Schema entkoppelt:
// - klarere Semantik für den Service
// - stabilere API-Verträge nach außen
//

export interface LoginInput {
  email: string;
  password: string;
  ip?: string;
  ua?: string;
}

export interface LoginResult {
  user: {
    id: string;
    email: string;
    tenantId: string; // CamelCase-Variante von tenant_id (API-freundlich)
  };
  accessToken: string;
  accessTokenExpiresAt: number;   // Unix-Sekunden (exp aus JWT)
  refreshToken: string;           // opaques Secret (UUID/JTI)
  refreshTokenExpiresAt: number;  // Unix-Sekunden
}

export interface RefreshInput {
  refreshToken: string;
  ip?: string;
  ua?: string;
}

export interface RefreshResult {
  accessToken: string;
  accessTokenExpiresAt: number;   // Unix-Sekunden
  refreshToken: string;
  refreshTokenExpiresAt: number;  // Unix-Sekunden
}
