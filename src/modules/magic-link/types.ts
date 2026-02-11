// src/modules/magic-link/types.ts
// ============================================================================
// Typen fuer Magic-Link-Login (db-auth26)
// ============================================================================

export interface UserRow {
  id: string;
  tenant_id: string;
  email: string;
  is_active: boolean;
  verified_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface TokenRow {
  id: string;
  tenant_id: string;
  user_id: string;
  type: string;
  token_hash: string;
  expires_at: Date;
  created_at: Date;
}

export interface MagicLinkRequestBody {
  email: string;
}

export interface MagicLinkRequestInput extends MagicLinkRequestBody {
  ip?: string;
  ua?: string;
}

export interface MagicLinkRequestResult {
  requestAccepted: boolean;
}

export interface MagicLinkConsumeInput {
  token: string;
  ip?: string;
  ua?: string;
}

export interface MagicLinkConsumeResult {
  user: {
    id: string;
    email: string;
    tenantId: string;
  };
  accessToken: string;
  accessTokenExpiresAt: number;
  refreshToken: string;
  refreshTokenExpiresAt: number;
}

export interface MagicLinkHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
