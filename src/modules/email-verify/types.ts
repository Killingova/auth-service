// src/modules/email-verify/types.ts
// ============================================================================
// Typen fuer E-Mail-Verifikation (db-auth26)
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

export interface EmailVerifyRequestInput {
  email: string;
  ip?: string;
  ua?: string;
}

export interface EmailVerifyConfirmInput {
  token: string;
  ip?: string;
  ua?: string;
}

export interface EmailVerifyRequestResult {
  requestAccepted: boolean;
}

export interface EmailVerifyConfirmResult {
  user: {
    id: string;
    email: string;
  };
  alreadyVerified?: boolean;
}

export interface EmailVerifyHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
