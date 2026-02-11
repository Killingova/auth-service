// src/modules/otp/types.ts
// ============================================================================
// Typen fuer OTP (db-auth26)
// ============================================================================

export interface OtpRecordRow {
  id: string;
  tenant_id: string;
  user_id: string;
  type: string;
  token_hash: string;
  expires_at: Date;
  created_at: Date;
}

export interface OtpRequestInput {
  email: string;
  ip?: string;
  ua?: string;
}

export interface OtpVerifyInput {
  email: string;
  code: string;
}

export interface OtpVerifyResult {
  success: boolean;
  user: {
    id: string;
    email: string;
    tenantId: string;
  };
}

export interface OtpHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
