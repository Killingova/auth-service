// src/modules/password/types.ts
// ============================================================================
// Typen fuer Passwort-Flow (db-auth26)
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

export interface CredentialRow {
  id: string;
  tenant_id: string;
  user_id: string;
  password_hash: string;
  password_changed_at: Date;
  created_at: Date;
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

export interface PublicUser {
  id: string;
  email: string;
}

export interface PasswordResetRequestInput {
  email: string;
  ip?: string;
  ua?: string;
}

export interface PasswordResetRequestResult {
  requestAccepted: boolean;
}

export interface PasswordResetConfirmInput {
  token: string;
  newPassword: string;
}

export interface PasswordResetConfirmResult {
  user: PublicUser;
}

export interface PasswordChangeInput {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

export interface PasswordChangeResult {
  changed: boolean;
}

export interface PasswordHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
