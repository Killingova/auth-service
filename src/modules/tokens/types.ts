// src/modules/tokens/types.ts
// ============================================================================
// Token-Typen fuer db-auth26 (auth.tokens)
// ============================================================================

export type TokenType =
  | "verify_email"
  | "password_reset"
  | "magic_link"
  | "otp"
  | "other";

export interface TokenRow {
  id: string;
  tenant_id: string;
  user_id: string;
  type: TokenType | string;
  token_hash: string;
  expires_at: Date;
  created_at: Date;
}
