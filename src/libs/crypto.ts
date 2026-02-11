// src/libs/crypto.ts
// ============================================================================
// Passwort-Hashing & -Verifikation (argon2id)
// ----------------------------------------------------------------------------
// - Sichere Default-Parameter für argon2id
// - Einfache Wrapper-Funktionen: hashPassword(), verifyPassword()
// ============================================================================

import { createHash, createHmac } from "node:crypto";
import argon2 from "argon2";
import { env } from "./env.js";

// ---------------------------------------------------------------------------
// Passwort hashen
// ---------------------------------------------------------------------------

export async function hashPassword(plain: string): Promise<string> {
  // Standard-Parametrierung – kannst du später anpassen (Memory/TimeCost)
  return argon2.hash(plain, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64 MiB
    timeCost: 3,
    parallelism: 1,
  });
}

// ---------------------------------------------------------------------------
// Passwort prüfen
// ---------------------------------------------------------------------------

export async function verifyPassword(
  hash: string,
  plain: string,
): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Opaque-Token hashen (z. B. Refresh/Verify/Reset)
// ---------------------------------------------------------------------------

export function hashOpaqueToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function hashOtpCode(code: string, pepper?: string): string {
  if (pepper && pepper.length > 0) {
    return createHmac("sha256", pepper).update(code, "utf8").digest("hex");
  }
  return hashOpaqueToken(code);
}

export function hashOtpCodeCandidates(code: string): string[] {
  const hashes = new Set<string>();
  hashes.add(hashOtpCode(code, env.TOKEN_PEPPER_ACTIVE));
  if (env.TOKEN_PEPPER_PREVIOUS) {
    hashes.add(hashOtpCode(code, env.TOKEN_PEPPER_PREVIOUS));
  }
  return [...hashes];
}
