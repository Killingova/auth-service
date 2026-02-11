// src/modules/otp/service.ts
// ============================================================================
// Business-Logik fuer OTP (db-auth26)
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { dbHealth } from "../../libs/db.js";
import {
  consumeOtpByCode,
  createOtpRecord,
  deleteOtpByUserId,
  findUserByEmail,
} from "./repository.js";
import type {
  OtpHealth,
  OtpRequestInput,
  OtpVerifyInput,
  OtpVerifyResult,
} from "./types.js";

function generateOtpCode(): string {
  return String(Math.floor(Math.random() * 1_000_000)).padStart(6, "0");
}

const OTP_TTL_SEC = 60 * 10; // 10m

export async function requestOtp(
  db: DbClient,
  input: OtpRequestInput,
): Promise<{ ok: true }> {
  const email = input.email.trim().toLowerCase();
  const user = await findUserByEmail(db, email);

  if (!user || !user.is_active) {
    return { ok: true };
  }

  // Maximal ein aktives OTP pro User.
  await deleteOtpByUserId(db, user.id);

  const code = generateOtpCode();
  await createOtpRecord(db, {
    userId: user.id,
    code,
    ttlSec: OTP_TTL_SEC,
  });

  // Versand des OTP-Codes erfolgt ueber separaten Worker/Provider.
  return { ok: true };
}

export async function verifyOtp(
  db: DbClient,
  input: OtpVerifyInput,
): Promise<OtpVerifyResult> {
  const email = input.email.trim().toLowerCase();
  const code = input.code.trim();

  const user = await findUserByEmail(db, email);
  if (!user || !user.is_active) {
    throw new Error("invalid_otp");
  }

  const consumed = await consumeOtpByCode(db, {
    userId: user.id,
    code,
  });

  if (!consumed) {
    throw new Error("invalid_otp");
  }

  return {
    success: true,
    user: {
      id: user.id,
      email: user.email,
      tenantId: user.tenant_id,
    },
  };
}

export async function getOtpHealth(): Promise<OtpHealth> {
  try {
    const { ok, error } = await dbHealth();
    return {
      healthy: ok,
      db: {
        ok,
        error: error ?? null,
      },
    };
  } catch (err: any) {
    return {
      healthy: false,
      db: {
        ok: false,
        error: err?.message ?? "Unknown DB error",
      },
    };
  }
}
