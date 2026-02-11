// src/modules/email-verify/service.ts
// ============================================================================
// Business-Logik fuer E-Mail-Verifikation (db-auth26)
// ============================================================================

import { randomUUID } from "node:crypto";
import type { DbClient } from "../../libs/db.js";
import { dbHealth } from "../../libs/db.js";

import {
  createEmailVerifyTokenRecord,
  deleteVerifyTokenById,
  findUserByEmailRow,
  findUserById,
  findVerifyTokenByRawToken,
  markUserVerifiedById,
} from "./repository.js";

import type {
  EmailVerifyConfirmInput,
  EmailVerifyConfirmResult,
  EmailVerifyHealth,
  EmailVerifyRequestInput,
  EmailVerifyRequestResult,
} from "./types.js";

const EMAIL_VERIFY_TTL_SEC = 60 * 60 * 24 * 3; // 3 Tage

export class InvalidVerifyTokenError extends Error {
  statusCode = 400;

  constructor(message = "Invalid email verification token") {
    super(message);
    this.name = "InvalidVerifyTokenError";
  }
}

export class ExpiredVerifyTokenError extends Error {
  statusCode = 410;

  constructor(message = "Email verification token has expired") {
    super(message);
    this.name = "ExpiredVerifyTokenError";
  }
}

export class AlreadyVerifiedError extends Error {
  statusCode = 200;

  constructor(email: string) {
    super(`Email already verified: ${email}`);
    this.name = "AlreadyVerifiedError";
  }
}

export async function requestEmailVerification(
  db: DbClient,
  input: EmailVerifyRequestInput,
): Promise<EmailVerifyRequestResult> {
  const email = input.email.trim().toLowerCase();
  const user = await findUserByEmailRow(db, email);

  if (!user || user.verified_at) {
    return { requestAccepted: true };
  }

  const token = randomUUID();
  await createEmailVerifyTokenRecord(db, {
    userId: user.id,
    token,
    ttlSec: EMAIL_VERIFY_TTL_SEC,
  });

  return { requestAccepted: true };
}

export async function verifyEmailToken(
  db: DbClient,
  input: EmailVerifyConfirmInput,
): Promise<EmailVerifyConfirmResult> {
  const rawToken = input.token.trim();
  if (!rawToken) {
    throw new InvalidVerifyTokenError("Empty verification token");
  }

  const tokenRow = await findVerifyTokenByRawToken(db, rawToken);
  if (!tokenRow) {
    throw new InvalidVerifyTokenError("Verification token not found");
  }

  if (tokenRow.expires_at.getTime() <= Date.now()) {
    await deleteVerifyTokenById(db, tokenRow.id);
    throw new ExpiredVerifyTokenError();
  }

  const user = await findUserById(db, tokenRow.user_id);
  if (!user) {
    await deleteVerifyTokenById(db, tokenRow.id);
    throw new InvalidVerifyTokenError("User for verification token not found");
  }

  if (user.verified_at) {
    await deleteVerifyTokenById(db, tokenRow.id);
    throw new AlreadyVerifiedError(user.email);
  }

  const updatedUser = await markUserVerifiedById(db, user.id);
  await deleteVerifyTokenById(db, tokenRow.id);

  return {
    user: {
      id: updatedUser.id,
      email: updatedUser.email,
    },
    alreadyVerified: false,
  };
}

export async function getVerifyHealth(): Promise<EmailVerifyHealth> {
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
