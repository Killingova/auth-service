// src/modules/password/service.ts
// ============================================================================
// Business-Logik fuer Passwort-Reset / Passwort-Aenderung (db-auth26)
// ============================================================================

import { randomUUID } from "node:crypto";
import type { DbClient } from "../../libs/db.js";
import { dbHealth } from "../../libs/db.js";
import { hashPassword, verifyPassword } from "../../libs/crypto.js";

import {
  createPasswordResetTokenRecord,
  deletePasswordResetTokenById,
  findCredentialByUserId,
  findPasswordResetTokenByRawToken,
  findUserByEmailRow,
  findUserById,
  updateCredentialPasswordByUserId,
} from "./repository.js";

import type {
  PasswordChangeInput,
  PasswordChangeResult,
  PasswordHealth,
  PasswordResetConfirmInput,
  PasswordResetConfirmResult,
  PasswordResetRequestInput,
  PasswordResetRequestResult,
} from "./types.js";

const PASSWORD_RESET_TTL_SEC = 60 * 60 * 2; // 2h

export class InvalidPasswordResetTokenError extends Error {
  statusCode = 400;

  constructor(message = "Invalid password reset token") {
    super(message);
    this.name = "InvalidPasswordResetTokenError";
  }
}

export class ExpiredPasswordResetTokenError extends Error {
  statusCode = 410;

  constructor(message = "Password reset token has expired") {
    super(message);
    this.name = "ExpiredPasswordResetTokenError";
  }
}

export class WrongCurrentPasswordError extends Error {
  statusCode = 400;

  constructor(message = "Current password is incorrect") {
    super(message);
    this.name = "WrongCurrentPasswordError";
  }
}

export async function requestPasswordReset(
  db: DbClient,
  input: PasswordResetRequestInput,
): Promise<PasswordResetRequestResult> {
  const email = input.email.trim().toLowerCase();
  const user = await findUserByEmailRow(db, email);

  if (!user || !user.is_active) {
    return { requestAccepted: true };
  }

  const token = randomUUID();
  await createPasswordResetTokenRecord(db, {
    userId: user.id,
    token,
    ttlSec: PASSWORD_RESET_TTL_SEC,
  });

  // Token wird bewusst nicht direkt im API-Response ausgegeben.
  return { requestAccepted: true };
}

export async function resetPasswordWithToken(
  db: DbClient,
  input: PasswordResetConfirmInput,
): Promise<PasswordResetConfirmResult> {
  const rawToken = input.token.trim();
  if (!rawToken) {
    throw new InvalidPasswordResetTokenError("Empty password reset token");
  }

  const tokenRow = await findPasswordResetTokenByRawToken(db, rawToken);
  if (!tokenRow) {
    throw new InvalidPasswordResetTokenError("Password reset token not found");
  }

  if (tokenRow.expires_at.getTime() <= Date.now()) {
    await deletePasswordResetTokenById(db, tokenRow.id);
    throw new ExpiredPasswordResetTokenError();
  }

  const user = await findUserById(db, tokenRow.user_id);
  if (!user) {
    await deletePasswordResetTokenById(db, tokenRow.id);
    throw new InvalidPasswordResetTokenError("User for reset token not found");
  }

  const newHash = await hashPassword(input.newPassword);
  await updateCredentialPasswordByUserId(db, {
    userId: user.id,
    passwordHash: newHash,
  });

  await deletePasswordResetTokenById(db, tokenRow.id);

  return {
    user: {
      id: user.id,
      email: user.email,
    },
  };
}

export async function changePasswordAuthenticated(
  db: DbClient,
  input: PasswordChangeInput,
): Promise<PasswordChangeResult> {
  const user = await findUserById(db, input.userId);
  if (!user || !user.is_active) {
    throw new WrongCurrentPasswordError();
  }

  const credential = await findCredentialByUserId(db, user.id);
  if (!credential) {
    throw new WrongCurrentPasswordError();
  }

  const ok = await verifyPassword(credential.password_hash, input.currentPassword);
  if (!ok) {
    throw new WrongCurrentPasswordError();
  }

  const newHash = await hashPassword(input.newPassword);
  await updateCredentialPasswordByUserId(db, {
    userId: user.id,
    passwordHash: newHash,
  });

  return { changed: true };
}

export async function getPasswordHealth(): Promise<PasswordHealth> {
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
