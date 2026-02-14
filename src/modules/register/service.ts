// src/modules/register/service.ts
// ============================================================================
// Business-Logik für Registrierung
// ----------------------------------------------------------------------------
// - Geschäftsregeln (Duplikat-E-Mails, Passwort-Hashing)
// - Orchestriert Repository-Aufrufe (RLS-aware über DbClient)
// - Erzeugt ein E-Mail-Verifikations-Token (nur intern, nicht im HTTP-Response)
// - Modul-Healthcheck (nutzt zentralen DB-Healthcheck)
// ============================================================================

import { randomUUID } from "node:crypto";

import { hashPassword } from "../../libs/crypto.js";
import { dbHealth } from "../../libs/db.js";
import type { DbClient } from "../../libs/db.js";
import { transporter, SMTP_FROM } from "../../libs/mail.js";

import {
  findUserByEmail,
  findUserByEmailRow,
  insertUser,
  createEmailVerifyTokenRecord,
} from "./repository.js";

import type {
  RegisterRequestBody,
  RegisterResult,
  RegisterHealth,
} from "./types.js";

/**
 * TTL für E-Mail-Verifikation (Sekunden)
 * TODO: später aus ENV holen (z. B. EMAIL_VERIFY_TTL_SEC).
 */
const EMAIL_VERIFY_TTL_SEC = 60 * 60 * 24 * 3; // 3 Tage

/**
 * Haupt-UseCase: neuen User registrieren.
 *
 * Schritte:
 * 1. E-Mail normalisieren (trim + lowercase)
 * 2. Prüfen, ob E-Mail schon vorhanden (RLS-gebundener DbClient)
 * 3. Passwort hashen (zentral über libs/crypto.ts)
 * 4. User in DB eintragen (über Repository + DbClient)
 * 5. E-Mail-Verifikations-Token in auth.tokens erfassen
 * 6. PublicUser zurückgeben (keine sensiblen Felder)
 *
 * WICHTIG:
 * - Das Verify-Token wird NICHT im HTTP-Response an den Client gegeben.
 *   Es ist nur für internen Mailversand / Worker gedacht.
 *
 * RLS:
 * - db ist ein per-Request-Client, den das Tenant-/RLS-Plugin vorbereitet:
 *     BEGIN;
 *     SELECT set_config('app.tenant', '<UUID>', true);
 *     SET LOCAL ROLE app_auth;
 */
export async function registerUser(
  params: { db: DbClient } & RegisterRequestBody,
): Promise<RegisterResult> {
  const { db } = params;
  const email = params.email.trim().toLowerCase();
  const password = params.password;

  // Anti-enum: wir liefern immer "accepted" zurück, egal ob der User existiert.
  // Trotzdem: wir versuchen best-effort ein Verify-Token zu erstellen (nur wenn sinnvoll).

  // 1) Existiert User schon?
  const existingRow = await findUserByEmailRow(db, email);
  if (existingRow) {
    if (!existingRow.verified_at) {
      const verifyToken = randomUUID();
      await createEmailVerifyTokenRecord({
        client: db,
        userId: existingRow.id,
        token: verifyToken,
        ttlSec: EMAIL_VERIFY_TTL_SEC,
      });

      // Best effort mail (DEV: Mailpit). Fehler darf Registrierung nicht brechen.
      try {
        const verifyUrl = `http://localhost:8080/verify?token=${verifyToken}`;
        await transporter.sendMail({
          from: SMTP_FROM,
          to: email,
          subject: "Verify your email",
          text: `Please verify your email: ${verifyUrl}`,
        });
      } catch {
        // ignore
      }
    }

    return { requestAccepted: true };
  }

  // 2) Passwort hashen (Work-Factor/Algorithmus zentral in libs/crypto.ts)
  const passwordHash = await hashPassword(password);

  // 3) User anlegen (global identity)
  let user = await insertUser(db, email, passwordHash).catch(async (err: any) => {
    // Race-condition-safe: email UNIQUE.
    if (err?.code !== "23505") {
      throw err;
    }
    // Best effort: treat as existing.
    const existing = await findUserByEmail(db, email);
    if (!existing) {
      throw err;
    }
    return existing;
  });

  // 4) E-Mail-Verifikations-Token erzeugen (auth.tokens, type='verify_email')
  const verifyToken = randomUUID();
  await createEmailVerifyTokenRecord({
    client: db,
    userId: user.id,
    token: verifyToken,
    ttlSec: EMAIL_VERIFY_TTL_SEC,
  });

  // Best effort mail (DEV: Mailpit). Fehler darf Registrierung nicht brechen.
  try {
    const verifyUrl = `http://localhost:8080/verify?token=${verifyToken}`;
    await transporter.sendMail({
      from: SMTP_FROM,
      to: email,
      subject: "Verify your email",
      text: `Please verify your email: ${verifyUrl}`,
    });
  } catch {
    // ignore
  }

  return { requestAccepted: true };
}

// ---------------------------------------------------------------------------
// Modul-Healthcheck für /auth/register/health
// ---------------------------------------------------------------------------

/**
 * Modul-Healthcheck:
 * Nutzt den globalen DB-Healthcheck aus libs/db.ts.
 * Liefert nur einfache Informationen, ob die DB erreichbar ist.
 *
 * Wichtig:
 * - Hier wird bewusst der globale Pool-Healthcheck verwendet, nicht der
 *   RLS-gebundene Request-Client.
 */
export async function getRegisterHealth(): Promise<RegisterHealth> {
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
