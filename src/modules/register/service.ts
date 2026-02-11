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

import {
  findUserByEmail,
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
 * Business-Fehler, wenn E-Mail bereits existiert.
 * Wird von der Route abgefangen und in eine datensparsame Antwort
 * (ohne konkrete Aussage "Account existiert bereits") übersetzt.
 */
export class EmailAlreadyRegisteredError extends Error {
  statusCode = 409;

  constructor(email: string) {
    super(`Email already registered: ${email}`);
    this.name = "EmailAlreadyRegisteredError";
  }
}

// ---------------------------------------------------------------------------
// Registrierung
// ---------------------------------------------------------------------------

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

  // 1) Prüfen, ob E-Mail schon vorhanden ist (RLS-sicher über db)
  const existing = await findUserByEmail(db, email);
  if (existing) {
    // Business-Fehler: von Route abgefangen → generische Antwort, DSGVO-freundlich
    throw new EmailAlreadyRegisteredError(email);
  }

  // 2) Passwort hashen (Work-Factor/Algorithmus zentral in libs/crypto.ts)
  const passwordHash = await hashPassword(password);

  // 3) User anlegen (aktuell über Default-Tenant in insertUser; später optional
  //    tenantName aus params.tenantName nutzen, um Mandanten dynamisch anzulegen)
  let user: Awaited<ReturnType<typeof insertUser>>;
  try {
    user = await insertUser(db, email, passwordHash);
  } catch (err: any) {
    // Race-condition-safe: unique(email per tenant) sauber als Business-Fehler mappen.
    if (err?.code === "23505") {
      throw new EmailAlreadyRegisteredError(email);
    }
    throw err;
  }

  // 4) E-Mail-Verifikations-Token erzeugen (auth.tokens, type = 'verify_email')
  const verifyToken = randomUUID();
  await createEmailVerifyTokenRecord({
    client: db,
    userId: user.id,
    token: verifyToken,
    ttlSec: EMAIL_VERIFY_TTL_SEC,
  });

  // TODO:
  // - An dieser Stelle kannst du ein Mail-Module / Worker triggern, der eine
  //   Verify-Mail verschickt (z. B. via Redis-Stream "auth-events").
  // - verifyToken bleibt bewusst intern und wird NICHT an den Client gesendet.

  const result: RegisterResult = {
    user,
    // emailVerification könnte hier optional mit zurückgegeben werden,
    // falls du sie innerhalb des Backends weiterreichen willst
    // (nicht an den HTTP-Client!).
    // emailVerification,
  };

  return result;
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
