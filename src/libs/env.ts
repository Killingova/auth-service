// src/libs/env.ts
// ============================================================================
// Zentrale Umgebungsvariablen-Verwaltung (Docker + Secrets-first) mit Zod
// ----------------------------------------------------------------------------
// Ziele
// - Keine .env-Abhängigkeit (kein dotenv)
// - Secrets bevorzugt aus *_FILE (Docker secrets) lesen
// - Fail-fast nur beim echten Service-Start (nicht bei Test-Imports)
// - Keine Secret-Werte loggen (nur [set]/[unset])
//
// Hinweise (Best Practices)
// - In PROD solltest du STARTUP_VALIDATE_ENV=1 setzen (Compose), damit fehlende
//   kritische Variablen sofort auffallen.
// - JWT_SECRET sollte in PROD immer via Docker secret kommen (JWT_SECRET_FILE).
// - Issuer/Audience werden zentral definiert, damit Auth- und Profile-Service
//   konsistent validieren.
// ============================================================================

import { readFileSync } from "node:fs";
import { z } from "zod";

// ----------------------------------------------------------------------------
// Helpers: Secrets lesen
// ----------------------------------------------------------------------------

/**
 * Liest ein Secret aus einer Datei (Docker secrets: /run/secrets/*).
 * - trimmt Whitespace
 * - entfernt trailing newlines
 * - wirft Fehler, wenn Datei nicht lesbar / leer
 */
function readSecretFile(filePath: string | undefined, label: string): string | undefined {
  if (!filePath) return undefined;

  let value: string;
  try {
    value = readFileSync(filePath, "utf8");
  } catch {
    throw new Error(`${label} nicht lesbar: ${filePath}`);
  }

  const trimmed = value.replace(/\r?\n+$/, "").trim();
  if (!trimmed) throw new Error(`${label} ist leer: ${filePath}`);

  return trimmed;
}

/**
 * Entscheidet: *_FILE wird bevorzugt gelesen, ENV ist Fallback.
 * - Secrets-first fuer Container/Production
 * - ENV-Fallback fuer lokale Entwicklung
 */
function resolveFromFileOrEnv(opts: {
  envValue?: string;
  filePath?: string;
  label: string;
}): string | undefined {
  const fromFile = readSecretFile(opts.filePath, opts.label);
  if (fromFile && fromFile.trim() !== "") return fromFile;
  if (opts.envValue && opts.envValue.trim() !== "") return opts.envValue;
  return undefined;
}

/**
 * Maskiert sensible Werte für Logs.
 */
function mask(value: unknown): string {
  if (value === undefined || value === null || value === "") return "[unset]";
  return "[set]";
}

// ----------------------------------------------------------------------------
// Schema: erwartet ENV + optional *_FILE
// ----------------------------------------------------------------------------

const EnvSchema = z.object({
  // --------------------------------------------------------------------------
  // Laufzeit / Server
  // --------------------------------------------------------------------------
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  LOG_LEVEL: z.string().default("info"),

  // --------------------------------------------------------------------------
  // CORS / Debug
  // --------------------------------------------------------------------------
  CORS_ORIGIN: z.string().default("*"),
  REQUEST_ID_HEADER: z.string().default("x-request-id"),
  TRUST_PROXY: z.coerce.boolean().default(true),
  OPENAPI_ENABLED: z.coerce.boolean().default(true),
  METRICS_ENABLED: z.coerce.boolean().default(true),
  REDIRECT_ALLOWLIST: z.string().default(""),
  ENABLE_DEBUG_HEADERS: z.coerce.boolean().default(false),

  // --------------------------------------------------------------------------
  // Redis
  // - entweder REDIS_URL komplett
  // - oder granular (HOST/PORT/USERNAME/PASSWORD)
  // - PASSWORD kann via REDIS_PASSWORD_FILE kommen
  // --------------------------------------------------------------------------
  REDIS_URL: z.string().optional(),
  REDIS_HOST: z.string().optional(),
  REDIS_PORT: z.coerce.number().int().optional(),
  REDIS_USERNAME: z.string().optional(),
  REDIS_PASSWORD: z.string().optional(),
  REDIS_PASSWORD_FILE: z.string().optional(),
  REDIS_NAMESPACE: z.string().default("paradox"),

  // --------------------------------------------------------------------------
  // PostgreSQL (Auth-Service)
  // - empfohlen: DATABASE_URL via Secret-File
  // - docker host sollte ein stabiler Alias sein (z. B. auth-db), kein Containername
  // --------------------------------------------------------------------------
  DATABASE_URL: z.string().optional(),
  DATABASE_URL_FILE: z.string().optional(),

  // --------------------------------------------------------------------------
  // Rate Limit Defaults (wenn du später extern konfigurierst)
  // --------------------------------------------------------------------------
  RATE_LIMIT_WINDOW: z.coerce.number().int().positive().default(60),
  RATE_LIMIT_MAX: z.coerce.number().int().positive().default(60),
  LOGIN_SOFT_LOCK_WINDOW_SEC: z.coerce.number().int().positive().default(300),
  LOGIN_SOFT_LOCK_MAX_ATTEMPTS: z.coerce.number().int().positive().default(10),

  // --------------------------------------------------------------------------
  // SMTP / Mail (optional; in DEV kann Mailpit laufen)
  // --------------------------------------------------------------------------
  SMTP_HOST: z.string().default("localhost"),
  SMTP_PORT: z.coerce.number().int().default(1025),
  SMTP_SECURE: z.coerce.boolean().default(false),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_USER_FILE: z.string().optional(),
  SMTP_PASS_FILE: z.string().optional(),
  SMTP_FROM: z.string().default("Auth Service <no-reply@local.test>"),

  // --------------------------------------------------------------------------
  // JWT
  // - active/previous erlaubt Secret-Rotation ohne Downtime
  // - Claims müssen service-übergreifend konsistent sein
  // --------------------------------------------------------------------------
  JWT_SECRET_ACTIVE: z.string().optional(),
  JWT_SECRET_ACTIVE_FILE: z.string().optional(),
  JWT_SECRET_PREVIOUS: z.string().optional(),
  JWT_SECRET_PREVIOUS_FILE: z.string().optional(),
  TOKEN_PEPPER_ACTIVE: z.string().optional(),
  TOKEN_PEPPER_ACTIVE_FILE: z.string().optional(),
  TOKEN_PEPPER_PREVIOUS: z.string().optional(),
  TOKEN_PEPPER_PREVIOUS_FILE: z.string().optional(),

  // Legacy-Variablen (Rueckwaertskompatibilitaet)
  JWT_SECRET: z.string().optional(),
  JWT_SECRET_FILE: z.string().optional(),
  JWT_ACTIVE_KID: z.string().optional(),

  JWT_ISSUER: z.string().default("auth-service"),
  JWT_AUDIENCE: z.string().default("auth-client"),
  JWT_ACCESS_TTL: z.coerce.number().int().positive().default(900),
  JWT_CLOCK_SKEW_SEC: z.coerce.number().int().min(0).max(300).default(60),
  JWT_DEFAULT_SCOPE: z.string().default("profile:read profile:write"),

  // --------------------------------------------------------------------------
  // Startup-Validation Switch (nur als String; wir interpretieren unten)
  // --------------------------------------------------------------------------
  STARTUP_VALIDATE_ENV: z.string().optional(),
});

// ----------------------------------------------------------------------------
// Secret-Resolution: *_FILE → konkrete Werte
// ----------------------------------------------------------------------------

const resolvedRedisPassword = resolveFromFileOrEnv({
  envValue: process.env.REDIS_PASSWORD,
  filePath: process.env.REDIS_PASSWORD_FILE,
  label: "REDIS_PASSWORD_FILE",
});

const resolvedDatabaseUrl = resolveFromFileOrEnv({
  envValue: process.env.DATABASE_URL,
  filePath: process.env.DATABASE_URL_FILE,
  label: "DATABASE_URL_FILE",
});

const resolvedSmtpUser = resolveFromFileOrEnv({
  envValue: process.env.SMTP_USER,
  filePath: process.env.SMTP_USER_FILE,
  label: "SMTP_USER_FILE",
});

const resolvedSmtpPass = resolveFromFileOrEnv({
  envValue: process.env.SMTP_PASS,
  filePath: process.env.SMTP_PASS_FILE,
  label: "SMTP_PASS_FILE",
});

const resolvedJwtSecretActive = resolveFromFileOrEnv({
  envValue: process.env.JWT_SECRET_ACTIVE ?? process.env.JWT_SECRET,
  filePath: process.env.JWT_SECRET_ACTIVE_FILE ?? process.env.JWT_SECRET_FILE,
  label: "JWT_SECRET_ACTIVE_FILE",
});

const resolvedJwtSecretPrevious = resolveFromFileOrEnv({
  envValue: process.env.JWT_SECRET_PREVIOUS,
  filePath: process.env.JWT_SECRET_PREVIOUS_FILE,
  label: "JWT_SECRET_PREVIOUS_FILE",
});

const resolvedTokenPepperActive = resolveFromFileOrEnv({
  envValue: process.env.TOKEN_PEPPER_ACTIVE ?? process.env.TOKEN_PEPPER,
  filePath: process.env.TOKEN_PEPPER_ACTIVE_FILE ?? process.env.TOKEN_PEPPER_FILE,
  label: "TOKEN_PEPPER_ACTIVE_FILE",
});

const resolvedTokenPepperPrevious = resolveFromFileOrEnv({
  envValue: process.env.TOKEN_PEPPER_PREVIOUS,
  filePath: process.env.TOKEN_PEPPER_PREVIOUS_FILE,
  label: "TOKEN_PEPPER_PREVIOUS_FILE",
});

// ----------------------------------------------------------------------------
// Parse & Normalize
// ----------------------------------------------------------------------------

const raw = EnvSchema.parse({
  ...process.env,
  REDIS_PASSWORD: resolvedRedisPassword,
  DATABASE_URL: resolvedDatabaseUrl,
  SMTP_USER: resolvedSmtpUser,
  SMTP_PASS: resolvedSmtpPass,
  JWT_SECRET_ACTIVE: resolvedJwtSecretActive,
  JWT_SECRET_PREVIOUS: resolvedJwtSecretPrevious,
  TOKEN_PEPPER_ACTIVE: resolvedTokenPepperActive,
  TOKEN_PEPPER_PREVIOUS: resolvedTokenPepperPrevious,
  // Legacy alias fuer bestehende Imports
  JWT_SECRET: resolvedJwtSecretActive,
});

/**
 * Baut eine Redis-URL aus granularen Feldern, falls REDIS_URL nicht gesetzt ist.
 * Erwartet: HOST, PORT, USERNAME, PASSWORD.
 */
function buildRedisUrl(input: {
  REDIS_URL?: string;
  REDIS_HOST?: string;
  REDIS_PORT?: number;
  REDIS_USERNAME?: string;
  REDIS_PASSWORD?: string;
}): string | undefined {
  if (input.REDIS_URL) return input.REDIS_URL;

  const { REDIS_HOST, REDIS_PORT, REDIS_USERNAME, REDIS_PASSWORD } = input;
  if (!REDIS_HOST || !REDIS_PORT || !REDIS_USERNAME || !REDIS_PASSWORD) return undefined;

  const u = encodeURIComponent(REDIS_USERNAME);
  const p = encodeURIComponent(REDIS_PASSWORD);
  return `redis://${u}:${p}@${REDIS_HOST}:${REDIS_PORT}`;
}

// Final export: normalisierte ENV (REDIS_URL ggf. abgeleitet)
export const env = {
  ...raw,
  REQUEST_ID_HEADER: raw.REQUEST_ID_HEADER.toLowerCase(),
  REDIS_URL: buildRedisUrl(raw),
  REDIRECT_ALLOWLIST_ITEMS: raw.REDIRECT_ALLOWLIST.split(",")
    .map((value) => value.trim())
    .filter(Boolean),
};

// ----------------------------------------------------------------------------
// Fail-fast: nur wenn Service wirklich startet
// ----------------------------------------------------------------------------
//
// Vitest importiert Module, bevor Setup-Dateien laufen → nicht in test crashen.
// Reine Builds (tsc) sollen auch nicht vom Laufzeit-Env abhängen.
//
// Schalter:
// - STARTUP_VALIDATE_ENV=1 -> immer validieren (typisch im Container)
// - sonst: validate in development/production, nicht in test
//
const shouldValidate =
  process.env.STARTUP_VALIDATE_ENV === "1" ? true : env.NODE_ENV !== "test";

if (shouldValidate) {
  // Auth-Service braucht DB+Redis (typisch immer)
  if (!env.DATABASE_URL) {
    throw new Error("DATABASE_URL fehlt: setze DATABASE_URL oder DATABASE_URL_FILE.");
  }
  if (!env.REDIS_URL) {
    throw new Error(
      "Redis-Konfiguration fehlt: setze REDIS_URL oder alle REDIS_HOST/REDIS_PORT/REDIS_USERNAME/REDIS_PASSWORD (alternativ REDIS_PASSWORD_FILE).",
    );
  }

  // JWT: in PROD muss ein aktives Secret vorhanden sein
  if (env.NODE_ENV === "production" && !env.JWT_SECRET_ACTIVE) {
    throw new Error(
      "JWT Secret fehlt: setze JWT_SECRET_ACTIVE oder JWT_SECRET_ACTIVE_FILE.",
    );
  }

  // Production-CORS Warnung (nicht hart failen, nur warnen)
  if (env.NODE_ENV === "production" && env.CORS_ORIGIN === "*") {
    // eslint-disable-next-line no-console
    console.warn("[env] WARNUNG: In Production sollte CORS_ORIGIN nicht '*'' sein.");
  }
}

// ----------------------------------------------------------------------------
// Debug-Ausgabe ohne Secrets
// ----------------------------------------------------------------------------

/**
 * Gibt eine sichere Zusammenfassung der Konfiguration aus (ohne Secrets).
 * Kann z.B. beim Startup einmal geloggt werden.
 */
export function logEnvSummary(
  log: (msg: string, extra?: unknown) => void = console.info,
) {
  const summary = {
    // Runtime
    NODE_ENV: env.NODE_ENV,
    HOST: env.HOST,
    PORT: env.PORT,
    LOG_LEVEL: env.LOG_LEVEL,

    // HTTP / Debug
    CORS_ORIGIN: env.CORS_ORIGIN,
    REQUEST_ID_HEADER: env.REQUEST_ID_HEADER,
    TRUST_PROXY: env.TRUST_PROXY,
    OPENAPI_ENABLED: env.OPENAPI_ENABLED,
    METRICS_ENABLED: env.METRICS_ENABLED,
    REDIRECT_ALLOWLIST: env.REDIRECT_ALLOWLIST_ITEMS.length,
    ENABLE_DEBUG_HEADERS: env.ENABLE_DEBUG_HEADERS,

    // Redis
    REDIS_URL: mask(env.REDIS_URL),
    REDIS_NAMESPACE: env.REDIS_NAMESPACE,

    // DB
    DATABASE_URL: mask(env.DATABASE_URL),

    // Rate limit
    RATE_LIMIT_WINDOW: env.RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX: env.RATE_LIMIT_MAX,
    LOGIN_SOFT_LOCK_WINDOW_SEC: env.LOGIN_SOFT_LOCK_WINDOW_SEC,
    LOGIN_SOFT_LOCK_MAX_ATTEMPTS: env.LOGIN_SOFT_LOCK_MAX_ATTEMPTS,

    // SMTP
    SMTP_HOST: env.SMTP_HOST,
    SMTP_PORT: env.SMTP_PORT,
    SMTP_SECURE: env.SMTP_SECURE,
    SMTP_USER: mask(env.SMTP_USER),
    SMTP_PASS: mask(env.SMTP_PASS),
    SMTP_FROM: env.SMTP_FROM,

    // JWT
    JWT_SECRET_ACTIVE: mask(env.JWT_SECRET_ACTIVE),
    JWT_SECRET_PREVIOUS: mask(env.JWT_SECRET_PREVIOUS),
    TOKEN_PEPPER_ACTIVE: mask(env.TOKEN_PEPPER_ACTIVE),
    TOKEN_PEPPER_PREVIOUS: mask(env.TOKEN_PEPPER_PREVIOUS),
    JWT_ACTIVE_KID: env.JWT_ACTIVE_KID ?? "[unset]",
    JWT_ISSUER: env.JWT_ISSUER,
    JWT_AUDIENCE: env.JWT_AUDIENCE,
    JWT_CLOCK_SKEW_SEC: env.JWT_CLOCK_SKEW_SEC,
  };

  log("[env] configuration summary", summary);
}

export type Env = typeof env;
