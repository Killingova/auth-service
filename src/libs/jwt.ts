// src/libs/jwt.ts
// ============================================================================
// JWT-Hilfen (JOSE)
// ----------------------------------------------------------------------------
// Design:
// - HS256 Symmetric Key (JWT_SECRET via env.ts, secrets-first)
// - JTI pro Token (Blacklist/Audit möglich)
// - typ="access" im Payload
// - tenant_id ist optional:
//   * Model A (tenant-bound token): tenant_id vorhanden
//   * Model B (global identity token): tenant_id fehlt; Tenant wird via membership geprüft
// ============================================================================

import crypto from "node:crypto";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { env } from "./env.js";

// ---------------------------------------------------------------------------
// JWT Secret laden (secrets-first via env.ts)
// ---------------------------------------------------------------------------

const activeRawSecret = env.JWT_SECRET_ACTIVE ?? env.JWT_SECRET;
const previousRawSecret = env.JWT_SECRET_PREVIOUS;

if (!activeRawSecret) {
  // Kein unsicherer Fallback (auch nicht in dev/test) -> bewusstes Setup erzwingen
  throw new Error(
    "JWT Secret fehlt: setze JWT_SECRET_ACTIVE oder JWT_SECRET_ACTIVE_FILE (Legacy: JWT_SECRET).",
  );
}

const activeSecret = new TextEncoder().encode(activeRawSecret);
const previousSecret = previousRawSecret
  ? new TextEncoder().encode(previousRawSecret)
  : undefined;

// Issuer/Audience: optional über env steuerbar
// (wenn du diese Variablen noch nicht im env.ts Schema hast: ergänzen)
const JWT_ISSUER = env.JWT_ISSUER ?? "auth-service";
const JWT_AUDIENCE = env.JWT_AUDIENCE ?? "auth-client";
const JWT_DEFAULT_SCOPE = (env.JWT_DEFAULT_SCOPE ?? "").trim();

// TTL: lieber über env.ts führen (hier fallback auf process.env für Legacy)
const DEFAULT_ACCESS_TTL_SEC = Number(env.JWT_ACCESS_TTL ?? process.env.JWT_ACCESS_TTL ?? 900);

// ---------------------------------------------------------------------------
// UUID-Validator (Format-Check, keine Allowlist)
// ---------------------------------------------------------------------------

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function assertUuid(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new Error(`${label}_invalid`);
  }
}

// ---------------------------------------------------------------------------
// Typdefinition Access-Token Payload
// ---------------------------------------------------------------------------

export interface AccessTokenPayload extends JWTPayload {
  // Standard JWT Claims (teilweise optional in JWTPayload)
  sub: string;          // User-ID (subject)
  jti: string;          // Token-ID
  exp: number;          // Ablauf (Unix-Sekunden)
  iat: number;          // Issued-at

  // Unsere Pflicht-Claims
  typ: "access";
  tenant_id?: string;   // UUID (wenn tenant-bound)
  tid?: string;         // optionaler Alias
  sid?: string;         // Session / Refresh family id
  ver?: number;         // Claim schema version
  role?: string;
  roles?: string[];
  plan?: string;
  permissions?: string[];
  perms?: string[];
  scope?: string;
}

type AccessTokenExtraClaims = {
  sid?: string;
  ver?: number;
  role?: string;
  roles?: string[];
  plan?: string;
};

// ---------------------------------------------------------------------------
// Access-Token signieren
// ---------------------------------------------------------------------------
// sub      = userId
// tenantId = verified tenant (aus DB/Session), NICHT aus Header
// ttlSec   = Sekunden bis exp
// ----------------------------------------------------------------------------

export async function signAccessToken(
  sub: string,
  tenantId?: string,
  ttlSec: number = DEFAULT_ACCESS_TTL_SEC,
  extraClaims: AccessTokenExtraClaims = {},
): Promise<{ token: string; jti: string; exp: number }> {
  // Defensive Validation (fail fast, sauberer Fehler)
  if (!sub || typeof sub !== "string") throw new Error("sub_missing");
  if (tenantId !== undefined && tenantId !== null && tenantId !== "") {
    assertUuid(tenantId, "tenant_id");
  } else {
    tenantId = undefined;
  }

  if (extraClaims.sid) {
    assertUuid(extraClaims.sid, "sid");
  }

  const jti = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSec;

  // Payload enthält typ + tenant_id (wird signiert -> kann nicht gefälscht werden)
  const token = await new SignJWT({
    typ: "access",
    ver: typeof extraClaims.ver === "number" ? extraClaims.ver : 1,
    ...(tenantId ? { tenant_id: tenantId, tid: tenantId } : {}),
    ...(extraClaims.sid ? { sid: extraClaims.sid } : {}),
    ...(extraClaims.role ? { role: extraClaims.role } : {}),
    ...(Array.isArray(extraClaims.roles) ? { roles: extraClaims.roles } : {}),
    ...(extraClaims.plan ? { plan: extraClaims.plan } : {}),
    ...(JWT_DEFAULT_SCOPE ? { scope: JWT_DEFAULT_SCOPE } : {}),
  })
    .setProtectedHeader({
      alg: "HS256",
      ...(env.JWT_ACTIVE_KID ? { kid: env.JWT_ACTIVE_KID } : {}),
    })
    .setSubject(sub)
    .setJti(jti)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .setIssuer(JWT_ISSUER)
    .setAudience(JWT_AUDIENCE)
    .sign(activeSecret);

  return { token, jti, exp };
}

// ---------------------------------------------------------------------------
// Access-Token verifizieren + Claims erzwingen
// ---------------------------------------------------------------------------

export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
  const verifyOptions = {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    clockTolerance: env.JWT_CLOCK_SKEW_SEC,
  } as const;

  let payload: JWTPayload;
  try {
    const verified = await jwtVerify(token, activeSecret, verifyOptions);
    payload = verified.payload;
  } catch (activeError) {
    if (!previousSecret) {
      throw activeError;
    }
    const verified = await jwtVerify(token, previousSecret, verifyOptions);
    payload = verified.payload;
  }

  // typ muss stimmen
  if (payload.typ !== "access") {
    throw new Error("invalid_token_type");
  }

  // Pflichtclaims erzwingen
  if (!payload.sub || typeof payload.sub !== "string") {
    throw new Error("sub_missing");
  }
  if (!payload.jti || typeof payload.jti !== "string") {
    throw new Error("jti_missing");
  }

  // tenant_id ist optional; wenn vorhanden: UUID-Format erzwingen
  const tokenTenantRaw = (payload as any).tenant_id ?? (payload as any).tid;
  if (tokenTenantRaw !== undefined && tokenTenantRaw !== null && tokenTenantRaw !== "") {
    assertUuid(tokenTenantRaw, "tenant_id");
    (payload as any).tenant_id = tokenTenantRaw;
    (payload as any).tid = tokenTenantRaw;
  } else {
    delete (payload as any).tenant_id;
    delete (payload as any).tid;
  }

  const tokenSid = (payload as any).sid;
  if (tokenSid !== undefined) {
    assertUuid(tokenSid, "sid");
  }

  const tokenVer = (payload as any).ver;
  if (tokenVer !== undefined) {
    if (typeof tokenVer !== "number" || tokenVer < 1) {
      throw new Error("ver_invalid");
    }
  } else {
    (payload as any).ver = 1;
  }

  // Jetzt ist payload sicher als AccessTokenPayload verwendbar
  return payload as AccessTokenPayload;
}
