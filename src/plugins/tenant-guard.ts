// src/plugins/tenant-guard.ts
// ============================================================================
// Tenant Guard (Fastify)
// ----------------------------------------------------------------------------
// Verantwortung (Policy Layer):
// - Für Routes mit config.auth === true:
//   - X-Tenant-Id Header lesen + UUID-format validieren
//   - JWT tenant_id (cryptographically bound) erzwingen (existiert durch verifyAccessToken)
//   - Header vs JWT matchen -> bei mismatch: 403
//   - verified Tenant in request.tenantId setzen (Quelle: JWT, nicht Header)
//
// Wichtig:
// - Niemals request.tenantId aus dem Raw-Header für DB/RLS verwenden.
// - Dieser Guard stellt sicher, dass request.tenantId ausschließlich aus dem JWT kommt.
// - Health/System-Endpoints bleiben tenant-free.
//
// Abhängigkeiten:
// - auth.ts muss vorher laufen und request.user setzen.
// - tenant-db-context.ts nutzt request.tenantId (verified) für set_config('app.tenant', ...).
// ============================================================================

import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import { isHealthPath } from "../libs/http.js";
import type { AccessTokenPayload } from "../libs/jwt.js";
import { sendApiError } from "../libs/error-response.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function getRouteNeedsAuth(req: any): boolean {
  return (req.routeOptions?.config as any)?.auth === true;
}

function normalizeHeaderValue(v: unknown): string | undefined {
  if (typeof v === "string") {
    const t = v.trim();
    return t.length > 0 ? t : undefined;
  }
  if (Array.isArray(v) && typeof v[0] === "string") {
    const t = v[0].trim();
    return t.length > 0 ? t : undefined;
  }
  return undefined;
}

function readTenantHeader(headers: Record<string, unknown>): string | undefined {
  // Header ist case-insensitiv; Fastify normalisiert i.d.R. auf lowercase keys
  const raw = headers["x-tenant-id"];
  const value = normalizeHeaderValue(raw);
  return value;
}

function canonicalizeUuid(uuid: string): string {
  return uuid.trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

const tenantGuardPlugin: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", async (request, reply) => {
    // 1) Health/System-Pfade niemals blockieren
    if (isHealthPath(request)) return;

    // 2) Nur für Routen, die wirklich Auth verlangen
    if (!getRouteNeedsAuth(request)) return;

    // 3) Auth-Kontext muss existieren (kommt aus plugins/auth.ts)
    const user = request.user as AccessTokenPayload | undefined;
    if (!user) {
      return sendApiError(reply, 401, "INVALID_TOKEN", "Missing auth context.");
    }

    // 4) JWT tenant_id ist Pflicht (verifyAccessToken erzwingt das bereits defensiv,
    //    aber wir bleiben robust bei falschen Typings/Callsites)
    const jwtTenant = user.tenant_id;
    if (!jwtTenant || !UUID_RE.test(jwtTenant)) {
      return sendApiError(reply, 401, "INVALID_TOKEN", "Missing tenant claim.");
    }

    // 5) Tenant Header lesen + validieren
    const headerTenant = readTenantHeader(request.headers as any);
    if (!headerTenant) {
      return sendApiError(
        reply,
        400,
        "VALIDATION_FAILED",
        "Missing X-Tenant-Id header.",
      );
    }
    if (!UUID_RE.test(headerTenant)) {
      return sendApiError(
        reply,
        400,
        "VALIDATION_FAILED",
        "Invalid X-Tenant-Id header.",
      );
    }

    // 6) Header vs JWT Match erzwingen
    const headerTenantCanonical = canonicalizeUuid(headerTenant);
    const jwtTenantCanonical = canonicalizeUuid(jwtTenant);

    if (headerTenantCanonical !== jwtTenantCanonical) {
      return sendApiError(reply, 403, "TENANT_MISMATCH", "Tenant mismatch.");
    }

    // 7) Verified Tenant für Downstream/DB setzen (Quelle: JWT!)
    //    -> überschreibt ggf. Werte aus tenant-context (falls der raw header dort gelandet ist)
    request.tenantId = jwtTenantCanonical;
  });
};

export default fp(tenantGuardPlugin, {
  name: "tenant-guard",
  // Optional: wenn du dependencies nutzt
  // dependencies: ["auth"],
});
