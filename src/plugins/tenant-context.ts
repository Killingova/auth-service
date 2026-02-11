// src/plugins/tenant-context.ts
// ============================================================================
// Tenant Context (Header Intake Only)
// ----------------------------------------------------------------------------
// Verantwortung:
// - Liest X-Tenant-Id Header
// - Validiert UUID-Format (frühes Input-Sanitizing)
// - Speichert den Header-Wert NUR als "requestedTenantId"
//
// WICHTIG:
// - Dieses Plugin setzt NICHT request.tenantId (das macht tenant-guard nach
//   JWT-Verifikation).
// - Header ist NICHT vertrauenswürdig – bei auth=true nur Vergleichswert gegen JWT tenant_id.
// - DB/RLS darf bei auth=true nicht auf Basis dieses Headers arbeiten.
//
// Reihenfolge:
// tenant-context -> auth -> tenant-guard -> tenant-db-context
// ============================================================================

import fp from "fastify-plugin";
import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import { isHealthPath } from "../libs/http.js";
import { sendApiError } from "../libs/error-response.js";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function needsTenant(req: any): boolean {
  const cfg = req.routeOptions?.config as any;
  return cfg?.tenant === true || cfg?.auth === true;
}

function normalizeHeader(v: unknown): string | undefined {
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

function canonicalizeUuid(uuid: string): string {
  return uuid.trim().toLowerCase();
}

const tenantContextPlugin: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  fastify.addHook("preHandler", async (request, reply) => {
    if (isHealthPath(request)) return;

    const raw = request.headers["x-tenant-id"];
    const headerTenant = normalizeHeader(raw);

    // Für tenant-/auth-geschützte Routen ist Tenant Pflicht
    if (needsTenant(request)) {
      if (!headerTenant || !UUID_RE.test(headerTenant)) {
        return sendApiError(
          reply,
          400,
          "VALIDATION_FAILED",
          "Missing or invalid X-Tenant-Id header.",
        );
      }
    }

    // Nur als "requested", NICHT als verified tenant
    (request as any).requestedTenantId = headerTenant
      ? canonicalizeUuid(headerTenant)
      : undefined;
  });
};

export default fp(tenantContextPlugin, { name: "tenant-context" });
