// src/modules/internal/routes.ts
// ============================================================================
// Internal Routes (service-to-service)
// ----------------------------------------------------------------------------
// - GET /internal/tenants/:tenantId -> prüft Existenz/Aktivität eines Tenants
// - GET /internal/verify -> verifiziert Access Token + Tenant Match (für NGINX auth_request)
// - Für NGINX auth_request gedacht (Gateway bleibt "dumm", DB ist Source of Truth)
// ============================================================================

import type { FastifyInstance } from "fastify";
import { pool, type DbClient } from "../../libs/db.js";
import { verifyAccessToken } from "../../libs/jwt.js";
import { blacklistHas } from "../../libs/redis.js";

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function extractBearerToken(authHeader: unknown): string | null {
  const raw =
    typeof authHeader === "string"
      ? authHeader
      : Array.isArray(authHeader)
        ? authHeader[0]
        : undefined;

  if (!raw) return null;
  const m = raw.match(/^\s*Bearer\s+(.+)\s*$/i);
  const token = m?.[1]?.trim();
  return token && token.length > 0 ? token : null;
}

function readHeaderValue(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  if (Array.isArray(value) && typeof value[0] === "string") {
    const trimmed = value[0].trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }

  return undefined;
}

function collectScopes(payload: Record<string, unknown>): Set<string> {
  const scopes = new Set<string>();

  const addScopeString = (value: string) => {
    for (const part of value.split(/\s+/)) {
      const scope = part.trim();
      if (scope) scopes.add(scope);
    }
  };

  if (typeof payload.scope === "string") {
    addScopeString(payload.scope);
  }

  const perms = payload.permissions ?? payload.perms;
  if (Array.isArray(perms)) {
    for (const item of perms) {
      if (typeof item === "string" && item.trim()) {
        scopes.add(item.trim());
      }
    }
  } else if (typeof perms === "string") {
    addScopeString(perms);
  }

  return scopes;
}

function collectRoles(payload: Record<string, unknown>): Set<string> {
  const roles = new Set<string>();

  if (typeof payload.role === "string" && payload.role.trim()) {
    roles.add(payload.role.trim());
  }

  if (Array.isArray(payload.roles)) {
    for (const item of payload.roles) {
      if (typeof item === "string" && item.trim()) {
        roles.add(item.trim());
      }
    }
  }

  return roles;
}

export default async function internalRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // GET /internal/verify
  // -------------------------------------------------------------------------
  //
  // Für NGINX auth_request:
  // - 204: token gültig + tenant header stimmt mit claim überein
  // - 401: fehlender/ungültiger/revoked token
  // - 403: tenant mismatch
  //
  app.get("/verify", async (req, reply) => {
    const token = extractBearerToken(req.headers.authorization);
    if (!token) {
      return reply.code(401).send({ status: 401, message: "Unauthorized" });
    }

    const headerTenantRaw = readHeaderValue(req.headers["x-tenant-id"]);
    if (!headerTenantRaw || !UUID_RE.test(headerTenantRaw)) {
      return reply.code(401).send({ status: 401, message: "Unauthorized" });
    }
    const headerTenant = headerTenantRaw.toLowerCase();

    const requiredScope = readHeaderValue(req.headers["x-required-scope"]);
    const requiredRole = readHeaderValue(req.headers["x-required-role"]);

    try {
      const payload = await verifyAccessToken(token);

      if (await blacklistHas(String(payload.jti), headerTenant)) {
        return reply.code(401).send({ status: 401, message: "Unauthorized" });
      }

      const tokenTenantRaw = String(payload.tenant_id ?? payload.tid ?? "");
      if (!UUID_RE.test(tokenTenantRaw)) {
        return reply.code(401).send({ status: 401, message: "Unauthorized" });
      }
      const tokenTenant = tokenTenantRaw.toLowerCase();

      if (tokenTenant !== headerTenant) {
        return reply.code(403).send({ status: 403, message: "Forbidden" });
      }

      const claimsObject = payload as unknown as Record<string, unknown>;
      const scopes = collectScopes(claimsObject);
      const roles = collectRoles(claimsObject);

      if (requiredScope && !scopes.has(requiredScope)) {
        return reply.code(403).send({ status: 403, message: "Forbidden" });
      }

      if (requiredRole && !roles.has(requiredRole)) {
        return reply.code(403).send({ status: 403, message: "Forbidden" });
      }

      reply.header("X-User-Id", String(payload.sub));
      reply.header("X-Tenant-Id", tokenTenant);
      reply.header("X-Token-Jti", String(payload.jti));
      return reply.code(204).send();
    } catch {
      return reply.code(401).send({ status: 401, message: "Unauthorized" });
    }
  });

  // -------------------------------------------------------------------------
  // GET /internal/tenants/:tenantId
  // -------------------------------------------------------------------------
  //
  // - 200: Tenant exists/active
  // - 403: Unknown/disabled tenant
  // - 503: Registry/DB unavailable
  //
  app.get<{ Params: { tenantId: string } }>("/tenants/:tenantId", async (req, reply) => {
    const tenantId = req.params.tenantId;

    // Defensive: NGINX prüft UUID bereits, aber intern dennoch validieren.
    if (!UUID_RE.test(tenantId)) {
      return reply.code(403).send({ status: 403, message: "Unknown tenant" });
    }

    let client: DbClient | undefined;

    try {
      client = await pool.connect();
      await client.query("BEGIN");
      await client.query("SELECT set_config('app.tenant', $1, true);", [tenantId]);
      await client.query("SET LOCAL ROLE app_auth;");

      const result = await client.query<{ exists: number }>(
        "SELECT 1 AS exists FROM auth.tenants WHERE id = $1 LIMIT 1;",
        [tenantId],
      );

      await client.query("COMMIT");

      if (result.rowCount === 0) {
        return reply.code(403).send({ status: 403, message: "Unknown tenant" });
      }

      return reply.send({ ok: true });
    } catch (err) {
      if (client) {
        try { await client.query("ROLLBACK"); } catch {}
      }

      req.log.error({ err }, "tenant_registry_check_failed");
      return reply.code(503).send({ status: 503, message: "Tenant registry unavailable" });
    } finally {
      client?.release();
    }
  });
}
