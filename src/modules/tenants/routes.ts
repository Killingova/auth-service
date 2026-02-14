// src/modules/tenants/routes.ts
// ============================================================================
// Tenant-Routen als Fastify-Plugin (RLS-aware)
// ----------------------------------------------------------------------------
// - GET  /auth/tenants/me      → Tenant des aktuellen Users
// - GET  /auth/tenants         → Tenants im aktuellen Kontext listen
// - GET  /auth/tenants/health  → Modul-Healthcheck
//
// Sicherheit / Datenschutz:
// - Authentifizierung via Bearer-Access-Token (wie /auth/me)
// - Kein Zugriff auf fremde Tenants (RLS + Join über user_id)
// - Datenminimierung: nur id, name, slug, createdAt
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import type { DbClient } from "../../libs/db.js";
import { blacklistHas } from "../../libs/redis.js";
import {
  verifyAccessToken,
  type AccessTokenPayload,
} from "../../libs/jwt.js";
import { sendApiError } from "../../libs/error-response.js";

import {
  getCurrentTenantForUser,
  listTenantsForContext,
  getTenantsHealth,
} from "./service.js";

// ---------------------------------------------------------------------------
// Zod-Schemas
// ---------------------------------------------------------------------------

// GET /auth/tenants?limit=...
const TenantsListQuerySchema = z.object({
  limit: z
    .coerce
    .number()
    .int()
    .min(1)
    .max(100)
    .optional(),
});

type TenantsListQuery = z.infer<typeof TenantsListQuerySchema>;

const TenantBootstrapBodySchema = z.object({
  name: z.string().min(3).max(120),
  slug: z.string().min(3).max(64).optional(),
});

type TenantBootstrapBody = z.infer<typeof TenantBootstrapBodySchema>;

// ---------------------------------------------------------------------------
// Hilfsfunktion: Access-Token aus Header validieren
// ---------------------------------------------------------------------------

async function getAuthenticatedUserId(
  authHeader: string | undefined,
): Promise<{ userId: string; jti: string; payload: AccessTokenPayload }> {
  const auth = authHeader || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

  if (!token) {
    const err: any = new Error("Authorization-Header mit Bearer-Token fehlt.");
    err.statusCode = 401;
    err.code = "MISSING_TOKEN";
    throw err;
  }

  const payload: AccessTokenPayload = await verifyAccessToken(token);
  const jti = String(payload.jti);

  if (await blacklistHas(jti, String(payload.tenant_id))) {
    const err: any = new Error("Token ist nicht mehr gültig.");
    err.statusCode = 401;
    err.code = "TOKEN_REVOKED";
    throw err;
  }

  return {
    userId: String(payload.sub),
    jti,
    payload,
  };
}

// ---------------------------------------------------------------------------
// Routen-Plugin
// ---------------------------------------------------------------------------
//
// Erwartete Registrierung in app.ts:
//
//   import tenantsRoutes from "./modules/tenants/routes.js";
//   ...
//   await app.register(tenantsRoutes, { prefix: "/auth/tenants" });
//
// → Endpoints:
//
//   GET  /auth/tenants/me
//   GET  /auth/tenants
//   GET  /auth/tenants/health
// ---------------------------------------------------------------------------

export default async function tenantsRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // POST /auth/tenants/bootstrap
  // -------------------------------------------------------------------------
  //
  // Global user Modell (Option 2):
  // - Auth required
  // - Tenant header ist NICHT erforderlich (Tenant wird hier erzeugt)
  //
  app.post<{ Body: TenantBootstrapBody }>(
    "/bootstrap",
    { config: { tenant: false, auth: true, db: true } },
    async (req, reply) => {
      const parsed = TenantBootstrapBodySchema.safeParse(req.body);
      if (!parsed.success) {
        return sendApiError(
          reply,
          400,
          "VALIDATION_FAILED",
          "Invalid tenant bootstrap payload.",
          parsed.error.flatten(),
        );
      }

      const user = req.user as AccessTokenPayload | undefined;
      if (!user) {
        return sendApiError(reply, 401, "INVALID_TOKEN", "Missing auth context.");
      }

      const db = (req as any).db as DbClient | undefined;
      if (!db) {
        return sendApiError(reply, 500, "INTERNAL", "Database context not available.");
      }

      const { name, slug } = parsed.data;

      const { rows } = await db.query<{
        tenant_id: string;
        tenant_name: string;
        tenant_slug: string;
        tenant_created_at: string;
        role: string;
        role_names: string[];
        plan_code: string;
      }>(
        `
          SELECT
            tenant_id,
            tenant_name,
            tenant_slug,
            tenant_created_at,
            role,
            role_names,
            plan_code
          FROM auth.tenants_bootstrap_for_user($1::uuid, $2::text, $3::text);
        `,
        [String(user.sub), name, slug ?? null],
      );

      const row = rows[0];
      if (!row?.tenant_id) {
        return sendApiError(reply, 500, "INTERNAL", "Tenant bootstrap failed.");
      }

      return reply.send({
        tenantId: row.tenant_id,
        tenant: {
          id: row.tenant_id,
          name: row.tenant_name,
          createdAt: row.tenant_created_at,
        },
        role: row.role,
        roles: row.role_names ?? [],
        plan: row.plan_code,
        message: "Tenant erfolgreich erstellt.",
      });
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/tenants/me
  // -------------------------------------------------------------------------
  //
  // Liefert den Tenant des aktuell authentifizierten Users.
  //
  app.get(
    "/me",
    { config: { tenant: true, auth: true } },
    async (req, reply) => {
    try {
      const { userId } = await getAuthenticatedUserId(
        req.headers.authorization,
      );

      const db = (req as any).db as DbClient;

      const result = await getCurrentTenantForUser(db, userId);

      return reply.send({
        tenant: result.tenant,
      });
    } catch (err: any) {
      if (err?.code === "MISSING_TOKEN") {
        return reply.code(401).send({
          error: {
            code: "MISSING_TOKEN",
            message: err.message,
          },
          statusCode: 401,
        });
      }

      if (err?.code === "TOKEN_REVOKED") {
        return reply.code(401).send({
          error: {
            code: "TOKEN_REVOKED",
            message: err.message,
          },
          statusCode: 401,
        });
      }

      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/tenants
  // -------------------------------------------------------------------------
  //
  // Listet Tenants im aktuellen Kontext (unter RLS in der Regel genau 1).
  //
  app.get<{ Querystring: TenantsListQuery }>(
    "/",
    { config: { tenant: true, auth: true } },
    async (req, reply) => {
    try {
      const parsed = TenantsListQuerySchema.safeParse(req.query);

      if (!parsed.success) {
        const errorDetails = parsed.error.flatten();
        return reply.code(400).send({
          error: {
            code: "TENANTS_LIST_VALIDATION_FAILED",
            message: "Ungültige Query-Parameter.",
            details: errorDetails,
          },
          statusCode: 400,
        });
      }

      // Auth erzwingt, dass nur angemeldete User ihre Tenants sehen
      await getAuthenticatedUserId(req.headers.authorization);

      const db = (req as any).db as DbClient;

      const result = await listTenantsForContext(db, parsed.data.limit);

      return reply.send({
        tenants: result.tenants,
      });
    } catch (err: any) {
      if (err?.code === "MISSING_TOKEN") {
        return reply.code(401).send({
          error: {
            code: "MISSING_TOKEN",
            message: err.message,
          },
          statusCode: 401,
        });
      }

      if (err?.code === "TOKEN_REVOKED") {
        return reply.code(401).send({
          error: {
            code: "TOKEN_REVOKED",
            message: err.message,
          },
          statusCode: 401,
        });
      }

      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/tenants/health
  // -------------------------------------------------------------------------
  app.get("/health", async (_req, reply) => {
    const health = await getTenantsHealth();
    const statusCode = health.healthy ? 200 : 503;

    return reply.code(statusCode).send({
      module: "tenants",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
