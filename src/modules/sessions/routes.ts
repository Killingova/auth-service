// src/modules/sessions/routes.ts
// ============================================================================
// Session-Routen als Fastify-Plugin (RLS-aware)
// ----------------------------------------------------------------------------
// - GET  /auth/sessions          → eigene Sessions listen
// - POST /auth/sessions/revoke   → eigene Session widerrufen
// - GET  /auth/sessions/health   → Modul-Healthcheck
//
// Sicherheit / Datenschutz:
// - Authentifizierung via Bearer-Access-Token (wie /auth/me)
// - Kein Zugriff auf Sessions anderer User (RLS + user_id-Filter)
// - Session-IDs werden nicht erratbar gemacht (UUIDs, RLS, user_id-Filter)
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import type { DbClient } from "../../libs/db.js";
import {
  blacklistHas,
} from "../../libs/redis.js";
import {
  verifyAccessToken,
  type AccessTokenPayload,
} from "../../libs/jwt.js";

import {
  getUserSessions,
  revokeSessionForUser,
  getSessionsHealth,
} from "./service.js";

// ---------------------------------------------------------------------------
// Zod-Schemas
// ---------------------------------------------------------------------------

// GET /auth/sessions?limit=...
const SessionsListQuerySchema = z.object({
  limit: z
    .coerce
    .number()
    .int()
    .min(1)
    .max(100)
    .optional(),
});

type SessionsListQuery = z.infer<typeof SessionsListQuerySchema>;

// POST /auth/sessions/revoke
const SessionRevokeBodySchema = z.object({
  session_id: z.string().min(1, "session_id ist Pflicht."),
});

type SessionRevokeBody = z.infer<typeof SessionRevokeBodySchema>;

// ---------------------------------------------------------------------------
// Hilfsfunktion: Access-Token aus Header validieren
// ---------------------------------------------------------------------------

async function getAuthenticatedUserId(
  app: FastifyInstance,
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

  if (await blacklistHas(jti)) {
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
//   import sessionsRoutes from "./modules/sessions/routes.js";
//   ...
//   await app.register(sessionsRoutes, { prefix: "/auth/sessions" });
//
// → Endpoints:
//
//   GET  /auth/sessions
//   POST /auth/sessions/revoke
//   GET  /auth/sessions/health
// ---------------------------------------------------------------------------

export default async function sessionsRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // GET /auth/sessions
  // -------------------------------------------------------------------------
  //
  // Listet die Sessions des aktuell authentifizierten Users.
  //
  app.get<{ Querystring: SessionsListQuery }>(
    "/",
    { config: { tenant: true, auth: true } },
    async (req, reply) => {
    try {
      const parsed = SessionsListQuerySchema.safeParse(req.query);

      if (!parsed.success) {
        const errorDetails = parsed.error.flatten();
        return reply.code(400).send({
          error: {
            code: "SESSIONS_LIST_VALIDATION_FAILED",
            message: "Ungültige Query-Parameter.",
            details: errorDetails,
          },
          statusCode: 400,
        });
      }

      const { userId } = await getAuthenticatedUserId(
        app,
        req.headers.authorization,
      );
      const db = (req as any).db as DbClient;

      const result = await getUserSessions(db, {
        userId,
        limit: parsed.data.limit,
      });

      return reply.send({
        sessions: result.sessions,
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
  // POST /auth/sessions/revoke
  // -------------------------------------------------------------------------
  //
  // Widerruft eine Session des Users (setzt revoked_at).
  // Idempotent: auch wenn keine Session gefunden wird → 200 mit revoked: false.
  //
  app.post<{ Body: SessionRevokeBody }>(
    "/revoke",
    { config: { tenant: true, auth: true } },
    async (req, reply) => {
    try {
      const parsed = SessionRevokeBodySchema.safeParse(req.body);

      if (!parsed.success) {
        const errorDetails = parsed.error.flatten();
        return reply.code(400).send({
          error: {
            code: "SESSION_REVOKE_VALIDATION_FAILED",
            message: "Ungültige Eingabe zum Widerruf einer Session.",
            details: errorDetails,
          },
          statusCode: 400,
        });
      }

      const { userId } = await getAuthenticatedUserId(
        app,
        req.headers.authorization,
      );
      const db = (req as any).db as DbClient;

      const result = await revokeSessionForUser(db, {
        userId,
        sessionId: parsed.data.session_id,
      });

      // Kein Unterschied im Statuscode – bewusst idempotent.
      return reply.code(200).send({
        revoked: result.revoked,
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
  // GET /auth/sessions/health
  // -------------------------------------------------------------------------
  app.get("/health", async (_req, reply) => {
    const health = await getSessionsHealth();
    const statusCode = health.healthy ? 200 : 503;

    return reply.code(statusCode).send({
      module: "sessions",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
