// src/modules/magic-link/routes.ts
// ============================================================================
// Magic-Link-Routen als Fastify-Plugin (RLS-aware)
// ----------------------------------------------------------------------------
// - POST /auth/magic-link/request   → Magic-Link anstoßen (idempotent)
// - GET  /auth/magic-link/consume   → Magic-Link-Token konsumieren (Login)
// - GET  /auth/magic-link/health    → Modul-Healthcheck
//
// Sicherheit / Datenschutz:
// - Keine Aussage, ob eine E-Mail existiert (Request ist immer "ok")
// - Tokens werden nicht im Klartext geloggt, nur Hash/Metadaten
// - Datenminimierung: nur notwendige Infos im Response
// - DB-Zugriffe laufen über req.db (RLS-aware DbClient)
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import type { DbClient } from "../../libs/db.js";
import { env } from "../../libs/env.js";
import { sendApiError } from "../../libs/error-response.js";
import {
  getIdempotencyKey,
  readIdempotentResponse,
  writeIdempotentResponse,
} from "../../libs/idempotency.js";
import { appendOutboxEvent } from "../../libs/outbox.js";
import { hashEmailForLog } from "../../libs/pii.js";
import { streamAdd } from "../../libs/redis.js";

import {
  requestMagicLink,
  consumeMagicLink,
  getMagicLinkHealth,
  InvalidMagicLinkTokenError,
  ExpiredMagicLinkTokenError,
} from "./service.js";

// ---------------------------------------------------------------------------
// Zod-Schemas
// ---------------------------------------------------------------------------

// POST /auth/magic-link/request
const MagicLinkRequestBodySchema = z.object({
  email: z.string().email("Bitte eine gültige E-Mail-Adresse angeben."),
  redirect_uri: z.string().url().optional(),
});

type MagicLinkRequestBody = z.infer<typeof MagicLinkRequestBodySchema>;

// GET /auth/magic-link/consume?token=...
const MagicLinkConsumeQuerySchema = z.object({
  token: z.string().min(1, "Token ist Pflicht."),
});

type MagicLinkConsumeQuery = z.infer<typeof MagicLinkConsumeQuerySchema>;

function isRedirectAllowed(uri: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  if (env.REDIRECT_ALLOWLIST_ITEMS.length === 0) {
    return false;
  }

  return env.REDIRECT_ALLOWLIST_ITEMS.some((allowed) => {
    if (!allowed) return false;
    try {
      const allowedUrl = new URL(allowed);
      return parsed.origin === allowedUrl.origin;
    } catch {
      return parsed.hostname === allowed || parsed.origin === allowed;
    }
  });
}

// ---------------------------------------------------------------------------
// Routen-Plugin
// ---------------------------------------------------------------------------
//
// Erwartete Registrierung in app.ts:
//
//   import magicLinkRoutes from "./modules/magic-link/routes.js";
//   ...
//   await app.register(magicLinkRoutes, { prefix: "/auth/magic-link" });
//
// → Endpoints:
//
//   POST /auth/magic-link/request
//   GET  /auth/magic-link/consume
//   GET  /auth/magic-link/health
// ---------------------------------------------------------------------------

export default async function magicLinkRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // POST /auth/magic-link/request
  // -------------------------------------------------------------------------
  app.post<{ Body: MagicLinkRequestBody }>(
    "/request",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
      const parsed = MagicLinkRequestBodySchema.safeParse(req.body);

      if (!parsed.success) {
        return sendApiError(
          reply,
          400,
          "VALIDATION_FAILED",
          "Invalid magic-link request payload.",
          parsed.error.flatten(),
        );
      }

      const { email, redirect_uri: redirectUri } = parsed.data;
      const db = (req as any).db as DbClient;
      const tenantId = (req as any).requestedTenantId as string | undefined;
      const idempotencyKey = getIdempotencyKey(req.headers["idempotency-key"]);

      if (tenantId && idempotencyKey) {
        const existing = await readIdempotentResponse(db, {
          tenantId,
          endpoint: "POST:/auth/magic-link/request",
          idempotencyKey,
        });

        if (existing) {
          return reply.code(existing.status_code).send(existing.response_body);
        }
      }

      if (redirectUri && !isRedirectAllowed(redirectUri)) {
        return sendApiError(
          reply,
          400,
          "INVALID_REDIRECT_URI",
          "Invalid redirect URI.",
        );
      }

      try {
        const result = await requestMagicLink(db, {
          email,
          ip: req.ip,
          ua: req.headers["user-agent"],
        });

        if (tenantId) {
          await appendOutboxEvent(db, {
            tenantId,
            eventType: "auth.magic_link_requested",
            payload: {
              email_hash: hashEmailForLog(email),
              request_accepted: result.requestAccepted,
            },
            idempotencyKey,
          });
        }

        // Event für Worker/Audit (ohne Klartext-E-Mail)
        try {
          await streamAdd("auth-events", {
            type: "magic_link_requested",
            email_hash: hashEmailForLog(email),
            status: result.requestAccepted ? "accepted" : "ignored",
          }, tenantId);
        } catch (err) {
          app.log.warn({ err }, "magic_link_request_stream_failed");
      }

        // Generische Antwort – kein Leak, ob Adresse existiert
        const responseBody = {
          ok: true,
          requestAccepted: result.requestAccepted,
        };

        if (tenantId && idempotencyKey) {
          await writeIdempotentResponse(db, {
            tenantId,
            endpoint: "POST:/auth/magic-link/request",
            idempotencyKey,
            statusCode: 200,
            responseBody,
          });
        }

        return reply.code(200).send(responseBody);
      } catch (err) {
        throw err;
      }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/magic-link/consume?token=...
  // -------------------------------------------------------------------------
  app.get<{ Querystring: MagicLinkConsumeQuery }>(
    "/consume",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
      const parsed = MagicLinkConsumeQuerySchema.safeParse(req.query);

      if (!parsed.success) {
        return sendApiError(
          reply,
          400,
          "VALIDATION_FAILED",
          "Invalid magic-link consume payload.",
          parsed.error.flatten(),
        );
      }

      const { token } = parsed.data;
      const db = (req as any).db as DbClient;
      const tenantId = (req as any).requestedTenantId as string | undefined;

      try {
        const result = await consumeMagicLink(db, {
          token,
          ip: req.ip,
          ua: req.headers["user-agent"],
        });

        try {
          await streamAdd("auth-events", {
            type: "magic_link_consumed",
            sub: result.user.id,
          }, tenantId);
        } catch (err) {
          app.log.warn({ err }, "magic_link_consume_stream_failed");
        }

        return reply.code(200).send({
          access_token: result.accessToken,
          access_expires_at: result.accessTokenExpiresAt,
          refresh_token: result.refreshToken,
          refresh_expires_at: result.refreshTokenExpiresAt,
          token_type: "bearer",
          user: result.user,
        });
      } catch (err: any) {
        // Erwartete Business-Fehler → sauber mappen
        if (err instanceof InvalidMagicLinkTokenError) {
          app.log.warn("magic_link_invalid_token");
          return sendApiError(
            reply,
            400,
            "MAGIC_LINK_INVALID_TOKEN",
            "The magic link token is invalid.",
          );
        }

        if (err instanceof ExpiredMagicLinkTokenError) {
          app.log.info("magic_link_expired_token");
          return sendApiError(
            reply,
            410,
            "MAGIC_LINK_TOKEN_EXPIRED",
            "The magic link token has expired.",
          );
        }

        // Unerwartet → globaler Error-Handler
        throw err;
      }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/magic-link/health
  // -------------------------------------------------------------------------
  app.get("/health", async (_req, reply) => {
    const health = await getMagicLinkHealth();
    const statusCode = health.healthy ? 200 : 503;

    return reply.code(statusCode).send({
      module: "magic-link",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
