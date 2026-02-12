// src/modules/email-verify/routes.ts
// ============================================================================
// E-Mail-Verifikations-Routen als Fastify-Plugin
// ----------------------------------------------------------------------------
// - POST /auth/email/verify/request   → Verify-Mail anstoßen (idempotent)
// - GET  /auth/email/verify/confirm   → Verify-Token einlösen
// - GET  /auth/email/verify/health    → Modul-Healthcheck
//
// Sicherheit / Datenschutz:
// - Keine Aussage, ob eine E-Mail existiert (Request ist immer "ok")
// - Tokens werden nicht geloggt, nur Metadaten / Fehlercodes
// - Datenminimierung im Response (id, email, flags)
// - Ideal für Verwendung mit RLS-DB-Plugin (request.db)
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import type { DbClient } from "../../libs/db.js";
import {
  getIdempotencyKey,
  readIdempotentResponse,
  writeIdempotentResponse,
} from "../../libs/idempotency.js";
import { appendOutboxEvent } from "../../libs/outbox.js";
import { hashEmailForLog } from "../../libs/pii.js";
import { streamAdd } from "../../libs/redis.js";
import {
  requestEmailVerification,
  verifyEmailToken,
  getVerifyHealth,
  InvalidVerifyTokenError,
  ExpiredVerifyTokenError,
  AlreadyVerifiedError,
} from "./service.js";

// ---------------------------------------------------------------------------
// Zod-Schemas
// ---------------------------------------------------------------------------

// POST /auth/email/verify/request
const VerifyRequestBodySchema = z.object({
  email: z.string().email("Bitte eine gültige E-Mail-Adresse angeben."),
});

type VerifyRequestBody = z.infer<typeof VerifyRequestBodySchema>;

// GET /auth/email/verify/confirm?token=...
const VerifyConfirmQuerySchema = z.object({
  token: z.string().min(1, "Token ist Pflicht."),
});

type VerifyConfirmQuery = z.infer<typeof VerifyConfirmQuerySchema>;

// ---------------------------------------------------------------------------
// Routen-Plugin
// ---------------------------------------------------------------------------
//
// Erwartete Registrierung in app.ts:
//
//   import emailVerifyRoutes from "./modules/email-verify/routes.js";
//   ...
//   await app.register(emailVerifyRoutes, { prefix: "/auth/email" });
//
// → Endpoints:
//
//   POST /auth/email/verify/request
//   GET  /auth/email/verify/confirm
//   GET  /auth/email/verify/health
// ---------------------------------------------------------------------------

export default async function emailVerifyRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // POST /auth/email/verify/request
  // -------------------------------------------------------------------------
  //
  // Zweck:
  // - Löst (idempotent) den Versand einer E-Mail-Verifikation aus.
  // - Aus Security-/DSGVO-Sicht wird KEINE Aussage darüber getroffen,
  //   ob die E-Mail existiert oder nicht.
  //
  app.post<{ Body: VerifyRequestBody }>(
    "/verify/request",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parsed = VerifyRequestBodySchema.safeParse(req.body);

    if (!parsed.success) {
      const errorDetails = parsed.error.flatten();
      return reply.code(400).send({
        error: {
          code: "EMAIL_VERIFY_REQUEST_VALIDATION_FAILED",
          message: "Ungültige Eingabe für E-Mail-Verifikation.",
          details: errorDetails,
        },
        statusCode: 400,
      });
    }

    const { email } = parsed.data;
    const db = (req as any).db as DbClient;
    const tenantId = (req as any).requestedTenantId as string | undefined;
    const idempotencyKey = getIdempotencyKey(req.headers["idempotency-key"]);

    if (tenantId && idempotencyKey) {
      const existing = await readIdempotentResponse(db, {
        tenantId,
        endpoint: "POST:/auth/email/verify/request",
        idempotencyKey,
      });

      if (existing) {
        return reply.code(existing.status_code).send(existing.response_body);
      }
    }

    try {
      // Der Service entscheidet selbst, ob:
      // - User existiert
      // - bereits verifiziert
      // - ein neues Token erzeugt wird
      //
      // Er MUSS dabei keine Information preisgeben, ob die E-Mail existiert.
      const result = await requestEmailVerification(db, {
        email,
        ip: req.ip,
        ua: req.headers["user-agent"],
      });

      if (tenantId) {
        await appendOutboxEvent(db, {
          tenantId,
          eventType: "auth.email_verify_requested",
          payload: {
            email_hash: hashEmailForLog(email),
            request_accepted: result.requestAccepted,
          },
          idempotencyKey,
        });
      }

      // Optionales Event für Worker / Audit:
      // - E-Mail wird gehasht oder weg gelassen, um DSGVO-/Security-Risiken
      //   zu minimieren.
      try {
        await streamAdd("auth-events", {
          type: "email_verify_requested",
          // kein Klartext, maximal Hash/Metadaten
          email_hash: hashEmailForLog(email),
          status: result.requestAccepted ? "accepted" : "ignored",
        }, tenantId);
      } catch (err) {
        app.log.warn({ err }, "email_verify_request_stream_failed");
      }

      // Generische Antwort – "wir haben, was wir tun konnten, getan".
      // Kein Leak, ob E-Mail bekannt ist.
      const responseBody = {
        ok: true,
        // Optionales Flag, nur für Frontend-UX – aber ohne Sicherheitsrisiko:
        // z.B. false, wenn der User schon verifiziert war.
        requestAccepted: result.requestAccepted,
      };

      if (tenantId && idempotencyKey) {
        await writeIdempotentResponse(db, {
          tenantId,
          endpoint: "POST:/auth/email/verify/request",
          idempotencyKey,
          statusCode: 200,
          responseBody,
        });
      }

      return reply.code(200).send(responseBody);
    } catch (err) {
      // Unerwartete Fehler → globaler Error-Handler (app.ts)
      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/email/verify/confirm?token=...
  // -------------------------------------------------------------------------
  //
  // Zweck:
  // - Nimmt das Verify-Token (JTI o. ä.) entgegen
  // - Prüft Gültigkeit / Ablauf / Status
  // - Markiert den User als verifiziert
  // - Verbraucht (löscht) das Token
  //
  app.get<{ Querystring: VerifyConfirmQuery }>(
    "/verify/confirm",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parsed = VerifyConfirmQuerySchema.safeParse(req.query);

    if (!parsed.success) {
      const errorDetails = parsed.error.flatten();
      return reply.code(400).send({
        error: {
          code: "EMAIL_VERIFY_CONFIRM_VALIDATION_FAILED",
          message: "Ungültiger Verify-Request.",
          details: errorDetails,
        },
        statusCode: 400,
      });
    }

    const { token } = parsed.data;
    const tenantId = (req as any).requestedTenantId as string | undefined;

    try {
      const db = (req as any).db as DbClient;
      const result = await verifyEmailToken(db, { token });

      // Event für Auditing / Worker (z. B. Onboarding-Flow starten)
      try {
        await streamAdd("auth-events", {
          type: "email_verified",
          sub: result.user.id,
        }, tenantId);
      } catch (err) {
        app.log.warn({ err }, "email_verify_confirm_stream_failed");
      }

      return reply.code(200).send({
        verified: true,
        alreadyVerified: result.alreadyVerified ?? false,
        user: {
          id: result.user.id,
          email: result.user.email,
        },
      });
    } catch (err: any) {
      // Erwartete Business-Fehler → sauber auf HTTP mappen

      if (err instanceof InvalidVerifyTokenError) {
        app.log.warn("email_verify_invalid_token");
        return reply.code(400).send({
          error: {
            code: "EMAIL_VERIFY_INVALID_TOKEN",
            message: "Das Verifikations-Token ist ungültig.",
          },
          statusCode: 400,
        });
      }

      if (err instanceof ExpiredVerifyTokenError) {
        app.log.info("email_verify_expired_token");
        // 410 Gone: Token war mal gültig, ist aber nicht mehr verwendbar.
        return reply.code(410).send({
          error: {
            code: "EMAIL_VERIFY_TOKEN_EXPIRED",
            message: "Das Verifikations-Token ist abgelaufen.",
          },
          statusCode: 410,
        });
      }

      if (err instanceof AlreadyVerifiedError) {
        app.log.info({ reason: "already_verified" }, "email_verify_already_verified");
        // 200 oder 409 – Designentscheidung.
        // Hier: 200, damit der Link idempotent ist und UX-freundlich bleibt.
        return reply.code(200).send({
          verified: true,
          alreadyVerified: true,
        });
      }

      // Unerwartetes → globaler Error-Handler
      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/email/verify/health
  // -------------------------------------------------------------------------
  //
  // Einfacher Modul-Healthcheck (z. B. DB erreichbar?)
  //
  app.get("/verify/health", async (_req, reply) => {
    const health = await getVerifyHealth();
    const statusCode = health.healthy ? 200 : 503;

    return reply.code(statusCode).send({
      module: "email-verify",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
