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
import { hashEmailForLog } from "../../libs/pii.js";
import { streamAdd } from "../../libs/redis.js";
import { sendApiError } from "../../libs/error-response.js";
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

// POST /auth/email/verify/confirm
const VerifyConfirmBodySchema = z.object({
  token: z.string().min(1, "Token ist Pflicht."),
});

type VerifyConfirmBody = z.infer<typeof VerifyConfirmBodySchema>;

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
    { config: { tenant: false, auth: false, db: true } },
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

      // Optionales Event für Worker / Audit:
      // - E-Mail wird gehasht oder weg gelassen, um DSGVO-/Security-Risiken
      //   zu minimieren.
      try {
        await streamAdd("auth-events", {
          type: "email_verify_requested",
          // kein Klartext, maximal Hash/Metadaten
          email_hash: hashEmailForLog(email),
          status: result.requestAccepted ? "accepted" : "ignored",
        });
      } catch (err) {
        app.log.warn({ err }, "email_verify_request_stream_failed");
      }

      // Generische Antwort – kein Leak, ob E-Mail bekannt ist.
      return reply.code(202).send({
        ok: true,
        message: "Wenn die E-Mail-Adresse gültig ist, erhältst du einen Verifizierungs-Link.",
      });
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
    { config: { tenant: false, auth: false, db: true } },
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

    try {
      const db = (req as any).db as DbClient;
      const result = await verifyEmailToken(db, { token });

      // Event für Auditing / Worker (z. B. Onboarding-Flow starten)
      try {
        await streamAdd("auth-events", {
          type: "email_verified",
          sub: result.user.id,
        });
      } catch (err) {
        app.log.warn({ err }, "email_verify_confirm_stream_failed");
      }

      return reply.code(204).send();
    } catch (err: any) {
      // Erwartete Business-Fehler → sauber auf HTTP mappen

      if (err instanceof InvalidVerifyTokenError) {
        app.log.warn("email_verify_invalid_token");
        return sendApiError(reply, 400, "EMAIL_VERIFY_INVALID_TOKEN", "Invalid verification token.");
      }

      if (err instanceof ExpiredVerifyTokenError) {
        app.log.info("email_verify_expired_token");
        // 410 Gone: Token war mal gültig, ist aber nicht mehr verwendbar.
        return sendApiError(reply, 410, "EMAIL_VERIFY_TOKEN_EXPIRED", "Verification token expired.");
      }

      if (err instanceof AlreadyVerifiedError) {
        app.log.info({ reason: "already_verified" }, "email_verify_already_verified");
        // Idempotent: der Link darf wiederholt verwendet werden.
        return reply.code(204).send();
      }

      // Unerwartetes → globaler Error-Handler
      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/email/verify/confirm  (Alias fuer SPA-Clients)
  // -------------------------------------------------------------------------
  app.post<{ Body: VerifyConfirmBody }>(
    "/verify/confirm",
    { config: { tenant: false, auth: false, db: true } },
    async (req, reply) => {
      const parsed = VerifyConfirmBodySchema.safeParse(req.body);

      if (!parsed.success) {
        return sendApiError(
          reply,
          400,
          "VALIDATION_FAILED",
          "Invalid verify payload.",
          parsed.error.flatten(),
        );
      }

      try {
        const db = (req as any).db as DbClient;
        await verifyEmailToken(db, { token: parsed.data.token });
        return reply.code(204).send();
      } catch (err: any) {
        if (err instanceof InvalidVerifyTokenError) {
          return sendApiError(reply, 400, "EMAIL_VERIFY_INVALID_TOKEN", "Invalid verification token.");
        }
        if (err instanceof ExpiredVerifyTokenError) {
          return sendApiError(reply, 410, "EMAIL_VERIFY_TOKEN_EXPIRED", "Verification token expired.");
        }
        if (err instanceof AlreadyVerifiedError) {
          return reply.code(204).send();
        }
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
