// src/modules/password/routes.ts
// ============================================================================
// Fastify-Routen für Passwort-Flow (RLS-aware)
// ----------------------------------------------------------------------------
// - POST /auth/password/forgot    → Passwort-Reset anstoßen (idempotent)
// - POST /auth/password/reset     → Passwort mit Reset-Token setzen
// - POST /auth/password/change    → Authentifizierter Passwortwechsel
// - GET  /auth/password/health    → Modul-Healthcheck
//
// Sicherheit / Datenschutz:
// - Strikte Eingabevalidierung mit Zod
// - Keine Aussage, ob eine E-Mail existiert (bei /forgot)
// - Tokens werden nicht geloggt, nur Metadaten / Hashes
// - DB-Zugriffe laufen über req.db (RLS-aware DbClient)
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
import { verifyAccessToken, type AccessTokenPayload } from "../../libs/jwt.js";

import {
  requestPasswordReset,
  resetPasswordWithToken,
  changePasswordAuthenticated,
  getPasswordHealth,
  InvalidPasswordResetTokenError,
  ExpiredPasswordResetTokenError,
  WrongCurrentPasswordError,
} from "./service.js";

// ---------------------------------------------------------------------------
// Zod-Schemas
// ---------------------------------------------------------------------------

// POST /auth/password/forgot
const ForgotPasswordBodySchema = z.object({
  email: z.string().email("Bitte eine gültige E-Mail-Adresse angeben."),
});

type ForgotPasswordBody = z.infer<typeof ForgotPasswordBodySchema>;

// POST /auth/password/reset
const ResetPasswordBodySchema = z.object({
  token: z.string().min(1, "Token ist Pflicht."),
  new_password: z
    .string()
    .min(8, "Passwort muss mindestens 8 Zeichen lang sein.")
    .max(72, "Passwort darf maximal 72 Zeichen lang sein."),
});

type ResetPasswordBody = z.infer<typeof ResetPasswordBodySchema>;

// POST /auth/password/change
const ChangePasswordBodySchema = z.object({
  old_password: z
    .string()
    .min(1, "Aktuelles Passwort ist Pflicht."),
  new_password: z
    .string()
    .min(8, "Neues Passwort muss mindestens 8 Zeichen lang sein.")
    .max(72, "Neues Passwort darf maximal 72 Zeichen lang sein."),
});

type ChangePasswordBody = z.infer<typeof ChangePasswordBodySchema>;

// ---------------------------------------------------------------------------
// Routen-Plugin
// ---------------------------------------------------------------------------
//
// Erwartete Registrierung in app.ts:
//
//   import passwordRoutes from "./modules/password/routes.js";
//   ...
//   await app.register(passwordRoutes, { prefix: "/auth/password" });
//
// → Endpoints:
//
//   POST /auth/password/forgot
//   POST /auth/password/reset
//   POST /auth/password/change
//   GET  /auth/password/health
// ---------------------------------------------------------------------------

export default async function passwordRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // POST /auth/password/forgot
  // -------------------------------------------------------------------------
  //
  // Zweck:
  // - Löst (idempotent) den Versand einer Passwort-Reset-Mail aus.
  // - Es wird KEINE Aussage darüber getroffen, ob die E-Mail existiert.
  //
  app.post<{ Body: ForgotPasswordBody }>(
    "/forgot",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parsed = ForgotPasswordBodySchema.safeParse(req.body);

    if (!parsed.success) {
      const errorDetails = parsed.error.flatten();
      return reply.code(400).send({
        error: {
          code: "PASSWORD_FORGOT_VALIDATION_FAILED",
          message: "Ungültige Eingabe für Passwort-Reset.",
          details: errorDetails,
        },
        statusCode: 400,
      });
    }

    const { email } = parsed.data;
    const db = (req as any).db as DbClient | undefined;
    const tenantId = (req as any).requestedTenantId as string | undefined;
    const idempotencyKey = getIdempotencyKey(req.headers["idempotency-key"]);

    if (!db) {
      app.log.error("password_forgot_missing_db_client");
      return reply.code(500).send({
        error: {
          code: "INTERNAL_DB_CONTEXT_MISSING",
          message: "Database context not available for this request.",
        },
        statusCode: 500,
      });
    }

    if (tenantId && idempotencyKey) {
      const existing = await readIdempotentResponse(db, {
        tenantId,
        endpoint: "POST:/auth/password/forgot",
        idempotencyKey,
      });

      if (existing) {
        return reply.code(existing.status_code).send(existing.response_body);
      }
    }

    try {
      const result = await requestPasswordReset(db, {
        email,
        ip: req.ip,
        ua: req.headers["user-agent"],
      });

      if (tenantId) {
        await appendOutboxEvent(db, {
          tenantId,
          eventType: "auth.password_reset_requested",
          payload: {
            email_hash: hashEmailForLog(email),
            request_accepted: result.requestAccepted,
          },
          idempotencyKey,
        });
      }

      // Event für Worker / Audit – E-Mail nur gehasht
      try {
        await streamAdd("auth-events", {
          type: "password_reset_requested",
          email_hash: hashEmailForLog(email),
          status: result.requestAccepted ? "accepted" : "ignored",
        }, tenantId);
      } catch (err) {
        app.log.warn({ err }, "password_forgot_stream_failed");
      }

      // Generische Antwort – kein Leak, ob E-Mail existiert.
      const responseBody = {
        ok: true,
        requestAccepted: result.requestAccepted,
      };

      if (tenantId && idempotencyKey) {
        await writeIdempotentResponse(db, {
          tenantId,
          endpoint: "POST:/auth/password/forgot",
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
  // POST /auth/password/reset
  // -------------------------------------------------------------------------
  //
  // Zweck:
  // - Nimmt das Reset-Token + neues Passwort entgegen
  // - Setzt Passwort neu, wenn Token gültig ist
  //
  app.post<{ Body: ResetPasswordBody }>(
    "/reset",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parsed = ResetPasswordBodySchema.safeParse(req.body);

    if (!parsed.success) {
      const errorDetails = parsed.error.flatten();
      return reply.code(400).send({
        error: {
          code: "PASSWORD_RESET_VALIDATION_FAILED",
          message: "Ungültige Eingabe für Passwort-Reset.",
          details: errorDetails,
        },
        statusCode: 400,
      });
    }

    const { token, new_password } = parsed.data;
    const db = (req as any).db as DbClient | undefined;
    const tenantId = (req as any).requestedTenantId as string | undefined;

    if (!db) {
      app.log.error("password_reset_missing_db_client");
      return reply.code(500).send({
        error: {
          code: "INTERNAL_DB_CONTEXT_MISSING",
          message: "Database context not available for this request.",
        },
        statusCode: 500,
      });
    }

    try {
      const result = await resetPasswordWithToken(db, {
        token,
        newPassword: new_password,
      });

      // Event für Auditing / Worker
      try {
        await streamAdd("auth-events", {
          type: "password_reset_completed",
          sub: result.user.id,
        }, tenantId);
      } catch (err) {
        app.log.warn({ err }, "password_reset_stream_failed");
      }

      return reply.code(200).send({
        ok: true,
        user: {
          id: result.user.id,
          email: result.user.email,
        },
      });
    } catch (err: any) {
      if (err instanceof InvalidPasswordResetTokenError) {
        app.log.warn("password_reset_invalid_token");
        return reply.code(400).send({
          error: {
            code: "PASSWORD_RESET_INVALID_TOKEN",
            message: "Das Reset-Token ist ungültig.",
          },
          statusCode: 400,
        });
      }

      if (err instanceof ExpiredPasswordResetTokenError) {
        app.log.info("password_reset_expired_token");
        return reply.code(410).send({
          error: {
            code: "PASSWORD_RESET_TOKEN_EXPIRED",
            message: "Das Reset-Token ist abgelaufen.",
          },
          statusCode: 410,
        });
      }

      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/password/change
  // -------------------------------------------------------------------------
  //
  // Zweck:
  // - Authentifizierter User ändert sein Passwort
  // - Authentifizierung via Bearer-Access-Token
  //
  app.post<{ Body: ChangePasswordBody }>(
    "/change",
    { config: { tenant: true, auth: true } },
    async (req, reply) => {
    const parsed = ChangePasswordBodySchema.safeParse(req.body);

    if (!parsed.success) {
      const errorDetails = parsed.error.flatten();
      return reply.code(400).send({
        error: {
          code: "PASSWORD_CHANGE_VALIDATION_FAILED",
          message: "Ungültige Eingabe für Passwortänderung.",
          details: errorDetails,
        },
        statusCode: 400,
      });
    }

    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

    if (!token) {
      return reply.code(401).send({
        error: {
          code: "MISSING_TOKEN",
          message: "Authorization-Header mit Bearer-Token fehlt.",
        },
        statusCode: 401,
      });
    }

    const db = (req as any).db as DbClient | undefined;

    if (!db) {
      app.log.error("password_change_missing_db_client");
      return reply.code(500).send({
        error: {
          code: "INTERNAL_DB_CONTEXT_MISSING",
          message: "Database context not available for this request.",
        },
        statusCode: 500,
      });
    }

    const { old_password, new_password } = parsed.data;

    try {
      const payload: AccessTokenPayload = await verifyAccessToken(token);

      const result = await changePasswordAuthenticated(db, {
        userId: String(payload.sub),
        currentPassword: old_password,
        newPassword: new_password,
      });

      try {
        await streamAdd("auth-events", {
          type: "password_changed",
          sub: String(payload.sub),
        }, String(payload.tenant_id));
      } catch (err) {
        app.log.warn({ err }, "password_change_stream_failed");
      }

      return reply.code(200).send({
        ok: result.changed,
      });
    } catch (err: any) {
      if (err instanceof WrongCurrentPasswordError) {
        return reply.code(400).send({
          error: {
            code: "PASSWORD_CHANGE_WRONG_CURRENT_PASSWORD",
            message: "Das aktuelle Passwort ist nicht korrekt.",
          },
          statusCode: 400,
        });
      }

      // Token-Fehler etc.
      if ((err as any).name === "JsonWebTokenError") {
        return reply.code(401).send({
          error: {
            code: "INVALID_TOKEN",
            message: "Ungültiges oder abgelaufenes Token.",
          },
          statusCode: 401,
        });
      }

      throw err;
    }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/password/health
  // -------------------------------------------------------------------------
  app.get("/health", async (_req, reply) => {
    const health = await getPasswordHealth();
    const statusCode = health.healthy ? 200 : 503;

    return reply.code(statusCode).send({
      module: "password",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
