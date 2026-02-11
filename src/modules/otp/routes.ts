// src/modules/otp/routes.ts
// ============================================================================
// OTP-Routen
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
import { requestOtp, verifyOtp, getOtpHealth } from "./service.js";

// Zod
const OtpRequestBody = z.object({
  email: z.string().email(),
});

const OtpVerifyBody = z.object({
  email: z.string().email(),
  code: z.string().length(6),
});

export default async function otpRoutes(app: FastifyInstance) {
  // /auth/otp/request
  app.post(
    "/request",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parse = OtpRequestBody.safeParse(req.body);
    if (!parse.success) {
      return reply.code(400).send({ error: "invalid_input" });
    }

    const db = (req as any).db as DbClient;
    const tenantId = (req as any).requestedTenantId as string | undefined;
    const idempotencyKey = getIdempotencyKey(req.headers["idempotency-key"]);

    if (tenantId && idempotencyKey) {
      const existing = await readIdempotentResponse(db, {
        tenantId,
        endpoint: "POST:/auth/otp/request",
        idempotencyKey,
      });

      if (existing) {
        return reply.code(existing.status_code).send(existing.response_body);
      }
    }

    await requestOtp(db, parse.data);

    if (tenantId) {
      await appendOutboxEvent(db, {
        tenantId,
        eventType: "auth.otp_requested",
        payload: {
          email_hash: hashEmailForLog(parse.data.email),
        },
        idempotencyKey,
      });
    }

    const responseBody = { ok: true };

    if (tenantId && idempotencyKey) {
      await writeIdempotentResponse(db, {
        tenantId,
        endpoint: "POST:/auth/otp/request",
        idempotencyKey,
        statusCode: 200,
        responseBody,
      });
    }

    return reply.send(responseBody);
    },
  );

  // /auth/otp/verify
  app.post(
    "/verify",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parse = OtpVerifyBody.safeParse(req.body);
    if (!parse.success) {
      return reply.code(400).send({ error: "invalid_input" });
    }

    const db = (req as any).db as DbClient;

    try {
      const result = await verifyOtp(db, parse.data);
      return reply.send(result);
    } catch (err) {
      return reply.code(401).send({ error: "invalid_or_expired_otp" });
    }
    },
  );

  // /auth/otp/health
  app.get("/health", async (_req, reply) => {
    const health = await getOtpHealth();
    return reply.code(health.healthy ? 200 : 503).send({
      module: "otp",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
