// src/modules/tokens/routes.ts
// ============================================================================
// Admin-Routen für Token-Management (optional)
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { DbClient } from "../../libs/db.js";
import { sendApiError } from "../../libs/error-response.js";
import { cleanupTokens } from "./service.js";

const CleanupBody = z
  .object({
    type: z.string().min(1).optional(),
    kind: z.string().min(1).optional(),
  })
  .refine((v) => Boolean(v.type ?? v.kind), {
    message: "type is required",
    path: ["type"],
  });

export default async function tokenRoutes(app: FastifyInstance) {
  app.post(
    "/cleanup",
    { config: { tenant: true, auth: false } },
    async (req, reply) => {
    const parsed = CleanupBody.safeParse(req.body);
    if (!parsed.success) {
      return sendApiError(
        reply,
        400,
        "VALIDATION_FAILED",
        "Invalid cleanup payload.",
        parsed.error.flatten(),
      );
    }

    const db = (req as any).db as DbClient;

    const tokenType = parsed.data.type ?? parsed.data.kind!;
    const deleted = await cleanupTokens(db, tokenType);

    return reply.send({ ok: true, deleted });
    },
  );

  app.get("/health", async (_req, reply) => {
    return reply.send({ module: "tokens", ok: true });
  });
}
