// src/plugins/rate-limit.ts
import type { FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import { incrLimit } from "../libs/redis.js";
import { apiError } from "../libs/error-response.js";

const WINDOW = Number(process.env.RATE_LIMIT_WINDOW ?? 60); // Sekunden
const MAX    = Number(process.env.RATE_LIMIT_MAX ?? 60);    // Requests/Fenster
const SENSITIVE_MAX = Number(process.env.RATE_LIMIT_AUTH_MAX ?? 10);
const SENSITIVE_ROUTES = new Set<string>([
  "/auth/login",
  "/auth/refresh",
  "/auth/password/forgot",
  "/auth/password/reset",
  "/auth/magic-link/request",
  "/auth/otp/request",
  "/auth/otp/verify",
]);

// Health-Routen zuverlässig ausnehmen (ohne Query-String)
const SKIP = new Set<string>([
  "/",
  "/health",
  "/healthz",
  "/readyz",
  "/health/live",
  "/health/ready",
  "/health/redis",
  "/health/db",
  "/health/smtp",
  "/health/stack",
  "/metrics",
  "/openapi.json",
]);

/** In onRequest ist die Route noch nicht "resolved".
 *  Deshalb robust: rohe URL nehmen, Query abtrennen, Normalisierung.
 */
function getStablePath(req: FastifyRequest): string {
  // raw.url enthält z. B. "/health?x=1"
  const raw = (req.raw?.url ?? req.url ?? "/").split("?")[0];
  // Doppelslashes o. ä. normalisieren
  return raw.replace(/\/{2,}/g, "/");
}

/** Schlüsselelement für Rate-Limit-Bucket */
function bucketKey(req: FastifyRequest): { route: string; ip: string } {
  const route = getStablePath(req);
  // IP: bei Proxy-Setups ist trustProxy=true in app.ts bereits gesetzt
  const ip = req.ip;
  return { route, ip };
}

declare module "fastify" {
  interface FastifyRequest {
    rate?: { count: number; ttl: number; blocked: boolean; max: number };
  }
}

const rateLimitPlugin: FastifyPluginAsync = async (app) => {
  app.addHook("onRequest", async (request: FastifyRequest, reply: FastifyReply) => {
    const { route, ip } = bucketKey(request);
    if (SKIP.has(route)) return;
    const maxForRoute = SENSITIVE_ROUTES.has(route) ? SENSITIVE_MAX : MAX;

    let count = 0, ttl = 0, blocked = false;

    try {
      // incrLimit(route, ip, windowSec, max)
      const res = await incrLimit(route, ip, WINDOW, maxForRoute);
      count   = res.count;
      ttl     = res.ttl;
      blocked = res.blocked;
    } catch (e) {
      // Optionales Fail-Open: bei Redis-Fehler nicht blockieren.
      request.log.warn({ e }, "rate_limit_store_error");
      count = 1; ttl = WINDOW; blocked = false;
    }

    request.rate = { count, ttl, blocked, max: maxForRoute };

    if (blocked) {
      // **Standard-Header (RFC Draft 06)** setzen
      reply
        .header("RateLimit-Limit", String(maxForRoute))
        .header("RateLimit-Remaining", "0")
        .header("RateLimit-Reset", String(Math.max(1, ttl)))
        .header("Retry-After", String(Math.max(1, ttl)));

      return reply.status(429).send({
        ...apiError(429, "RATE_LIMITED", "Too many requests."),
        reset_in_seconds: ttl,
      });
    }
  });

  // Header immer setzen (auch wenn nicht geblockt)
  app.addHook("onSend", async (request, reply, payload) => {
    if (request.rate) {
      const { count, ttl, max } = request.rate;
      const remaining = Math.max(0, max - count);

      reply
        .header("RateLimit-Limit", String(max))
        .header("RateLimit-Remaining", String(remaining))
        .header("RateLimit-Reset", String(Math.max(0, ttl)));
    }
    return payload;
  });
};

export default rateLimitPlugin;
