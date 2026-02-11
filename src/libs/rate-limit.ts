// ============================================================================
// src/plugins/rate-limit.ts
// ----------------------------------------------------------------------------
// Clusterfähiges Rate-Limiting (gemeinsamer Redis-Store)
// - @fastify/rate-limit mit ioredis-Singleton
// - Scope steuerbar (ip | ip-route | user | user-route)
// - Allowlist via ENV
// ============================================================================
import fp from "fastify-plugin";
import rateLimit from "@fastify/rate-limit";
import type { FastifyInstance, FastifyRequest } from "fastify";
import { env } from "../libs/env.js";
import { redis } from "../libs/redis.js";
import { getRouteId } from "../libs/http.js"; // <— Datei aus Schritt 3

// Scope-Strategie (optional via ENV)
type Scope = "ip" | "ip-route" | "user" | "user-route";
const SCOPE: Scope = (process.env.RATE_LIMIT_SCOPE as Scope) ?? "ip";

// Allowlist (kommasepariert): z. B. "127.0.0.1,10.0.0.5"
const ALLOW = (process.env.RATE_LIMIT_ALLOWLIST ?? "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const allowSet = new Set(ALLOW);

// Key-Strategie
function keyFor(req: FastifyRequest): string {
  const ip = req.ip ?? "0.0.0.0";
  const route = getRouteId(req);
  const userId = (req as any).user?.id as string | undefined;

  switch (SCOPE) {
    case "user":
      return userId ? `u:${userId}` : `ip:${ip}`;
    case "user-route":
      return userId ? `u:${userId}:${route}` : `ip:${ip}:${route}`;
    case "ip-route":
      return `ip:${ip}:${route}`;
    case "ip":
    default:
      return `ip:${ip}`;
  }
}

export default fp(async function rateLimitPlugin(app: FastifyInstance) {
  await app.register(rateLimit, {
    max: env.RATE_LIMIT_MAX,
    timeWindow: `${env.RATE_LIMIT_WINDOW}s`,

    // Clusterweit synchronisierte Zähler:
    redis,

    // Eigene Schlüsselbildung (Scope s. o.)
    keyGenerator: (req: FastifyRequest) => keyFor(req),

    // Optionale Allowlist (exakte IPs)
    allowList: (req: FastifyRequest) => allowSet.has(req.ip),

    // Saubere Header für Clients
    addHeaders: {
      "x-ratelimit-limit": true,
      "x-ratelimit-remaining": true,
      "x-ratelimit-reset": true,
    },

    // Optionales Verhalten:
    // ban: 1,
    // hook: "onSend",
  });

  app.log.info(
    {
      scope: SCOPE,
      max: env.RATE_LIMIT_MAX,
      windowSec: env.RATE_LIMIT_WINDOW,
      store: "redis",
      allowListCount: allowSet.size,
    },
    "rate_limit_enabled"
  );
}, { name: "rate-limit-plugin" });
