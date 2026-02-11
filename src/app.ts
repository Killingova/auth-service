// src/app.ts
// ============================================================================
// Auth-Service (Fastify + RLS)
// ----------------------------------------------------------------------------
// Verantwortlichkeiten:
//  - Zentrales Fastify-Setup (Logger, Timeouts, CORS, Rate-Limit)
//  - Redis-Init + Health
//  - DB-Health + SMTP-Health
//  - /health, /healthz, /readyz, /health/* + /health/stack
//  - Registrierung aller Auth-Module mit Tenant/Auth-Guard + RLS-/DB-Kontext
//  - Graceful Shutdown (Redis + DB via onClose)
// ============================================================================

import Fastify, {
  type FastifyInstance,
  type FastifyServerOptions,
} from "fastify";
import cors from "@fastify/cors";
// import helmet from "@fastify/helmet";
import { randomUUID } from "node:crypto";

import rateLimitPlugin from "./plugins/rate-limit.js";

// Reihenfolge / Auth-Chain
import tenantContextPlugin from "./plugins/tenant-context.js";
import authPlugin from "./plugins/auth.js";
import authorizationPlugin from "./plugins/authorization.js";
import tenantGuardPlugin from "./plugins/tenant-guard.js";
import tenantDbContextPlugin from "./plugins/tenant-db-context.js";

import { ensureRedis, redisHealth, quitRedis } from "./libs/redis.js";
import { env } from "./libs/env.js";
import { dbHealth, closeDb } from "./libs/db.js";
import { mailHealth } from "./libs/mail.js";
import { apiError } from "./libs/error-response.js";
import { mapDbError } from "./libs/error-map.js";
import { getRouteId } from "./libs/http.js";
import { recordHttpRequest, renderPrometheusMetrics } from "./libs/metrics.js";

// Auth-Module (Routen-Plugins)
import identityRoutes from "./modules/identity/routes.js";
import registerRoutes from "./modules/register/routes.js";
import emailVerifyRoutes from "./modules/email-verify/routes.js";
import passwordRoutes from "./modules/password/routes.js";
import magicLinkRoutes from "./modules/magic-link/routes.js";
import otpRoutes from "./modules/otp/routes.js";
import sessionsRoutes from "./modules/sessions/routes.js";
import tenantsRoutes from "./modules/tenants/routes.js";
import tokenRoutes from "./modules/tokens/routes.js";
import internalRoutes from "./modules/internal/routes.js";

// ---------------------------------------------------------------------------
// Readiness-Flag (von server.ts über setReady() manipulierbar)
// ---------------------------------------------------------------------------

let isReady = false;

export function setReady(ready: boolean) {
  isReady = ready;
}

// Optionale Start-Parameter für Tests / spezielle Umgebungen
type AppOptions = FastifyServerOptions & {
  enableCors?: boolean;
  corsOrigin?: string | RegExp | (string | RegExp)[];
};

// ---------------------------------------------------------------------------
// Hilfsfunktion: Auth-Module registrieren (Tenant/Auth/Guard + RLS-/DB-Kontext)
// ---------------------------------------------------------------------------

async function registerAuthModules(app: FastifyInstance) {
  await app.register(async (instance) => {
    // Kette (wichtig):
    // 1) Tenant aus Header (x-tenant-id) + Validierung
    instance.register(tenantContextPlugin);

    // 2) Auth (JWT -> request.user) – soll Health nicht stören
    instance.register(authPlugin);

    // 3) Optionaler AuthZ-Hook (permissions aus Claims/Scope)
    instance.register(authorizationPlugin);

    // 4) Guard: wenn Route config.auth === true => JWT muss da sein + Tenant-Match
    instance.register(tenantGuardPlugin);

    // 5) DB/RLS-Kontext (BEGIN, set_config(app.tenant), SET LOCAL ROLE, COMMIT/ROLLBACK)
    instance.register(tenantDbContextPlugin);

    // Danach erst Routes registrieren (damit Hooks greifen)

    // Identity / Login / Token-Refresh / me / logout
    instance.register(identityRoutes, { prefix: "/auth" });

    // Registrierung
    instance.register(registerRoutes, { prefix: "/auth" });

    // E-Mail-Verifikation
    instance.register(emailVerifyRoutes, { prefix: "/auth/email" });

    // Passwort-Reset / Passwort-Change
    instance.register(passwordRoutes, { prefix: "/auth/password" });

    // Magic-Link Login
    instance.register(magicLinkRoutes, { prefix: "/auth/magic-link" });

    // OTP (One-Time-Passcodes)
    instance.register(otpRoutes, { prefix: "/auth/otp" });

    // Sessions-Übersicht / Revoke
    instance.register(sessionsRoutes, { prefix: "/auth/sessions" });

    // Tenants (Mandantenverwaltung)
    instance.register(tenantsRoutes, { prefix: "/auth/tenants" });

    // Token-Administration / Cleanup
    instance.register(tokenRoutes, { prefix: "/auth/tokens" });
  });
}

// ---------------------------------------------------------------------------
// Hilfsfunktion: Interne Service-Routen registrieren
// ---------------------------------------------------------------------------

async function registerInternalRoutes(app: FastifyInstance) {
  await app.register(internalRoutes, { prefix: "/internal" });
}

// ---------------------------------------------------------------------------
// Hilfsfunktion: Health- und Observability-Routen registrieren
// ---------------------------------------------------------------------------

async function registerHealthRoutes(app: FastifyInstance) {
  const DEBUG_HEADER_ALLOWLIST = [
    "x-tenant-id",
    "x-request-id",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-real-ip",
    "host",
    "user-agent",
  ];

  const pickHeaders = (headers: Record<string, string | string[] | undefined>) => {
    const picked: Record<string, string> = {};
    for (const key of DEBUG_HEADER_ALLOWLIST) {
      const value = headers[key];
      if (typeof value === "string") picked[key] = value;
      else if (Array.isArray(value)) picked[key] = value.join(",");
    }
    return picked;
  };

  // Basis-Info / Root
  app.get("/", async () => ({
    ok: true,
    service: "auth-service",
    ts: Date.now(),
  }));

  // OpenAPI Contract (optional per config)
  app.get("/openapi.json", async (_req, reply) => {
    if (!env.OPENAPI_ENABLED) {
      return reply.code(404).send(apiError(404, "NOT_FOUND", "Not found."));
    }

    return reply.send({
      openapi: "3.0.3",
      info: {
        title: "Auth Service API",
        version: "1.0.0",
      },
      components: {
        schemas: {
          ErrorResponse: {
            type: "object",
            properties: {
              status: { type: "integer" },
              error: {
                type: "object",
                properties: {
                  code: { type: "string" },
                  message: { type: "string" },
                },
                required: ["code", "message"],
              },
            },
            required: ["status", "error"],
          },
        },
      },
      paths: {
        "/auth/login": { post: { summary: "Login with email/password" } },
        "/auth/refresh": { post: { summary: "Rotate refresh token" } },
        "/auth/logout": { post: { summary: "Revoke current access token" } },
        "/auth/me": { get: { summary: "Return current access token claims" } },
        "/health/live": { get: { summary: "Liveness" } },
        "/health/ready": { get: { summary: "Readiness" } },
      },
    });
  });

  // Prometheus endpoint (optional per config)
  app.get("/metrics", async (_req, reply) => {
    if (!env.METRICS_ENABLED) {
      return reply.code(404).send(apiError(404, "NOT_FOUND", "Not found."));
    }
    reply.type("text/plain; version=0.0.4; charset=utf-8");
    return reply.send(renderPrometheusMetrics());
  });

  // Liveness-Check – lebt der Prozess?
  app.get("/healthz", async () => ({ status: "alive", pid: process.pid }));
  app.get("/health/live", async () => ({ status: "alive", pid: process.pid }));

  // Zentrales Health-Aggregat – Docker-Healthcheck hängt an /health
  app.get("/health", async (_req, reply) => {
    const services: Record<string, "ok" | "degraded" | "down" | "unknown"> = {
      redis: "unknown",
      db: "unknown",
      smtp: "unknown",
    };

    let overall: "ok" | "degraded" | "down" = isReady ? "ok" : "degraded";

    // Redis
    try {
      const rh = await redisHealth();

      let redisOk = false;
      if ("ok" in rh) redisOk = !!(rh as any).ok;
      else if ("ping" in rh) redisOk = (rh as any).ping === "PONG";

      services.redis = redisOk ? "ok" : "down";
      if (!redisOk) overall = "down";
    } catch (err) {
      services.redis = "down";
      overall = "down";
      app.log.error({ err }, "health_redis_failed");
    }

    // DB
    try {
      const dh = await dbHealth();
      services.db = dh.ok ? "ok" : "down";
      if (!dh.ok) overall = "down";
    } catch (err) {
      services.db = "down";
      overall = "down";
      app.log.error({ err }, "health_db_failed");
    }

    // SMTP / Mailpit
    try {
      const sh = await mailHealth();
      if (sh.ok) services.smtp = "ok";
      else {
        services.smtp = "degraded";
        if (overall === "ok") overall = "degraded";
      }
    } catch (err) {
      services.smtp = "degraded";
      if (overall === "ok") overall = "degraded";
      app.log.warn({ err }, "health_smtp_failed");
    }

    const statusCode = overall === "down" ? 503 : 200;

    return reply.code(statusCode).send({
      status: overall,
      env: env.NODE_ENV ?? process.env.NODE_ENV ?? "development",
      ready: isReady,
      services,
      ts: new Date().toISOString(),
    });
  });

  const handleReady = async (_req: any, reply: any) => {
    if (!isReady) {
      return reply.code(503).send({ status: "starting", ready: false });
    }

    let rh: Awaited<ReturnType<typeof redisHealth>>;
    try {
      rh = await redisHealth();
    } catch {
      rh = { ok: false } as any;
    }

    let healthy = false;
    if ("ok" in (rh as any)) healthy = !!(rh as any).ok;
    else if ("ping" in (rh as any)) healthy = (rh as any).ping === "PONG";

    if (!healthy) {
      return reply.code(503).send({ status: "degraded", redis: rh, ready: false });
    }

    return reply.send({ status: "ready", ready: true });
  };

  // Readiness – für Loadbalancer/K8s
  app.get("/readyz", handleReady);
  app.get("/health/ready", handleReady);

  // Detail-Endpoints
  app.get("/health/redis", async () => await redisHealth());

  app.get("/health/db", async (_req, reply) => {
    try {
      const dh = await dbHealth();
      const statusCode = dh.ok ? 200 : 503;
      return reply.code(statusCode).send({ status: dh.ok ? "ok" : "down", ...dh });
    } catch (err) {
      app.log.error({ err }, "health_db_failed");
      return reply.code(503).send({ status: "down" });
    }
  });

  app.get("/health/smtp", async (_req, reply) => {
    try {
      const sh = await mailHealth();
      return reply.send({ status: sh.ok ? "ok" : "degraded", ...sh });
    } catch (err) {
      app.log.warn({ err }, "health_smtp_failed");
      return reply.code(503).send({ status: "degraded" });
    }
  });

  // Aggregierter Stack-Health unter /health/stack
  app.get("/health/stack", async (_req, reply) => {
    const [redis, db, smtp] = await Promise.allSettled([
      redisHealth(),
      dbHealth(),
      mailHealth(),
    ]);

    const redisRaw: any =
      redis.status === "fulfilled"
        ? redis.value
        : { ok: false, error: "redis_check_failed" as const };

    const dbRes: { ok: boolean; [key: string]: any } =
      db.status === "fulfilled"
        ? (db.value as any)
        : { ok: false, error: "db_check_failed" as const };

    const smtpRes: { ok: boolean; [key: string]: any } =
      smtp.status === "fulfilled"
        ? (smtp.value as any)
        : { ok: false, reason: "smtp_check_failed" as const };

    const redisRes: { ok: boolean; [key: string]: any } =
      "ok" in redisRaw
        ? { ...redisRaw, ok: Boolean(redisRaw.ok) }
        : "ping" in redisRaw
          ? { ...redisRaw, ok: redisRaw.ping === "PONG" }
          : { ...redisRaw, ok: false };

    const stackOk = Boolean(redisRes.ok && dbRes.ok && smtpRes.ok);

    return reply.code(stackOk ? 200 : 503).send({
      status: stackOk ? "ok" : "degraded",
      env: env.NODE_ENV ?? process.env.NODE_ENV ?? "development",
      ready: isReady,
      components: {
        redis: redisRes,
        db: dbRes,
        smtp: smtpRes,
      },
      ts: new Date().toISOString(),
    });
  });

  if (env.ENABLE_DEBUG_HEADERS) {
    app.get("/auth/debug/headers", async (request) => {
      const headers = pickHeaders(request.headers);
      return {
        ok: true,
        service: "auth-service",
        tenant: headers["x-tenant-id"] ?? null,
        headers,
      };
    });
  }
}

// ---------------------------------------------------------------------------
// Haupt-Fabrikfunktion: baut eine Fastify-Instanz
// ---------------------------------------------------------------------------

export async function buildApp(opts: AppOptions = {}): Promise<FastifyInstance> {
  const {
    enableCors = true,
    corsOrigin: corsOriginFromOpts = "*",
    logger = { level: env.LOG_LEVEL ?? "info" },
    ...rest
  } = opts;

  const app = Fastify({
    logger,
    trustProxy: env.TRUST_PROXY,
    requestIdHeader: env.REQUEST_ID_HEADER,
    requestIdLogLabel: "request_id",
    genReqId: () => randomUUID(),
    requestTimeout: 30_000,
    connectionTimeout: 10_000,
    keepAliveTimeout: 65_000,
    ...rest,
  });

  app.addHook("onRequest", async (request, reply) => {
    request.requestStartedAtNs = process.hrtime.bigint();
    reply.header(env.REQUEST_ID_HEADER, request.id);
  });

  app.addHook("onSend", async (_request, reply, payload) => {
    // Baseline Security Headers for auth endpoints.
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    reply.header("X-Frame-Options", "DENY");
    reply.header("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
    reply.header("Content-Security-Policy", "frame-ancestors 'none'");
    return payload;
  });

  app.addHook("onResponse", async (request, reply) => {
    const started = request.requestStartedAtNs;
    if (!started) return;

    const durationNs = process.hrtime.bigint() - started;
    const durationSeconds = Number(durationNs) / 1_000_000_000;
    recordHttpRequest(
      request.method,
      getRouteId(request),
      reply.statusCode,
      durationSeconds,
    );
  });

  // Basis-Plugins (CORS, Rate-Limit, optional Helmet)
  const DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173", // Vite dev
    "http://localhost:3000", // Docker lokal
    "http://192.168.100.10:3000", // Host-Frontend
  ];

  const corsOriginRaw = env.CORS_ORIGIN ?? String(corsOriginFromOpts ?? "");
  const corsAllowlist =
    corsOriginRaw === "*"
      ? DEFAULT_CORS_ORIGINS
      : corsOriginRaw
          .split(",")
          .map((o) => o.trim())
          .filter(Boolean);

  if (enableCors) {
    await app.register(cors as any, {
      origin: (origin: string | undefined, cb: (err: Error | null, ok: boolean) => void) => {
        if (!origin) return cb(null, true);
        const allowed = corsAllowlist.includes(origin);
        return cb(null, allowed);
      },
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
      credentials: true,
      maxAge: 86_400,
    });
  }

  // Für PROD später aktivierbar:
  // await app.register(helmet);

  await app.register(rateLimitPlugin);

  // Redis-Initialisierung (onReady-Hook)
  app.addHook("onReady", async () => {
    try {
      await ensureRedis();
      app.log.info("Redis connection established");
    } catch (err) {
      app.log.error({ err }, "Redis initialization failed");
    }

    isReady = true;
  });

  // Auth-Module (Tenant/Auth/Guard + RLS-/DB-Kontext)
  await registerInternalRoutes(app);
  await registerAuthModules(app);

  // Health & Observability
  await registerHealthRoutes(app);

  // Error-/NotFound-Handler
  app.setErrorHandler((err, req, reply) => {
    req.log.error({ err }, "unhandled_error");
    const errInfo = err as {
      statusCode?: number;
      validation?: unknown;
      message?: string;
      name?: string;
      code?: string;
    };

    if (!errInfo.statusCode && errInfo.code) {
      const mappedDbError = mapDbError(err);
      if (mappedDbError.code !== "INTERNAL") {
        return reply
          .code(mappedDbError.status)
          .type("application/json")
          .send(apiError(mappedDbError.status, mappedDbError.code, mappedDbError.message));
      }
    }

    const status = errInfo.statusCode ?? (errInfo.validation ? 400 : 500);
    const code =
      status === 400
        ? "VALIDATION_FAILED"
        : status === 401
          ? "UNAUTHORIZED"
          : status === 403
            ? "FORBIDDEN"
            : status === 404
              ? "NOT_FOUND"
              : "INTERNAL";
    const message = status === 500 ? "Internal server error." : errInfo.message ?? "Request failed.";

    reply
      .code(status)
      .type("application/json")
      .send(apiError(status, errInfo.code ?? code, message, errInfo.validation));
  });

  app.setNotFoundHandler((req, reply) => {
    reply
      .code(404)
      .send(apiError(404, "NOT_FOUND", `Route ${req.method}:${req.url} not found`));
  });

  // Graceful Shutdown Hooks (werden von server.ts via app.close() getriggert)
  app.addHook("onClose", async () => {
    try {
      await quitRedis();
      app.log.info("Redis connection closed");
    } catch (err) {
      app.log.warn({ err }, "Redis shutdown failed");
    }

    try {
      await closeDb();
      app.log.info("DB pool closed");
    } catch (err) {
      app.log.warn({ err }, "DB shutdown failed");
    }
  });

  // Debug: Routen einmal ausgeben
  app.ready().then(() => {
    app.log.info(app.printRoutes());
  });

  return app;
}
