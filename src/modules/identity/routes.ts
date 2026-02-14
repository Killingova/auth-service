// src/modules/identity/routes.ts
// ============================================================================
// Identity-Routen (RLS-aware)
// ----------------------------------------------------------------------------
// Endpoints (relativ zum Prefix /auth):
// - POST   /login    (tenant=false, auth=false, db=true)  -> DB/RLS, kein JWT
// - POST   /refresh  (tenant=false, auth=false, db=true)  -> DB/RLS, kein JWT (opaque refresh)
// - GET    /me       (tenant=false, auth=true)            -> JWT + blacklist (global)
// - POST   /logout   (tenant=false, auth=true, db=true)   -> JWT + revoke refresh family
// - POST   /logout/all (tenant=false, auth=true, db=true) -> JWT + revoke alle refresh token families
//
// Security / Tenant:
// - Tenant-Header ist Pflicht für tenant=true (Gateway setzt X-Tenant-Id).
// - tenant_id Claim ist optional (global user Modell).
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import {
  blacklistAdd,
  blacklistHas,
  clearLoginFailures,
  getLoginFailureState,
  getJSON,
  registerLoginFailure,
  setJSON,
  streamAdd,
} from "../../libs/redis.js";
import type { DbClient } from "../../libs/db.js";
import { env } from "../../libs/env.js";
import { sendApiError } from "../../libs/error-response.js";
import { hashEmailForLog, hashIpForLog } from "../../libs/pii.js";
import {
  recordAuthLogin,
  recordAuthRefreshReuseDetected,
  recordAuthRefreshSuccess,
} from "../../libs/metrics.js";
import {
  LoginFailedError,
  loginWithEmailPassword,
  refreshWithToken,
  RefreshFailedError,
  RefreshReuseDetectedError,
} from "./service.js";
import type { AccessTokenPayload } from "../../libs/jwt.js";
import {
  revokeAllRefreshTokensForUser,
  revokeAllSessionsForUser,
  revokeRefreshFamily,
  revokeSessionByIdForUser,
} from "./repository.js";

// ---------------------------------------------------------------------------
// Zod Schemas
// ---------------------------------------------------------------------------

const LoginBodySchema = z.object({
  email: z.string().email("Bitte eine gültige E-Mail-Adresse angeben."),
  password: z.string().min(1, "Passwort ist Pflicht."),
});

type LoginBody = z.infer<typeof LoginBodySchema>;

const RefreshBodySchema = z.object({
  refresh_token: z.string().min(1, "refresh_token ist Pflicht."),
});

type RefreshBody = z.infer<typeof RefreshBodySchema>;

const LOGIN_FAILURE_DELAY_MIN_MS = 200;
const LOGIN_FAILURE_DELAY_MAX_MS = 400;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function requireDb(app: FastifyInstance, req: any, reply: any): DbClient | null {
  const db = req.db as DbClient | undefined;
  if (!db) {
    app.log.error({ route: req.url }, "missing_db_context");
    sendApiError(
      reply,
      500,
      "INTERNAL",
      "Database context not available for this request.",
    );
    return null;
  }
  return db;
}

async function applyLoginFailureDelay(): Promise<void> {
  const jitter = Math.floor(
    Math.random() * (LOGIN_FAILURE_DELAY_MAX_MS - LOGIN_FAILURE_DELAY_MIN_MS + 1),
  );
  const total = LOGIN_FAILURE_DELAY_MIN_MS + jitter;
  await new Promise((resolve) => setTimeout(resolve, total));
}

export default async function identityRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // POST /auth/login  (tenant optional, no JWT)
  // -------------------------------------------------------------------------
  app.post<{ Body: LoginBody }>(
    "/login",
    {
      config: { tenant: false, auth: false, db: true },
      preValidation: async (req, reply) => {
        const parsed = LoginBodySchema.safeParse(req.body);
        if (!parsed.success) {
          return sendApiError(
            reply,
            400,
            "VALIDATION_FAILED",
            "Invalid login payload.",
            parsed.error.flatten(),
          );
        }
        req.body = parsed.data as LoginBody;
      },
    },
    async (req, reply) => {
      const db = requireDb(app, req, reply);
      if (!db) return;

      const { email, password } = req.body as LoginBody;
      const emailHash = hashEmailForLog(email);
      const ipHash = hashIpForLog(req.ip || "unknown");
      const requestedTenantId = (req as any).requestedTenantId as string | undefined;

      try {
        if (requestedTenantId) {
          const lockState = await getLoginFailureState(
            emailHash,
            ipHash,
            env.LOGIN_SOFT_LOCK_MAX_ATTEMPTS,
            requestedTenantId,
          );
          if (lockState.locked) {
            recordAuthLogin(false);
            await applyLoginFailureDelay();
            return sendApiError(
              reply,
              401,
              "LOGIN_FAILED",
              "Invalid credentials.",
            );
          }
        }
      } catch (err) {
        app.log.warn({ err }, "login_soft_lock_check_failed");
      }

      try {
        const result = await loginWithEmailPassword(db, {
          email,
          password,
          requestedTenantId,
          ip: req.ip,
          ua: req.headers["user-agent"],
        });

        const resolvedTenantId = result.user.tenantId;

        try {
          await clearLoginFailures(emailHash, ipHash, resolvedTenantId);
        } catch (err) {
          app.log.warn({ err }, "login_soft_lock_clear_failed");
        }

        recordAuthLogin(true);

        // Kurzzeit-Cache (keine sensiblen Daten)
        try {
          await setJSON(
            `cache:user:${result.user.id}`,
            { id: result.user.id, email: result.user.email },
            300,
            undefined,
          );
        } catch (cacheErr) {
          app.log.warn({ err: cacheErr }, "login_success_cache_failed");
        }

        try {
          await streamAdd(
            "auth-events",
            {
              type: "auth.login_success",
              sub: result.user.id,
            },
            undefined,
          );
        } catch (streamErr) {
          app.log.warn({ err: streamErr }, "login_success_stream_failed");
        }

        return reply.send({
          access_token: result.accessToken,
          access_expires_at: result.accessTokenExpiresAt,
          refresh_token: result.refreshToken,
          refresh_expires_at: result.refreshTokenExpiresAt,
          session_id: result.sessionId,
          token_type: "bearer",
          user: result.user,
        });
      } catch (err) {
        if (err instanceof LoginFailedError) {
          // Keine Details nach außen
          app.log.warn({ err, route: "/auth/login", email_hash: emailHash }, "login_failed");
          recordAuthLogin(false);
          try {
            if (requestedTenantId) {
              const state = await registerLoginFailure(
                emailHash,
                ipHash,
                env.LOGIN_SOFT_LOCK_WINDOW_SEC,
                env.LOGIN_SOFT_LOCK_MAX_ATTEMPTS,
                requestedTenantId,
              );
              await streamAdd(
                "auth-events",
                {
                  type: "auth.login_failed",
                  email_hash: emailHash,
                  ip_hash: ipHash,
                  attempts: state.count,
                },
                requestedTenantId,
              );
            }
          } catch (lockErr) {
            app.log.warn({ err: lockErr }, "login_soft_lock_increment_failed");
          }

          await applyLoginFailureDelay();
          return sendApiError(
            reply,
            401,
            "LOGIN_FAILED",
            "Invalid credentials.",
          );
        }

        app.log.error({ err, route: "/auth/login", email_hash: emailHash }, "login_internal_failed");
        return sendApiError(
          reply,
          500,
          "INTERNAL",
          "Login temporarily unavailable.",
        );
      }
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/refresh  (tenant required, no JWT; opaque refresh token)
  // -------------------------------------------------------------------------
  app.post<{ Body: RefreshBody }>(
    "/refresh",
    { config: { tenant: false, auth: false, db: true } },
    async (req, reply) => {
      const parsed = RefreshBodySchema.safeParse(req.body);
      if (!parsed.success) {
        return sendApiError(
          reply,
          400,
          "VALIDATION_FAILED",
          "Invalid refresh payload.",
          parsed.error.flatten(),
        );
      }

      const db = requireDb(app, req, reply);
      if (!db) return;
      const requestedTenantId = (req as any).requestedTenantId as string | undefined;

      try {
        const result = await refreshWithToken(db, {
          refreshToken: parsed.data.refresh_token,
          requestedTenantId,
          ip: req.ip,
          ua: req.headers["user-agent"],
        });

        recordAuthRefreshSuccess();
        try {
          await streamAdd("auth-events", {
            type: "auth.refresh_success",
          }, requestedTenantId);
        } catch (streamErr) {
          app.log.warn({ err: streamErr }, "refresh_success_stream_failed");
        }

        return reply.send({
          access_token: result.accessToken,
          access_expires_at: result.accessTokenExpiresAt,
          refresh_token: result.refreshToken,
          refresh_expires_at: result.refreshTokenExpiresAt,
          token_type: "bearer",
        });
      } catch (err) {
        app.log.warn({ err, route: "/auth/refresh" }, "refresh_failed");
        if (err instanceof RefreshReuseDetectedError) {
          recordAuthRefreshReuseDetected();
          try {
            await streamAdd("auth-events", { type: "auth.refresh_reuse_detected" }, requestedTenantId);
            await streamAdd("auth-events", { type: "auth.refresh_family_revoked" }, requestedTenantId);
          } catch (streamErr) {
            app.log.warn({ err: streamErr }, "refresh_reuse_stream_failed");
          }
          return sendApiError(
            reply,
            401,
            "REFRESH_REUSE_DETECTED",
            "Refresh token reuse detected.",
          );
        }

        if (err instanceof RefreshFailedError) {
          return sendApiError(
            reply,
            401,
            "REFRESH_FAILED",
            "Invalid refresh token.",
          );
        }

        return sendApiError(reply, 401, "REFRESH_FAILED", "Invalid refresh token.");
      }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/me  (JWT required; DB-frei)
  // -------------------------------------------------------------------------
  app.get(
    "/me",
    { config: { tenant: false, auth: true } },
    async (req, reply) => {
      const user = req.user as AccessTokenPayload | undefined;
      if (!user) {
        return sendApiError(reply, 401, "INVALID_TOKEN", "Missing auth context.");
      }

      const jti = String(user.jti);

      if (await blacklistHas(jti)) {
        return sendApiError(reply, 401, "TOKEN_REVOKED", "Token has been revoked.");
      }

      const cached = await getJSON<{ id: string; email: string }>(
        `cache:user:${user.sub}`,
        undefined,
      );

      return reply.send({
        sub: user.sub,
        tenant_id: user.tenant_id,
        cached,
        claims: {
          jti,
          sid: user.sid,
          ver: user.ver ?? 1,
          role: user.role,
          roles: user.roles ?? [],
          plan: user.plan,
          scope: user.scope,
          exp: user.exp,
          iat: user.iat,
        },
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/logout  (JWT required; DB-frei)
  // -------------------------------------------------------------------------
  app.post(
    "/logout",
    { config: { tenant: false, auth: true, db: true } },
    async (req, reply) => {
      const user = req.user as AccessTokenPayload | undefined;
      if (!user) {
        return sendApiError(reply, 401, "INVALID_TOKEN", "Missing auth context.");
      }

      const exp = Number(user.exp ?? 0);
      const now = Math.floor(Date.now() / 1000);
      const ttl = Math.max(1, exp - now);

      const db = requireDb(app, req, reply);
      if (!db) return;

      await blacklistAdd(String(user.jti), ttl);

      // Best effort: revoke refresh family + session by sid (falls vorhanden).
      const familyId = typeof user.sid === "string" ? user.sid : undefined;
      if (familyId) {
        try {
          await revokeRefreshFamily(db, familyId);
        } catch (err) {
          app.log.warn({ err }, "logout_revoke_refresh_family_failed");
        }
        try {
          await revokeSessionByIdForUser(db, { sessionId: familyId, userId: String(user.sub) });
        } catch (err) {
          app.log.warn({ err }, "logout_revoke_session_failed");
        }
      }

      try {
        await streamAdd("auth-events", {
          type: "auth.logout",
          sub: String(user.sub),
        });
      } catch (streamErr) {
        app.log.warn({ err: streamErr }, "logout_stream_failed");
      }

      return reply.code(204).send();
    },
  );

  // -------------------------------------------------------------------------
  // POST /auth/logout/all  (JWT required; revoke all sessions/refresh tokens)
  // -------------------------------------------------------------------------
  app.post(
    "/logout/all",
    { config: { tenant: false, auth: true, db: true } },
    async (req, reply) => {
      const user = req.user as AccessTokenPayload | undefined;
      if (!user) {
        return sendApiError(reply, 401, "INVALID_TOKEN", "Missing auth context.");
      }

      const exp = Number(user.exp ?? 0);
      const now = Math.floor(Date.now() / 1000);
      const ttl = Math.max(1, exp - now);

      const db = requireDb(app, req, reply);
      if (!db) return;

      await blacklistAdd(String(user.jti), ttl);

      try {
        await revokeAllRefreshTokensForUser(db, String(user.sub));
      } catch (err) {
        app.log.warn({ err }, "logout_all_revoke_refresh_failed");
      }
      try {
        await revokeAllSessionsForUser(db, String(user.sub));
      } catch (err) {
        app.log.warn({ err }, "logout_all_revoke_sessions_failed");
      }

      try {
        await streamAdd("auth-events", {
          type: "auth.logout_all",
          sub: String(user.sub),
        });
      } catch (streamErr) {
        app.log.warn({ err: streamErr }, "logout_all_stream_failed");
      }

      return reply.code(204).send();
    },
  );
}
