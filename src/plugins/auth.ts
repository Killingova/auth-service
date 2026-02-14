// src/plugins/auth.ts
// ============================================================================
// Auth-Plugin (Fastify)
// ----------------------------------------------------------------------------
// Verantwortung (Single Responsibility):
// - Für Routes mit config.auth === true:
//   - Bearer Token extrahieren
//   - Access Token verifizieren (inkl. Claims-Pflichten, z.B. tenant_id)
//   - req.user setzen (Auth-Context)
// - Health/System-Pfade bleiben immer ohne Auth möglich
//
// Nicht in diesem Plugin:
// - Tenant Header vs JWT Match (macht tenant-guard.ts)
// - DB/RLS Context (macht tenant-db-context.ts)
// ============================================================================

import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import { isHealthPath } from "../libs/http.js";
import { verifyAccessToken, type AccessTokenPayload } from "../libs/jwt.js";
import { blacklistHas } from "../libs/redis.js";
import { sendApiError } from "../libs/error-response.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function getRouteNeedsAuth(req: any): boolean {
  // Route config ist pro Handler setzbar (du nutzt das bereits)
  return (req.routeOptions?.config as any)?.auth === true;
}

function extractBearerToken(authHeader: unknown): string | null {
  // Fastify Header kann string|string[]|undefined sein
  const raw =
    typeof authHeader === "string"
      ? authHeader
      : Array.isArray(authHeader)
        ? authHeader[0]
        : undefined;

  if (!raw) return null;

  // toleriert: "Bearer <token>", "bearer <token>", extra spaces
  const m = raw.match(/^\s*Bearer\s+(.+)\s*$/i);
  const token = m?.[1]?.trim();
  return token && token.length > 0 ? token : null;
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

const authPlugin: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", async (req, reply) => {
    // 1) Health niemals blockieren
    if (isHealthPath(req)) return;

    // 2) Nur Routen mit auth=true absichern
    if (!getRouteNeedsAuth(req)) return;

    // 3) Token aus Authorization Header
    const token = extractBearerToken(req.headers.authorization);

    if (!token) {
      // Standardkonform: WWW-Authenticate setzen (ohne Details)
      reply.header("WWW-Authenticate", 'Bearer realm="auth-service"');
      return sendApiError(reply, 401, "MISSING_TOKEN", "Missing bearer token.");
    }

    try {
      // verifyAccessToken erzwingt:
      // - typ=access
      // - sub, jti vorhanden
      // - tenant_id optional (global user Modell)
      const payload = await verifyAccessToken(token);

      // req.user wird von tenant-guard.ts und Routes genutzt
      // (Type Augmentation sollte das in types/fastify.d.ts deklarieren)
      if (await blacklistHas(String(payload.jti))) {
        reply.header("WWW-Authenticate", 'Bearer error="invalid_token"');
        return sendApiError(reply, 401, "TOKEN_REVOKED", "Token has been revoked.");
      }

      req.user = payload as AccessTokenPayload;
    } catch (_err) {
      // Keine internen Fehler nach außen leaken
      reply.header("WWW-Authenticate", 'Bearer error="invalid_token"');
      return sendApiError(reply, 401, "INVALID_TOKEN", "Invalid bearer token.");
    }
  });
};

export default fp(authPlugin, { name: "auth" });
