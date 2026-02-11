import fp from "fastify-plugin";
import type { FastifyPluginAsync } from "fastify";
import { isHealthPath } from "../libs/http.js";
import { sendApiError } from "../libs/error-response.js";

type AuthzConfig = {
  permission?: string;
  permissions?: string[];
};

function toPermissionSet(request: any): Set<string> {
  const user = request.user ?? {};

  const fromArray =
    Array.isArray(user.permissions) && user.permissions.every((item: unknown) => typeof item === "string")
      ? (user.permissions as string[])
      : Array.isArray(user.perms) && user.perms.every((item: unknown) => typeof item === "string")
        ? (user.perms as string[])
        : [];

  const fromScope =
    typeof user.scope === "string"
      ? user.scope
          .split(/\s+/)
          .map((value: string) => value.trim())
          .filter(Boolean)
      : [];

  return new Set([...fromArray, ...fromScope]);
}

function getRequiredPermissions(request: any): string[] {
  const cfg = (request.routeOptions?.config ?? {}) as AuthzConfig;

  if (typeof cfg.permission === "string" && cfg.permission.trim()) {
    return [cfg.permission.trim()];
  }

  if (Array.isArray(cfg.permissions)) {
    return cfg.permissions
      .map((value) => (typeof value === "string" ? value.trim() : ""))
      .filter(Boolean);
  }

  return [];
}

const authorizationPlugin: FastifyPluginAsync = async (app) => {
  app.addHook("preHandler", async (request, reply) => {
    if (isHealthPath(request)) return;

    const required = getRequiredPermissions(request);
    if (required.length === 0) return;

    if (!request.user) {
      return sendApiError(reply, 401, "INVALID_TOKEN", "Missing auth context.");
    }

    const userPermissions = toPermissionSet(request);
    const missing = required.filter((permission) => !userPermissions.has(permission));

    if (missing.length > 0) {
      return sendApiError(reply, 403, "PERMISSION_DENIED", "Missing required permission.");
    }
  });
};

export default fp(authorizationPlugin, { name: "authorization" });
