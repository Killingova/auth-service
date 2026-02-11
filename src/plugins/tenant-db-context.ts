// src/plugins/tenant-db-context.ts
// ============================================================================
// Tenant- / RLS-DB-Context (Fastify)
// ----------------------------------------------------------------------------
// Verantwortung:
// - pro Request einen dedizierten DB-Client aus dem Pool holen
// - pro Request eine Transaktion öffnen (BEGIN)
// - RLS-Kontext setzen (SET LOCAL / set_config):
//     SELECT set_config('app.tenant', $1, true);
//     SET LOCAL ROLE app_auth;
// - am Ende:
//   - COMMIT bei Erfolg (onResponse)
//   - ROLLBACK bei Fehler (onError)
//   - Client immer freigeben (release), exakt einmal
//
// Sicherheitsprinzip:
// - Bei auth=true kommt Tenant ausschließlich aus request.tenantId
//   (gesetzt durch tenant-guard.ts via JWT tenant_id).
// - Bei auth=false/tenant=true kommt Tenant aus request.requestedTenantId
//   (validierter Header via tenant-context.ts).
//
// Hinweise:
// - Dieses Plugin wird sinnvollerweise nur in dem Scope registriert,
//   in dem auch tenant/auth routes liegen (machst du bereits).
// ============================================================================

import fp from "fastify-plugin";
import type { FastifyInstance, FastifyPluginAsync } from "fastify";
import { pool, type DbClient } from "../libs/db.js";
import { isHealthPath } from "../libs/http.js";
import { sendApiError } from "../libs/error-response.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function needsDbTenantTx(req: any): boolean {
  const cfg = req.routeOptions?.config as any;
  return cfg?.tenant === true || cfg?.auth === true;
}

function getTenantForDb(req: any): string | undefined {
  const cfg = req.routeOptions?.config as any;
  if (cfg?.auth === true) {
    return req.tenantId as string | undefined;
  }
  if (cfg?.tenant === true) {
    return (req as any).requestedTenantId as string | undefined;
  }
  return undefined;
}

function getUserIdForDb(req: any): string | undefined {
  const cfg = req.routeOptions?.config as any;
  if (cfg?.auth !== true) return undefined;
  return req.user?.sub ? String(req.user.sub) : undefined;
}

type TxState = {
  client?: DbClient;
  inTx: boolean;
  finalized: boolean; // verhindert double commit/rollback/release
};

function ensureTxState(request: any): TxState {
  if (!request._txState) {
    request._txState = { inTx: false, finalized: false } satisfies TxState;
  }
  return request._txState as TxState;
}

async function finalizeTx(
  app: FastifyInstance,
  request: any,
  mode: "commit" | "rollback",
) {
  const s = ensureTxState(request);

  if (s.finalized) return;
  s.finalized = true;

  const client = s.client;
  s.client = undefined;

  if (!client) return;

  try {
    if (s.inTx) {
      await client.query(mode === "commit" ? "COMMIT" : "ROLLBACK");
    }
  } catch (err) {
    // Nur loggen – wir sind bereits im Response/Fehlerpfad
    app.log.error({ err, mode }, "db_tx_finalize_failed");
  } finally {
    try {
      client.release();
    } catch (err) {
      app.log.error({ err }, "db_client_release_failed");
    }
    request.db = undefined;
    s.inTx = false;
  }
}

// ---------------------------------------------------------------------------
// Plugin
// ---------------------------------------------------------------------------

const tenantDbContextPlugin: FastifyPluginAsync = async (app: FastifyInstance) => {
  // 1) Setup vor Handler (BEGIN + RLS)
  app.addHook("preHandler", async (request, reply) => {
    if (isHealthPath(request)) return;

    // Optional, aber empfehlenswert:
    // Nur dort DB-TX öffnen, wo Tenant/Auth wirklich verlangt wird.
    if (!needsDbTenantTx(request)) return;

    const tenantId = getTenantForDb(request);
    const userId = getUserIdForDb(request);

    if (!tenantId) {
      return sendApiError(
        reply,
        400,
        "VALIDATION_FAILED",
        "Tenant context not set.",
      );
    }

    const s = ensureTxState(request);

    const client = await pool.connect();
    s.client = client;
    request.db = client;

    try {
      await client.query("BEGIN");
      s.inTx = true;

      // Tenant in GUC setzen (transaction-local)
      await client.query("SELECT set_config('app.tenant', $1, true);", [tenantId]);

      // Optional: User in GUC setzen, wenn authentifiziert.
      if (userId) {
        await client.query("SELECT set_config('app.user_id', $1, true);", [userId]);
      }

      // Rolle für RLS (setzt Permissions innerhalb der TX)
      await client.query("SET LOCAL ROLE app_auth;");
    } catch (err) {
      // Cleanup sofort, sonst Leak
      await finalizeTx(app, request, "rollback");
      throw err;
    }
  });

  // 2) Erfolgspfad: Commit nach Response (robuster als onSend)
  app.addHook("onResponse", async (request) => {
    await finalizeTx(app, request, "commit");
  });

  // 3) Fehlerpfad: Rollback
  app.addHook("onError", async (request, _reply, _error) => {
    await finalizeTx(app, request, "rollback");
  });
};

export default fp(tenantDbContextPlugin, {
  name: "tenant-db-context",
  // Wenn du fastify-plugin dependencies aktiv nutzt:
  // dependencies: ["tenant-guard"],
});
