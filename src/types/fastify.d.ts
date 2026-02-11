// src/types/fastify.d.ts
// ============================================================================
// Fastify Type Augmentation
// ----------------------------------------------------------------------------
// Zweck:
// - Request Decorations typisieren:
//   - request.user: verifiziertes JWT (AccessTokenPayload)
//   - request.tenantId: verifizierter Tenant (aus JWT, durch tenant-guard gesetzt)
//   - request.db: PoolClient für RLS-Transaktionen (durch tenant-db-context gesetzt)
// - Route Config typisieren: config.auth / config.tenant
//
// Hinweis:
// - Diese Datei muss vom TS-Compiler gefunden werden (tsconfig include / typeRoots).
// - Sie sollte KEINE Runtime-Imports auslösen (nur Type-Imports).
// ============================================================================

import "fastify";

declare module "fastify" {
  interface FastifyContextConfig {
    /**
     * Wenn true, erzwingen wir:
     * - Authorization Bearer Token (auth.ts)
     * - tenant header vs jwt tenant_id match (tenant-guard.ts)
     * - RLS DB Kontext (tenant-db-context.ts)
     */
    auth?: boolean;

    /**
     * Wenn true, erzwingen wir:
     * - Tenant Header Pflicht (tenant-context.ts)
     * - RLS DB Kontext (tenant-db-context.ts)
     */
    tenant?: boolean;

    /**
     * Optionaler AuthZ-Vertrag:
     * - permission: einzelne Berechtigung
     * - permissions: mehrere Berechtigungen (AND-Logik)
     */
    permission?: string;
    permissions?: string[];
  }

  interface FastifyRequest {
    /**
     * Verifizierter JWT-Payload (nur vorhanden, wenn Route config.auth === true
     * und plugins/auth.ts erfolgreich verifyAccessToken() ausgeführt hat).
     */
    user?: import("../libs/jwt.js").AccessTokenPayload;

    /**
     * Verifizierter Tenant für RLS/DB-Kontext.
     * Quelle: JWT tenant_id (nicht raw header!)
     * Wird im tenant-guard.ts gesetzt, nachdem Header vs JWT gematcht hat.
     */
    tenantId?: string;
    requestedTenantId?: string;

    /**
     * Per-Request DB Client (PoolClient) für Transaktion + RLS-Kontext.
     * Wird im tenant-db-context.ts gesetzt und am Ende wieder released.
     */
    db?: import("../libs/db.js").DbClient;

    /**
     * Interner Transaktionszustand (nur für tenant-db-context.ts).
     * Optional typisiert, damit TS bei request._txState nicht meckert.
     */
    _txState?: {
      client?: import("../libs/db.js").DbClient;
      inTx: boolean;
      finalized: boolean;
    };

    requestStartedAtNs?: bigint;
  }

  interface RouteConfig {
    auth?: boolean;
    tenant?: boolean;
    permission?: string;
    permissions?: string[];
  }
}
