// src/modules/tenants/repository.ts
// ============================================================================
// Persistence-Layer für Tenant-Management
// ----------------------------------------------------------------------------
// - Direkter SQL-Zugriff auf auth.tenants (über DbClient)
// - KEINE Business-Logik, nur Datenzugriff
// - RLS-aware: im HTTP-Flow immer req.db verwenden
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import type { TenantRow } from "./types.js";

// ---------------------------------------------------------------------------
// Mapping-Helfer
// ---------------------------------------------------------------------------

/**
 * Rohes TenantRow aus DB holen (nach ID).
 */
export async function findTenantById(
  client: DbClient,
  tenantId: string,
): Promise<TenantRow | null> {
  const res = await client.query<TenantRow>(
    `
      SELECT
        id,
        name,
        slug,
        created_at
      FROM auth.tenants
      WHERE id = $1
      LIMIT 1;
    `,
    [tenantId],
  );

  return res.rows[0] ?? null;
}

/**
 * Tenant für einen User ermitteln.
 *
 * - Join auth.users → auth.tenants
 * - RLS:
 *     * Über RLS siehst du nur Tenants, die zum aktuellen Kontext passen.
 *     * Zusätzlich filtert die Query über user_id.
 */
export async function findTenantForUserId(
  client: DbClient,
  userId: string,
): Promise<TenantRow | null> {
  const res = await client.query<TenantRow>(
    `
      SELECT
        t.id,
        t.name,
        t.slug,
        t.created_at
      FROM auth.tenants t
      JOIN auth.users u
        ON u.tenant_id = t.id
      WHERE u.id = $1
      LIMIT 1;
    `,
    [userId],
  );

  return res.rows[0] ?? null;
}

/**
 * Tenants im aktuellen Kontext auflisten.
 *
 * RLS:
 * - Unter app_auth + app.tenant() kann das z. B. nur genau 1 Tenant sein.
 * - Für System-Clients (Owner-Rolle) kann es mehrere Tenants geben.
 */
export async function listTenants(
  client: DbClient,
  limit = 20,
): Promise<TenantRow[]> {
  const res = await client.query<TenantRow>(
    `
      SELECT
        id,
        name,
        slug,
        created_at
      FROM auth.tenants
      ORDER BY created_at ASC
      LIMIT $1;
    `,
    [limit],
  );

  return res.rows;
}
