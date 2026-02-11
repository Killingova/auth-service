// src/modules/tenants/service.ts
// ============================================================================
// Business-Logik für Tenant-Management
// ----------------------------------------------------------------------------
// UseCases:
// - getCurrentTenantForUser:
//     * Tenant des aktuellen Users ermitteln (RLS-aware)
// - listTenantsForContext:
//     * Tenants im aktuellen Kontext listen (oft nur 1)
// - getTenantsHealth:
//     * einfacher Modul-Healthcheck, nutzt dbHealth()
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { dbHealth } from "../../libs/db.js";

import {
  findTenantForUserId,
  listTenants,
} from "./repository.js";

import type {
  CurrentTenantResult,
  TenantsListResult,
  TenantsHealth,
  PublicTenant,
} from "./types.js";

// ---------------------------------------------------------------------------
// Mapping TenantRow → PublicTenant
// ---------------------------------------------------------------------------

function mapRowToPublicTenant(row: {
  id: string;
  name: string;
  slug: string;
  created_at: Date;
}): PublicTenant {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// UseCase: Tenant des Users ermitteln
// ---------------------------------------------------------------------------

/**
 * Liefert den Tenant des Users im aktuellen RLS-Kontext.
 *
 * - User wird über AccessToken-sub identifiziert (in der Route).
 * - RLS + Join sorgen dafür, dass nur "eigene" Tenants sichtbar sind.
 */
export async function getCurrentTenantForUser(
  db: DbClient,
  userId: string,
): Promise<CurrentTenantResult> {
  const row = await findTenantForUserId(db, userId);
  if (!row) {
    return { tenant: null };
  }

  return {
    tenant: mapRowToPublicTenant(row),
  };
}

// ---------------------------------------------------------------------------
// UseCase: Tenants im Kontext auflisten
// ---------------------------------------------------------------------------

/**
 * Listet Tenants im aktuellen Kontext (typischerweise 1 unter RLS).
 *
 * - Für spätere Admin-/Owner-Views nutzbar (System-Client ohne RLS).
 */
export async function listTenantsForContext(
  db: DbClient,
  limit?: number,
): Promise<TenantsListResult> {
  const lim = limit && limit > 0 ? limit : 20;
  const rows = await listTenants(db, lim);

  const tenants = rows.map(mapRowToPublicTenant);

  return { tenants };
}

// ---------------------------------------------------------------------------
// Modul-Healthcheck für /auth/tenants/health
// ---------------------------------------------------------------------------

export async function getTenantsHealth(): Promise<TenantsHealth> {
  try {
    const { ok, error } = await dbHealth();

    return {
      healthy: ok,
      db: {
        ok,
        error: error ?? null,
      },
    };
  } catch (err: any) {
    return {
      healthy: false,
      db: {
        ok: false,
        error: err?.message ?? "Unknown DB error",
      },
    };
  }
}
