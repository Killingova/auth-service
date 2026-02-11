// src/modules/tenants/types.ts
// ============================================================================
// Typen für Tenant-Management
// ----------------------------------------------------------------------------
// - Intern: TenantRow (DB-Level, auth.tenants)
// - Extern: PublicTenant für API-Responses
// - Health-Typen für /auth/tenants/health
// ============================================================================

// ---------------------------------------------------------------------------
// DB-Row-Typ (direkt aus auth.tenants)
// ---------------------------------------------------------------------------

export interface TenantRow {
  id: string;
  name: string;
  slug: string;
  created_at: Date;
}

// ---------------------------------------------------------------------------
// Öffentliche Typen (DTOs für Services / Routes)
// ---------------------------------------------------------------------------

/**
 * Öffentliche Sicht auf einen Tenant.
 * Achtung: hier KEINE sensiblen/technischen Felder (z. B. interne Flags).
 */
export interface PublicTenant {
  id: string;
  name: string;
  slug: string;
  createdAt: Date;
}

/**
 * Ergebnis von getCurrentTenantForUser().
 */
export interface CurrentTenantResult {
  tenant: PublicTenant | null;
}

/**
 * Ergebnis von listTenantsForContext().
 */
export interface TenantsListResult {
  tenants: PublicTenant[];
}

// ---------------------------------------------------------------------------
// Modul-spezifischer Healthcheck für /auth/tenants/health
// ---------------------------------------------------------------------------

export interface TenantsHealth {
  healthy: boolean;
  db: {
    ok: boolean;
    error?: string | null;
  };
}
