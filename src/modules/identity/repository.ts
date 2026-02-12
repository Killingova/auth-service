// src/modules/identity/repository.ts
// ============================================================================
// Identity-Repository
// ----------------------------------------------------------------------------
// - Zugriff auf auth.users/auth.credentials, auth.sessions, auth.refresh_tokens
// - RLS-aware: arbeitet nur mit dem pro-Request-DB-Client (DbClient)
// - KEINE Business-Logik, nur Datenzugriff
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import type { RefreshTokenRow, SessionRow, UserRow } from "./types.js";

// ---------------------------------------------------------------------------
// User + Credentials
// ---------------------------------------------------------------------------

export async function findUserByEmail(
  client: DbClient,
  email: string,
): Promise<UserRow | null> {
  const { rows } = await client.query<UserRow>(
    `
      SELECT
        u.id,
        u.tenant_id,
        u.email,
        c.password_hash,
        u.is_active,
        u.verified_at,
        u.created_at,
        u.updated_at,
        p.code AS plan_code,
        COALESCE(array_agg(DISTINCT r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS role_names
      FROM auth.users u
      JOIN auth.credentials c
        ON c.user_id = u.id
       AND c.tenant_id = u.tenant_id
      JOIN auth.tenants t
        ON t.id = u.tenant_id
      LEFT JOIN auth.plans p
        ON p.id = t.plan_id
      LEFT JOIN auth.memberships m
        ON m.tenant_id = u.tenant_id
       AND m.user_id = u.id
      LEFT JOIN auth.roles r
        ON r.id = m.role_id
       AND r.tenant_id = m.tenant_id
      WHERE u.email = $1
      GROUP BY
        u.id,
        u.tenant_id,
        u.email,
        c.password_hash,
        u.is_active,
        u.verified_at,
        u.created_at,
        u.updated_at,
        p.code
      LIMIT 1;
    `,
    [email.toLowerCase()],
  );

  return rows[0] ?? null;
}

export async function findUserAuthContextById(
  client: DbClient,
  opts: {
    tenantId: string;
    userId: string;
  },
): Promise<Pick<UserRow, "plan_code" | "role_names"> | null> {
  const { rows } = await client.query<Pick<UserRow, "plan_code" | "role_names">>(
    `
      SELECT
        p.code AS plan_code,
        COALESCE(array_agg(DISTINCT r.name ORDER BY r.name) FILTER (WHERE r.name IS NOT NULL), ARRAY[]::text[]) AS role_names
      FROM auth.users u
      JOIN auth.tenants t
        ON t.id = u.tenant_id
      LEFT JOIN auth.plans p
        ON p.id = t.plan_id
      LEFT JOIN auth.memberships m
        ON m.tenant_id = u.tenant_id
       AND m.user_id = u.id
      LEFT JOIN auth.roles r
        ON r.id = m.role_id
       AND r.tenant_id = m.tenant_id
      WHERE u.tenant_id = $1
        AND u.id = $2
      GROUP BY p.code
      LIMIT 1;
    `,
    [opts.tenantId, opts.userId],
  );

  return rows[0] ?? null;
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export async function createSession(
  client: DbClient,
  opts: {
    tenantId: string;
    userId: string;
    ttlSec: number;
    sessionId?: string;
  },
): Promise<SessionRow> {
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<SessionRow>(
    `
      INSERT INTO auth.sessions (id, tenant_id, user_id, expires_at)
      VALUES (COALESCE($1::uuid, extensions.gen_random_uuid()), $2, $3, $4)
      RETURNING
        id,
        tenant_id,
        user_id,
        created_at,
        expires_at,
        revoked_at;
    `,
    [opts.sessionId ?? null, opts.tenantId, opts.userId, expires],
  );

  return rows[0];
}

// ---------------------------------------------------------------------------
// Refresh Tokens (hash-only + rotation)
// ---------------------------------------------------------------------------

export async function createRefreshTokenRecord(
  client: DbClient,
  opts: {
    tenantId: string;
    userId: string;
    tokenHash: string;
    ttlSec: number;
    familyId?: string;
  },
): Promise<RefreshTokenRow> {
  const expires = new Date(Date.now() + opts.ttlSec * 1000);

  const { rows } = await client.query<RefreshTokenRow>(
    `
      INSERT INTO auth.refresh_tokens (
        tenant_id,
        user_id,
        token_hash,
        family_id,
        expires_at
      )
      VALUES (
        $1,
        $2,
        $3,
        COALESCE($4::uuid, extensions.gen_random_uuid()),
        $5
      )
      RETURNING
        id,
        tenant_id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at;
    `,
    [opts.tenantId, opts.userId, opts.tokenHash, opts.familyId ?? null, expires],
  );

  return rows[0];
}

export async function findActiveRefreshTokenByHash(
  client: DbClient,
  tokenHash: string,
): Promise<RefreshTokenRow | null> {
  const { rows } = await client.query<RefreshTokenRow>(
    `
      SELECT
        id,
        tenant_id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at
      FROM auth.refresh_tokens
      WHERE token_hash = $1
        AND revoked_at IS NULL
        AND expires_at > now()
      LIMIT 1;
    `,
    [tokenHash],
  );

  return rows[0] ?? null;
}

export async function findRefreshTokenByHash(
  client: DbClient,
  tokenHash: string,
): Promise<RefreshTokenRow | null> {
  const { rows } = await client.query<RefreshTokenRow>(
    `
      SELECT
        id,
        tenant_id,
        user_id,
        token_hash,
        family_id,
        replaced_by,
        revoked_at,
        created_at,
        expires_at
      FROM auth.refresh_tokens
      WHERE token_hash = $1
      LIMIT 1;
    `,
    [tokenHash],
  );

  return rows[0] ?? null;
}

export async function markRefreshTokenRotated(
  client: DbClient,
  opts: {
    tokenId: string;
    replacedById: string;
  },
): Promise<boolean> {
  const res = await client.query(
    `
      UPDATE auth.refresh_tokens
      SET
        revoked_at = now(),
        replaced_by = $2
      WHERE id = $1
        AND revoked_at IS NULL;
    `,
    [opts.tokenId, opts.replacedById],
  );

  return (res.rowCount ?? 0) === 1;
}

export async function deleteRefreshTokenById(
  client: DbClient,
  tokenId: string,
): Promise<void> {
  await client.query(
    `
      DELETE FROM auth.refresh_tokens
      WHERE id = $1;
    `,
    [tokenId],
  );
}

export async function revokeRefreshFamily(
  client: DbClient,
  familyId: string,
): Promise<number> {
  const result = await client.query(
    `
      UPDATE auth.refresh_tokens
      SET revoked_at = now()
      WHERE family_id = $1
        AND revoked_at IS NULL;
    `,
    [familyId],
  );

  return result.rowCount ?? 0;
}

export async function ensureUserHasMembership(
  client: DbClient,
  opts: {
    tenantId: string;
    userId: string;
  },
): Promise<{
  role: string;
  roles: string[];
  plan: string;
}> {
  try {
    const { rows } = await client.query<{
      tenant_id: string;
      role: string;
      plan_code: string;
    }>(
      `
        SELECT
          tenant_id,
          role,
          plan_code
        FROM auth.bootstrap_tenant_for_user($1);
      `,
      [opts.userId],
    );

    const row = rows[0];
    if (!row) {
      throw new Error("membership_bootstrap_failed");
    }

    const roleList = await client.query<{ name: string }>(
      `
        SELECT r.name
        FROM auth.memberships m
        JOIN auth.roles r
          ON r.id = m.role_id
         AND r.tenant_id = m.tenant_id
        WHERE m.tenant_id = $1
          AND m.user_id = $2
        ORDER BY r.name ASC;
      `,
      [opts.tenantId, opts.userId],
    );

    const roles = roleList.rows.length
      ? roleList.rows.map((item) => item.name)
      : [row.role || "member"];

    return {
      role: row.role || roles[0] || "member",
      roles,
      plan: row.plan_code || "free",
    };
  } catch (err: any) {
    // Backward-compatibility, bis DB-Migration 0002 ueberall ausgerollt ist.
    if (err?.code !== "42883") {
      throw err;
    }
  }

  try {
    const { rows } = await client.query<{
      tenant_id: string;
      primary_role: string;
      role_names: string[];
      plan_code: string;
    }>(
      `
        SELECT
          tenant_id,
          primary_role,
          role_names,
          plan_code
        FROM auth.bootstrap_user_auth_context($1, $2, $3);
      `,
      [opts.tenantId, opts.userId, "member"],
    );

    const row = rows[0];
    if (!row) {
      throw new Error("membership_bootstrap_failed");
    }

    const roles = row.role_names?.length ? row.role_names : [row.primary_role || "member"];

    return {
      role: row.primary_role || roles[0] || "member",
      roles,
      plan: row.plan_code || "free",
    };
  } catch (err: any) {
    if (err?.code !== "42883") {
      throw err;
    }
  }

  await client.query("SELECT pg_advisory_xact_lock(hashtext($1));", [opts.userId]);

  const existing = await client.query<{ name: string }>(
    `
      SELECT r.name
      FROM auth.memberships m
      JOIN auth.roles r
        ON r.id = m.role_id
       AND r.tenant_id = m.tenant_id
      WHERE m.tenant_id = $1
        AND m.user_id = $2
      ORDER BY r.name ASC;
    `,
    [opts.tenantId, opts.userId],
  );

  const planResult = await client.query<{ code: string | null }>(
    `
      SELECT p.code
      FROM auth.tenants t
      LEFT JOIN auth.plans p
        ON p.id = t.plan_id
      WHERE t.id = $1
      LIMIT 1;
    `,
    [opts.tenantId],
  );
  const plan = planResult.rows[0]?.code || "free";

  if (existing.rowCount && existing.rowCount > 0) {
    const roles = existing.rows.map((row) => row.name);
    return {
      role: roles[0] ?? "member",
      roles,
      plan,
    };
  }

  const roleInsert = await client.query<{ id: string }>(
    `
      INSERT INTO auth.roles (tenant_id, name)
      VALUES ($1, $2)
      ON CONFLICT (tenant_id, name) DO UPDATE
        SET name = EXCLUDED.name
      RETURNING id;
    `,
    [opts.tenantId, "member"],
  );

  const roleId = roleInsert.rows[0]?.id;
  if (!roleId) {
    throw new Error("role_bootstrap_failed");
  }

  await client.query(
    `
      INSERT INTO auth.memberships (tenant_id, user_id, role_id)
      VALUES ($1, $2, $3)
      ON CONFLICT DO NOTHING;
    `,
    [opts.tenantId, opts.userId, roleId],
  );

  return {
    role: "member",
    roles: ["member"],
    plan,
  };
}
