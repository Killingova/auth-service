// src/modules/register/repository.ts
// ============================================================================
// Persistence-Layer für Registrierung / Tenant-Anlage / E-Mail-Verify
// ----------------------------------------------------------------------------
// - Direkter SQL-Zugriff auf PostgreSQL über DbClient (libs/db.ts)
// - Nutzt das Schema auth.* (auth.tenants, auth.users, auth.tokens)
// - Keine Business-Logik, nur Datenzugriff
// - Mapping von DB-Row → PublicUser (datensparsam für das API)
// - RLS-aware: im HTTP-Flow immer einen RLS-gebundenen DbClient verwenden
//   (req.db aus tenantDbContextPlugin)
// ============================================================================

import type { DbClient } from "../../libs/db.js";
import { hashOpaqueToken } from "../../libs/crypto.js";
import type {
  TenantRow,
  UserRow,
  TokenRow,
  PublicUser,
} from "./types.js";

// ---------------------------------------------------------------------------
// Hilfsfunktion: einfachen Slug aus Tenant-Namen bauen
// ---------------------------------------------------------------------------

function slugify(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

// ---------------------------------------------------------------------------
// Mapping: DB-Row → PublicUser
// ---------------------------------------------------------------------------

function mapUserRowToPublicUser(row: UserRow): PublicUser {
  return {
    id: row.id,
    email: row.email,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// User lesen
// ---------------------------------------------------------------------------

/**
 * Roh-Zugriff: UserRow anhand der E-Mail aus auth.users laden.
 * Wird z. B. für Existenzprüfungen oder interne Logik genutzt.
 *
 * Hinweis:
 * - client ist der RLS-gebundene DbClient (typisch: req.db).
 */
export async function findUserByEmailRow(
  client: DbClient,
  email: string,
): Promise<UserRow | null> {
  const { rows } = await client.query<UserRow>(
    `
      SELECT
        id,
        tenant_id,
        email,
        is_active,
        verified_at,
        created_at,
        updated_at
      FROM auth.users
      WHERE email = $1
      LIMIT 1;
    `,
    [email.toLowerCase()],
  );

  return rows[0] ?? null;
}

/**
 * Public-Variante: gibt nur PublicUser zurück.
 * Kann z. B. von Services genutzt werden, die keine sensiblen Felder brauchen.
 */
export async function findUserByEmail(
  client: DbClient,
  email: string,
): Promise<PublicUser | null> {
  const row = await findUserByEmailRow(client, email);
  if (!row) return null;
  return mapUserRowToPublicUser(row);
}

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

/**
 * Neuen Tenant in auth.tenants anlegen.
 *
 * Kontext:
 * - Für "Self-Service"-SaaS: typischerweise im Provisioning-Flow (z. B. /register-tenant)
 * - Wird meist mit einem "System-Client" ohne gesetztes app.tenant aufgerufen
 *   (Owner-Rolle oder spezieller Service-User).
 */
export async function createTenant(
  client: DbClient,
  name: string,
): Promise<TenantRow> {
  const slug = slugify(name);

  const { rows } = await client.query<TenantRow>(
    `
      INSERT INTO auth.tenants (name, slug)
      VALUES ($1, $2)
      RETURNING
        id,
        name,
        slug,
        created_at;
    `,
    [name, slug],
  );

  return rows[0];
}

/**
 * Einen bestehenden Tenant holen.
 *
 * RLS-Variante:
 * - Unter RLS+app_auth siehst du nur den aktuellen Tenant.
 * - "erste Zeile" entspricht damit dem Tenant des aktuellen Kontextes.
 *
 * System-Variante:
 * - Wenn ohne RLS (Owner-Client) aufgerufen, entspricht es "erster Tenant im System".
 */
export async function findAnyTenant(
  client: DbClient,
): Promise<TenantRow | null> {
  const { rows } = await client.query<TenantRow>(
    `
      SELECT
        id,
        name,
        slug,
        created_at
      FROM auth.tenants
      ORDER BY created_at ASC
      LIMIT 1;
    `,
  );

  return rows[0] ?? null;
}

// ---------------------------------------------------------------------------
// User anlegen
// ---------------------------------------------------------------------------

/**
 * UserRow anlegen – "low level": gibt die komplette DB-Row zurück.
 *
 * Erwartet:
 * - Einen DbClient im passenden Kontext:
 *   - im HTTP-Flow: RLS-gebunden (req.db, mit gesetztem app.tenant + app_auth)
 *   - für System-Tasks: ggf. Owner-Client (ohne RLS)
 */
export async function createUserRow(opts: {
  client: DbClient;
  email: string;
  isActive?: boolean;
}): Promise<UserRow> {
  const { client, email } = opts;
  const isActive = opts.isActive ?? true;

  const { rows } = await client.query<UserRow>(
    `
      INSERT INTO auth.users (tenant_id, email, is_active)
      VALUES (meta.require_tenant_id(), $1, $2)
      RETURNING
        id,
        tenant_id,
        email,
        is_active,
        verified_at,
        created_at,
        updated_at;
    `,
    [email.toLowerCase(), isActive],
  );

  return rows[0];
}

export async function createCredentialsRow(opts: {
  client: DbClient;
  tenantId: string;
  userId: string;
  passwordHash: string;
}): Promise<void> {
  const { client, tenantId, userId, passwordHash } = opts;
  await client.query(
    `
      INSERT INTO auth.credentials (tenant_id, user_id, password_hash)
      VALUES ($1, $2, $3);
    `,
    [tenantId, userId, passwordHash],
  );
}

/**
 * High-Level-Helfer für den aktuellen Register-UseCase:
 *
 * - Verwendet einen existierenden Tenant (im RLS-Flow: "aktueller Tenant")
 * - Legt den User an
 * - Gibt PublicUser zurück (ohne password_hash etc.)
 *
 * Wird von src/modules/register/service.ts über insertUser() genutzt.
 */
export async function insertUser(
  client: DbClient,
  email: string,
  passwordHash: string,
): Promise<PublicUser> {
  const userRow = await createUserRow({
    client,
    email,
    isActive: true,
  });

  await createCredentialsRow({
    client,
    tenantId: userRow.tenant_id,
    userId: userRow.id,
    passwordHash,
  });

  return mapUserRowToPublicUser(userRow);
}

// ---------------------------------------------------------------------------
// E-Mail-Verifikations-Token
// ---------------------------------------------------------------------------

/**
 * E-Mail-Verifikations-Token in auth.tokens speichern.
 * TTL wird in Sekunden übergeben, expires_at wird daraus berechnet.
 *
 * Achtung: tokens_kind_check erlaubt aktuell nur:
 *   'refresh', 'reset', 'verify'
 * → Für E-Mail-Verify verwenden wir 'verify'.
 *
 * Auch hier: im HTTP-Flow unbedingt einen RLS-gebundenen Client verwenden,
 * damit nur Tokens für den aktuellen Tenant sichtbar/veränderbar sind.
 */
export async function createEmailVerifyTokenRecord(opts: {
  client: DbClient;
  userId: string;
  token: string;
  ttlSec: number;
}): Promise<TokenRow> {
  const { client, userId, token, ttlSec } = opts;

  const tokenHash = hashOpaqueToken(token);
  const expires = new Date(Date.now() + ttlSec * 1000);

  const { rows } = await client.query<TokenRow>(
    `
      INSERT INTO auth.tokens (tenant_id, user_id, type, token_hash, expires_at)
      VALUES (meta.require_tenant_id(), $1, 'verify_email', $2, $3)
      RETURNING
        id,
        tenant_id,
        user_id,
        type,
        token_hash,
        expires_at,
        created_at;
    `,
    [userId, tokenHash, expires],
  );

  return rows[0];
}
