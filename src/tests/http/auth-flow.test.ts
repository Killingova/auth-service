// src/tests/http/auth-flow.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";
import { query } from "../../libs/db.js";
import { hashPassword } from "../../libs/crypto.js";

let app: FastifyInstance;

const TEST_EMAIL = "auth-flow-user@example.test";
const TEST_PASSWORD = "Test1234!";
let tenantId: string;
let userId: string;

describe("Happy path auth flow", () => {
  beforeAll(async () => {
    const [plan] = await query<{ id: string }>(
      `
        SELECT id
        FROM auth.plans
        ORDER BY created_at ASC, id ASC
        LIMIT 1;
      `,
    );

    if (!plan) {
      throw new Error("No auth.plans seed row found for test tenant setup.");
    }

    // DB-Setup: Tenant + User anlegen (idempotent)
    const [tenant] = await query<{ id: string }>(
      `
        INSERT INTO auth.tenants (slug, name, plan_id)
        VALUES ('auth-flow', 'Auth Flow Tenant', $1)
        ON CONFLICT (slug) DO UPDATE
          SET name = EXCLUDED.name,
              plan_id = EXCLUDED.plan_id
        RETURNING id;
      `,
      [plan.id],
    );
    tenantId = tenant.id;

    const passwordHash = await hashPassword(TEST_PASSWORD);

    const [user] = await query<{ id: string }>(
      `
        INSERT INTO auth.users (tenant_id, email, is_active)
        VALUES ($1, $2, true)
        ON CONFLICT (tenant_id, email) DO UPDATE
          SET tenant_id = EXCLUDED.tenant_id,
              is_active = EXCLUDED.is_active
        RETURNING id;
      `,
      [tenantId, TEST_EMAIL],
    );
    userId = user.id;

    await query(
      `
        INSERT INTO auth.credentials (tenant_id, user_id, password_hash, password_changed_at)
        VALUES ($1, $2, $3, now())
        ON CONFLICT (user_id) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            password_changed_at = now();
      `,
      [tenantId, userId, passwordHash],
    );

    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it("can login and call /auth/me", async () => {
    // 1) Login
    const loginRes = await app.inject({
      method: "POST",
      url: "/auth/login",
      headers: {
        "x-tenant-id": tenantId,
      },
      payload: {
        email: TEST_EMAIL,
        password: TEST_PASSWORD,
      },
    });

    expect(loginRes.statusCode).toBe(200);

    const loginBody = loginRes.json() as any;
    expect(typeof loginBody.access_token).toBe("string");
    expect(loginBody.user?.id).toBe(userId);

    const accessToken = loginBody.access_token as string;

    // 2) /auth/me mit Access-Token
    const meRes = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "x-tenant-id": tenantId,
      },
    });

    expect(meRes.statusCode).toBe(200);

    const meBody = meRes.json() as any;
    expect(String(meBody.sub)).toBe(userId);
  });
});
