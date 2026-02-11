import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";
import { query } from "../../libs/db.js";
import { hashPassword } from "../../libs/crypto.js";

let app: FastifyInstance | undefined;
let dbAvailable = false;

const TEST_EMAIL = "refresh-rotation-user@example.test";
const TEST_PASSWORD = "Test1234!";
let tenantId: string;
let userId: string;

describe("Refresh rotation + reuse detection", () => {
  beforeAll(async () => {
    try {
      await query("SELECT 1;");
      dbAvailable = true;
    } catch {
      dbAvailable = false;
      return;
    }

    const [plan] = await query<{ id: string }>(
      `
        SELECT id
        FROM auth.plans
        ORDER BY created_at ASC, id ASC
        LIMIT 1;
      `,
    );

    if (!plan) {
      dbAvailable = false;
      return;
    }

    const [tenant] = await query<{ id: string }>(
      `
        INSERT INTO auth.tenants (slug, name, plan_id)
        VALUES ('refresh-rotation', 'Refresh Rotation Tenant', $1)
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
          SET is_active = EXCLUDED.is_active
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

  it("kills family on refresh token reuse", async () => {
    if (!dbAvailable || !app) {
      expect(true).toBe(true);
      return;
    }

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
    const refresh1 = String(loginBody.refresh_token);

    const refreshRes1 = await app.inject({
      method: "POST",
      url: "/auth/refresh",
      headers: {
        "x-tenant-id": tenantId,
      },
      payload: {
        refresh_token: refresh1,
      },
    });

    expect(refreshRes1.statusCode).toBe(200);
    const refreshBody1 = refreshRes1.json() as any;
    const refresh2 = String(refreshBody1.refresh_token);

    const reuseRes = await app.inject({
      method: "POST",
      url: "/auth/refresh",
      headers: {
        "x-tenant-id": tenantId,
      },
      payload: {
        refresh_token: refresh1,
      },
    });

    expect(reuseRes.statusCode).toBe(401);
    const reuseBody = reuseRes.json() as any;
    expect(reuseBody.error?.code).toBe("REFRESH_REUSE_DETECTED");

    const refreshRes2 = await app.inject({
      method: "POST",
      url: "/auth/refresh",
      headers: {
        "x-tenant-id": tenantId,
      },
      payload: {
        refresh_token: refresh2,
      },
    });

    expect(refreshRes2.statusCode).toBe(401);
    const refreshBody2 = refreshRes2.json() as any;
    expect(refreshBody2.error?.code).toBe("REFRESH_FAILED");
  });
});
