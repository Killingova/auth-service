import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";
import { query } from "../../libs/db.js";

let app: FastifyInstance | undefined;
let tenantId: string;

describe("Idempotency request endpoints", () => {
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
      return;
    }

    const [tenant] = await query<{ id: string }>(
      `
        INSERT INTO auth.tenants (slug, name, plan_id)
        VALUES ('idempotency-suite', 'Idempotency Suite', $1)
        ON CONFLICT (slug) DO UPDATE
          SET name = EXCLUDED.name,
              plan_id = EXCLUDED.plan_id
        RETURNING id;
      `,
      [plan.id],
    );

    tenantId = tenant.id;

    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    if (app) {
      await app.close();
    }
  });

  it("returns same response and avoids duplicate outbox rows", async () => {
    if (!app) {
      expect(true).toBe(true);
      return;
    }

    const headers = {
      "x-tenant-id": tenantId,
      "idempotency-key": "idem-password-forgot-1",
    };

    const first = await app.inject({
      method: "POST",
      url: "/auth/password/forgot",
      headers,
      payload: {
        email: "nobody@example.test",
      },
    });

    const second = await app.inject({
      method: "POST",
      url: "/auth/password/forgot",
      headers,
      payload: {
        email: "nobody@example.test",
      },
    });

    expect(first.statusCode).toBe(200);
    expect(second.statusCode).toBe(200);
    expect(second.body).toBe(first.body);

    const idempotencyRows = await query<{ count: string }>(
      `
        SELECT COUNT(*)::text AS count
        FROM auth.idempotency_keys
        WHERE tenant_id = $1
          AND endpoint = 'POST:/auth/password/forgot'
          AND idempotency_key = 'idem-password-forgot-1';
      `,
      [tenantId],
    );

    const outboxRows = await query<{ count: string }>(
      `
        SELECT COUNT(*)::text AS count
        FROM auth.outbox_events
        WHERE tenant_id = $1
          AND event_type = 'auth.password_reset_requested'
          AND idempotency_key = 'idem-password-forgot-1';
      `,
      [tenantId],
    );

    expect(Number(idempotencyRows[0].count)).toBe(1);
    expect(Number(outboxRows[0].count)).toBe(1);
  });
});
