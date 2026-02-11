// src/tests/http/sessions.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;

describe("Sessions routes", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("GET /auth/sessions returns 401 when token is missing", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/sessions?limit=10",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
    });

    expect(res.statusCode).toBe(401);
  });

  it("POST /auth/sessions/revoke returns 401 when token is missing", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/sessions/revoke",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        session_id: "dummy-session-id",
      },
    });

    expect(res.statusCode).toBe(401);
  });

  it("GET /auth/sessions/health returns 200", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/sessions/health",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as any;
    expect(body.healthy).toBe(true);
    expect(body.db?.ok).toBe(true);
  });
});
