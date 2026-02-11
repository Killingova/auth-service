// src/tests/http/magic-link.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;

describe("Magic-link routes", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("POST /auth/magic-link/request returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/magic-link/request",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "not-an-email",
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("GET /auth/magic-link/consume returns 400 for missing token", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/magic-link/consume?token=",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("GET /auth/magic-link/health returns 200", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/magic-link/health",
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
