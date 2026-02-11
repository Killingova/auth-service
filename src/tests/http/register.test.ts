// src/tests/http/register.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;

describe("Register routes", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("POST /auth/register returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/register",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "not-an-email",
        // password missing on purpose
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("GET /auth/register/health returns 200", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/register/health",
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
