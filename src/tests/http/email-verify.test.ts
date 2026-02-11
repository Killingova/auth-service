// src/tests/http/email-verify.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;

describe("Email verify routes", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("POST /auth/email/verify/request returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/verify/request",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "not-an-email",
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("GET /auth/email/verify/confirm returns 400 for missing token", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/email/verify/confirm?token=",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("GET /auth/email/verify/health returns 200", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/email/verify/health",
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
