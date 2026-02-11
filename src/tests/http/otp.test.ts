// src/tests/http/otp.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;

describe("OTP routes", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("POST /auth/otp/request returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/otp/request",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "not-an-email",
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("POST /auth/otp/verify returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/otp/verify",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "not-an-email",
        // code missing on purpose
      } as any,
    });

    expect(res.statusCode).toBe(400);
  });

  it("GET /auth/otp/health returns 200", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/otp/health",
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
