// src/tests/http/otp.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";
import { hashEmailForLog } from "../../libs/pii.js";
import { acquireShortLock, releaseShortLock } from "../../libs/redis.js";

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

  it("POST /auth/otp/request returns 409 when lock is held", async () => {
    const lock = await acquireShortLock({
      tenantId: TENANT_ID,
      scope: "otp_request",
      resource: hashEmailForLog("locked-otp@example.test"),
      ttlMs: 30_000,
    });
    expect(lock.acquired).toBe(true);
    expect(lock.lock).toBeDefined();

    try {
      const res = await app.inject({
        method: "POST",
        url: "/auth/otp/request",
        headers: {
          "x-tenant-id": TENANT_ID,
        },
        payload: {
          email: "locked-otp@example.test",
        },
      });

      expect(res.statusCode).toBe(409);
      const body = res.json() as any;
      expect(body.error).toBe("otp_request_in_progress");
    } finally {
      if (lock.lock) await releaseShortLock(lock.lock);
    }
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
