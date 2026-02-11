// src/tests/http/password.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;

describe("Password routes", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("POST /auth/password/forgot returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/password/forgot",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "not-an-email",
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("POST /auth/password/reset returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/password/reset",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        token: "",
        new_password: "short",
      },
    });

    expect(res.statusCode).toBe(400);
  });

  it("POST /auth/password/change returns 401 when token is missing", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/password/change",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        old_password: "old",
        new_password: "new-password-123",
      },
    });

    expect(res.statusCode).toBe(401);
  });

  it("GET /auth/password/health returns 200", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/password/health",
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
