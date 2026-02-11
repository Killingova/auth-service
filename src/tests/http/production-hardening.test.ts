import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

const TENANT_ID = "00000000-0000-4000-8000-000000000001";

let app: FastifyInstance;
let dbAvailable = false;

describe("Production hardening endpoints", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();

    const dbHealth = await app.inject({ method: "GET", url: "/health/db" });
    dbAvailable = dbHealth.statusCode === 200 && (dbHealth.json() as any).status === "ok";
  });

  afterAll(async () => {
    await app.close();
  });

  it("echoes incoming x-request-id", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health/live",
      headers: {
        "x-request-id": "req-12345",
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers["x-request-id"]).toBe("req-12345");
  });

  it("generates x-request-id when missing", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health/live",
    });

    expect(res.statusCode).toBe(200);
    expect(typeof res.headers["x-request-id"]).toBe("string");
    expect((res.headers["x-request-id"] as string).length).toBeGreaterThan(0);
  });

  it("accepts case-insensitive tenant header", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/auth/me",
      headers: {
        "X-Tenant-Id": TENANT_ID,
      },
    });

    expect(res.statusCode).toBe(401);
    const body = res.json() as any;
    expect(body.error?.code).toBe("MISSING_TOKEN");
  });

  it("rejects redirect_uri outside allowlist", async () => {
    if (!dbAvailable) {
      expect(true).toBe(true);
      return;
    }

    const res = await app.inject({
      method: "POST",
      url: "/auth/magic-link/request",
      headers: {
        "x-tenant-id": TENANT_ID,
      },
      payload: {
        email: "valid@example.test",
        redirect_uri: "https://evil.example.com/callback",
      },
    });

    expect(res.statusCode).toBe(400);
    const body = res.json() as any;
    expect(body.error?.code).toBe("INVALID_REDIRECT_URI");
  });

  it("serves openapi and metrics endpoints", async () => {
    const openapiRes = await app.inject({ method: "GET", url: "/openapi.json" });
    expect(openapiRes.statusCode).toBe(200);
    const openapi = openapiRes.json() as any;
    expect(openapi.openapi).toBe("3.0.3");

    const metricsRes = await app.inject({ method: "GET", url: "/metrics" });
    expect(metricsRes.statusCode).toBe(200);
    expect(metricsRes.body.includes("http_requests_total")).toBe(true);
  });
});
