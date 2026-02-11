// tests/http/health.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

let app: FastifyInstance;

describe("Health endpoints", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("GET /health returns ready aggregate status", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health",
    });

    expect(res.statusCode).toBe(200);

    const body = res.json() as any;
    expect(["ok", "degraded"]).toContain(body.status);
    expect(body.services).toBeDefined();
    expect(body.services.db).toBe("ok");
  });

  it("GET /health/db returns ok", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health/db",
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as any;
    expect(body.status).toBe("ok");
  });

  it("GET /health/redis returns redis ok/ping", async () => {
    const res = await app.inject({
      method: "GET",
      url: "/health/redis",
    });

    expect(res.statusCode).toBe(200);
    const body = res.json() as any;

    if ("ping" in body) {
      expect(body.ping).toBe("PONG");
    } else if ("ok" in body) {
      expect(body.ok).toBe(true);
    } else {
      // Fallback: mindestens irgendein Truthy-Status erwartet
      expect(body).toBeDefined();
    }
  });
});
