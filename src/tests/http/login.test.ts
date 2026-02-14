// src/tests/http/login.test.ts
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../../app.js";

let app: FastifyInstance;

describe("POST /auth/login", () => {
  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it("returns 400 for invalid payload", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/login",
      payload: {
        email: "not-an-email",
        // password intentionally omitted → should fail Zod validation
      },
    });

    expect(res.statusCode).toBe(400);
  });
});
