import { describe, expect, it } from "vitest";
import { SignJWT } from "jose";
import { env } from "../../libs/env.js";
import { verifyAccessToken } from "../../libs/jwt.js";

const encoder = new TextEncoder();

describe("JWT clock skew", () => {
  it("accepts token slightly in the future within tolerance", async () => {
    const secret = encoder.encode(env.JWT_SECRET_ACTIVE ?? env.JWT_SECRET ?? "test-secret");

    const token = await new SignJWT({
      typ: "access",
      tenant_id: "00000000-0000-4000-8000-000000000001",
      tid: "00000000-0000-4000-8000-000000000001",
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("00000000-0000-4000-8000-000000000002")
      .setJti("00000000-0000-4000-8000-000000000003")
      .setIssuedAt()
      .setNotBefore("45s")
      .setExpirationTime("15m")
      .setIssuer(env.JWT_ISSUER)
      .setAudience(env.JWT_AUDIENCE)
      .sign(secret);

    await expect(verifyAccessToken(token)).resolves.toMatchObject({
      typ: "access",
      tenant_id: "00000000-0000-4000-8000-000000000001",
    });
  });

  it("rejects token far in the future beyond tolerance", async () => {
    const secret = encoder.encode(env.JWT_SECRET_ACTIVE ?? env.JWT_SECRET ?? "test-secret");

    const token = await new SignJWT({
      typ: "access",
      tenant_id: "00000000-0000-4000-8000-000000000001",
      tid: "00000000-0000-4000-8000-000000000001",
    })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("00000000-0000-4000-8000-000000000002")
      .setJti("00000000-0000-4000-8000-000000000003")
      .setIssuedAt()
      .setNotBefore("5m")
      .setExpirationTime("20m")
      .setIssuer(env.JWT_ISSUER)
      .setAudience(env.JWT_AUDIENCE)
      .sign(secret);

    await expect(verifyAccessToken(token)).rejects.toBeDefined();
  });
});
