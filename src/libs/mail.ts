// src/libs/mail.ts
// ============================================================================
// SMTP / Mailpit-Integration für den Auth-Service
// ----------------------------------------------------------------------------
// - Nutzt direkt process.env (unabhängig von env.ts-Schema)
// - Healthcheck via transporter.verify()
// ============================================================================

import nodemailer from "nodemailer";

const SMTP_HOST = process.env.SMTP_HOST ?? "auth-mailpit";
const SMTP_PORT = Number(process.env.SMTP_PORT ?? "1025");
const SMTP_SECURE = process.env.SMTP_SECURE === "true";
const SMTP_USER = process.env.SMTP_USER || undefined;
const SMTP_PASS = process.env.SMTP_PASS || undefined;
export const SMTP_FROM =
  process.env.SMTP_FROM ?? "Auth Service DEV <auth@example.test>";

export const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_SECURE,
  auth:
    SMTP_USER && SMTP_PASS
      ? {
          user: SMTP_USER,
          pass: SMTP_PASS,
        }
      : undefined,
});

// Health-Check für /health und /health/smtp
export async function mailHealth(): Promise<{
  ok: boolean;
  reason?: string;
}> {
  try {
    await transporter.verify();
    return { ok: true };
  } catch (err: any) {
    return {
      ok: false,
      reason: err?.message ?? "smtp_verify_failed",
    };
  }
}
