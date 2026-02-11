import { createHash } from "node:crypto";

export function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function hashEmailForLog(email: string): string {
  return sha256(email.trim().toLowerCase());
}

export function hashIpForLog(ip: string): string {
  return sha256(ip.trim());
}
