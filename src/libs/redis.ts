// ============================================================================
// src/libs/redis.ts
// ----------------------------------------------------------------------------
// Robuste Redis-Integration (ioredis v5)
// - nutzt env.REDIS_URL oder granularen Fallback
// - globaler Singleton-Client
// - Utility-Funktionen fuer JSON, Rate-Limit, Blacklist, Streams
// - tenant-basierte Keys als einziges Zielschema
// ============================================================================
import Redis, { Redis as RedisClient } from "ioredis";
import { createHash, randomUUID } from "node:crypto";
import { env } from "./env.js";

// globaler Cache fuer Singleton (verhindert Mehrfachverbindungen im Dev)
const GLOBAL_KEY = "__auth_service_redis__" as const;
type GlobalWithRedis = typeof globalThis & { [GLOBAL_KEY]?: RedisClient };
const g = globalThis as GlobalWithRedis;

const SERVICE_NS = "auth";
const IDEMPOTENCY_TTL_SEC = 60 * 60 * 24; // 24h
const DEFAULT_LOCK_TTL_MS = 60_000;

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const KEY_PART_RE = /^[a-z0-9:_-]{1,128}$/;

// -----------------------------
// Client-Erzeugung
// -----------------------------
function createClient(): RedisClient {
  const url = env.REDIS_URL ?? "redis://localhost:6379";

  // Konstruktor ueber cast wegen ESM/TS-Inkompatibilitaeten in ioredis v5
  return new (Redis as unknown as new (url: string, opts?: any) => RedisClient)(url, {
    lazyConnect: true,
    enableReadyCheck: true,
    enableAutoPipelining: true,
    maxRetriesPerRequest: 3,
    retryStrategy: (times: number) => Math.min(1000 * times, 10_000),
  });
}

// Singleton-Instanz
export const redis: RedisClient = g[GLOBAL_KEY] ?? (g[GLOBAL_KEY] = createClient());

// -----------------------------
// Basis-Events
// -----------------------------
redis.on("connect", () => console.log("[redis] connect"));
redis.on("ready", () => console.log("[redis] ready"));
redis.on("error", (err) => console.error("[redis] error", err));
redis.on("end", () => console.log("[redis] end"));

// -----------------------------
// Health & Lifecycle
// -----------------------------
export async function ensureRedis() {
  if ((redis as any).status !== "ready") {
    await redis.connect();
    await redis.ping();
  }
}

export async function redisHealth() {
  const pong = await redis.ping();
  return { ping: pong, mode: (redis as any).status };
}

export async function quitRedis() {
  try {
    await redis.quit();
  } catch {
    await redis.disconnect();
  }
}

// -----------------------------
// Key-Helper
// -----------------------------
function normalizeTenantId(tenantId?: string): string | undefined {
  if (!tenantId) return undefined;
  const normalized = tenantId.trim().toLowerCase();
  return UUID_RE.test(normalized) ? normalized : undefined;
}

function requireTenantId(tenantId?: string, op = "redis_op"): string {
  const normalized = normalizeTenantId(tenantId);
  if (!normalized) {
    throw new Error(`[redis] tenant scope required for ${op}`);
  }
  return normalized;
}

function tenantKey(tenantId: string, ...parts: (string | number)[]) {
  return ["tenant", tenantId, SERVICE_NS, ...parts].join(":");
}

function scopedTenantKey(
  tenantId: string | undefined,
  op: string,
  ...parts: (string | number)[]
) {
  return tenantKey(requireTenantId(tenantId, op), ...parts);
}

function scopedKey(
  tenantId: string | undefined,
  ...parts: (string | number)[]
): string {
  const normalized = normalizeTenantId(tenantId);
  if (normalized) {
    return tenantKey(normalized, ...parts);
  }
  return ["global", SERVICE_NS, ...parts].join(":");
}

function splitLogicalKey(logicalKey: string): string[] {
  return logicalKey.split(":").filter(Boolean);
}

function hashKeyPart(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

function normalizedKeyPart(input: string): string {
  const value = input.trim().toLowerCase();
  if (KEY_PART_RE.test(value)) return value;
  return hashKeyPart(input);
}

// -----------------------------
// JSON-Storage
// -----------------------------
export async function setJSON(
  logicalKey: string,
  value: unknown,
  ttlSec?: number,
  tenantId?: string,
) {
  const payload = JSON.stringify(value);
  const keyName = scopedKey(tenantId, ...splitLogicalKey(logicalKey));
  const args: (string | number)[] = [keyName, payload];
  if (ttlSec && ttlSec > 0) args.push("EX", ttlSec);
  return (redis as any).set(...(args as any));
}

export async function getJSON<T = unknown>(
  logicalKey: string,
  tenantId?: string,
): Promise<T | null> {
  const parts = splitLogicalKey(logicalKey);
  const primaryKey = scopedKey(tenantId, ...parts);
  const raw = await redis.get(primaryKey);
  return raw ? (JSON.parse(raw) as T) : null;
}

// -----------------------------
// Rate-Limit-Counter
// -----------------------------
export async function incrLimit(
  routeId: string,
  ip: string,
  windowSec: number,
  max: number,
  tenantId?: string,
) {
  const rateKey = scopedKey(
    tenantId,
    "rate",
    normalizedKeyPart(routeId),
    normalizedKeyPart(ip),
  );
  const count = await redis.incr(rateKey);
  if (count === 1) await redis.expire(rateKey, windowSec);
  const ttl = await redis.ttl(rateKey);
  return { count, ttl, blocked: count > max };
}

// -----------------------------
// Login soft-lock (account + ip)
// -----------------------------
function loginLockKey(emailHash: string, ipHash: string, tenantId?: string) {
  return scopedKey(tenantId, "lock", "login", emailHash, ipHash);
}

export async function getLoginFailureState(
  emailHash: string,
  ipHash: string,
  maxAttempts: number,
  tenantId?: string,
) {
  const keyName = loginLockKey(emailHash, ipHash, tenantId);

  const raw = await redis.get(keyName);
  const ttl = await redis.ttl(keyName);

  const count = raw ? Number(raw) : 0;
  return {
    count,
    ttl,
    locked: count >= maxAttempts,
  };
}

export async function registerLoginFailure(
  emailHash: string,
  ipHash: string,
  windowSec: number,
  maxAttempts: number,
  tenantId?: string,
) {
  const keyName = loginLockKey(emailHash, ipHash, tenantId);
  const count = await redis.incr(keyName);
  if (count === 1) {
    await redis.expire(keyName, windowSec);
  }
  const ttl = await redis.ttl(keyName);
  return {
    count,
    ttl,
    locked: count >= maxAttempts,
  };
}

export async function clearLoginFailures(
  emailHash: string,
  ipHash: string,
  tenantId?: string,
) {
  await redis.del(loginLockKey(emailHash, ipHash, tenantId));
}

// -----------------------------
// Token-Blacklist
// -----------------------------
export async function blacklistAdd(tokenJti: string, ttlSec: number, tenantId?: string) {
  return redis.set(
    scopedKey(tenantId, "bl", "access", tokenJti),
    "1",
    "EX",
    ttlSec,
  );
}

export async function blacklistHas(tokenJti: string, tenantId?: string) {
  return (
    (await redis.exists(scopedKey(tenantId, "bl", "access", tokenJti))) ===
    1
  );
}

// -----------------------------
// Idempotency-Cache (Redis)
// -----------------------------
export type CachedIdempotentResponse = {
  status_code: number;
  response_body: unknown;
};

function idempotencyCacheKey(
  tenantId: string | undefined,
  endpoint: string,
  idempotencyKey: string,
) {
  return scopedKey(
    tenantId,
    "idem",
    hashKeyPart(endpoint),
    hashKeyPart(idempotencyKey),
  );
}

export async function readIdempotentResponseCache(opts: {
  tenantId: string;
  endpoint: string;
  idempotencyKey: string;
}): Promise<CachedIdempotentResponse | null> {
  const keyName = idempotencyCacheKey(opts.tenantId, opts.endpoint, opts.idempotencyKey);
  const raw = await redis.get(keyName);
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as CachedIdempotentResponse;
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      typeof parsed.status_code !== "number"
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export async function writeIdempotentResponseCache(opts: {
  tenantId: string;
  endpoint: string;
  idempotencyKey: string;
  statusCode: number;
  responseBody: unknown;
  ttlSec?: number;
}): Promise<void> {
  const keyName = idempotencyCacheKey(opts.tenantId, opts.endpoint, opts.idempotencyKey);
  const payload = JSON.stringify({
    status_code: opts.statusCode,
    response_body: opts.responseBody,
  });
  const ttlSec = Math.max(1, Math.floor(opts.ttlSec ?? IDEMPOTENCY_TTL_SEC));
  await redis.set(keyName, payload, "EX", ttlSec);
}

// -----------------------------
// Short Locks (Redis SET NX PX)
// -----------------------------
export type RedisLockHandle = {
  key: string;
  token: string;
};

function lockKey(
  tenantId: string | undefined,
  scope: string,
  resource: string,
): string {
  return scopedTenantKey(
    tenantId,
    "lockKey",
    "lock",
    normalizedKeyPart(scope),
    hashKeyPart(resource),
  );
}

export async function acquireShortLock(opts: {
  tenantId: string;
  scope: string;
  resource: string;
  ttlMs?: number;
}): Promise<{ acquired: boolean; lock?: RedisLockHandle }> {
  const ttlMs = Math.max(1_000, Math.floor(opts.ttlMs ?? DEFAULT_LOCK_TTL_MS));
  const keyName = lockKey(opts.tenantId, opts.scope, opts.resource);
  const token = randomUUID();
  const result = await redis.set(keyName, token, "PX", ttlMs, "NX");
  if (result !== "OK") return { acquired: false };
  return {
    acquired: true,
    lock: {
      key: keyName,
      token,
    },
  };
}

export async function releaseShortLock(lock: RedisLockHandle): Promise<boolean> {
  // ACL-minimal ohne EVAL:
  // Wenn der Lock-Token nicht mehr passt, wird nicht geloescht.
  const current = await redis.get(lock.key);
  if (current !== lock.token) return false;
  return (await redis.del(lock.key)) === 1;
}

// -----------------------------
// Streams / Event-Log
// -----------------------------
export async function streamAdd(
  stream: string,
  fields: Record<string, string | number>,
  tenantId?: string,
) {
  const flat: (string | number)[] = [];
  for (const [k, v] of Object.entries(fields)) flat.push(k, String(v));

  const streamKey = scopedKey(tenantId, "stream", stream);
  return (redis as any).xadd(streamKey, "*", ...(flat as any));
}
