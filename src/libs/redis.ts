// ============================================================================
// src/libs/redis.ts
// ----------------------------------------------------------------------------
// Robuste Redis-Integration (ioredis v5)
// - nutzt env.REDIS_URL oder granularen Fallback
// - globaler Singleton-Client
// - Utility-Funktionen für JSON, Rate-Limit, Blacklist, Streams
// - Health-Check & Graceful-Shutdown
// ============================================================================
import Redis, { Redis as RedisClient } from "ioredis";
import { env } from "./env.js";

// globaler Cache für Singleton (verhindert Mehrfachverbindungen im Dev)
const GLOBAL_KEY = "__paradox_redis__" as const;
type GlobalWithRedis = typeof globalThis & { [GLOBAL_KEY]?: RedisClient };
const g = globalThis as GlobalWithRedis;

// Namespace für alle Keys (präfix)
const ns = env.REDIS_NAMESPACE;

// -----------------------------
// Client-Erzeugung
// -----------------------------
function createClient(): RedisClient {
  const url = env.REDIS_URL ?? "redis://localhost:6379";

  // Konstruktor über cast wegen ESM/TS-Inkompatibilitäten in ioredis v5
  return new (Redis as unknown as new (url: string, opts?: any) => RedisClient)(url, {
    lazyConnect: true,            // Verbindung erst bei Bedarf
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
redis.on("ready",   () => console.log("[redis] ready"));
redis.on("error",   (err) => console.error("[redis] error", err));
redis.on("end",     () => console.log("[redis] end"));

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
const key = (...parts: (string | number)[]) => [ns, ...parts].join(":");

// -----------------------------
// JSON-Storage
// -----------------------------
export async function setJSON(k: string, value: unknown, ttlSec?: number) {
  const payload = JSON.stringify(value);
  const args: (string | number)[] = [key(k), payload];
  if (ttlSec && ttlSec > 0) args.push("EX", ttlSec);
  return (redis as any).set(...(args as any));
}

export async function getJSON<T = unknown>(k: string): Promise<T | null> {
  const raw = await redis.get(key(k));
  return raw ? (JSON.parse(raw) as T) : null;
}

// -----------------------------
// Rate-Limit-Counter
// -----------------------------
export async function incrLimit(routeId: string, ip: string, windowSec: number, max: number) {
  const rk = key("rl", routeId, ip);
  const count = await redis.incr(rk);
  if (count === 1) await redis.expire(rk, windowSec);
  const ttl = await redis.ttl(rk);
  return { count, ttl, blocked: count > max };
}

// -----------------------------
// Login soft-lock (account + ip)
// -----------------------------
function loginLockKey(emailHash: string, ipHash: string) {
  return key("lock", "login", emailHash, ipHash);
}

export async function getLoginFailureState(
  emailHash: string,
  ipHash: string,
  maxAttempts: number,
) {
  const k = loginLockKey(emailHash, ipHash);
  const raw = await redis.get(k);
  const count = raw ? Number(raw) : 0;
  const ttl = await redis.ttl(k);
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
) {
  const k = loginLockKey(emailHash, ipHash);
  const count = await redis.incr(k);
  if (count === 1) {
    await redis.expire(k, windowSec);
  }
  const ttl = await redis.ttl(k);
  return {
    count,
    ttl,
    locked: count >= maxAttempts,
  };
}

export async function clearLoginFailures(emailHash: string, ipHash: string) {
  await redis.del(loginLockKey(emailHash, ipHash));
}

// -----------------------------
// Token-Blacklist
// -----------------------------
export async function blacklistAdd(tokenJti: string, ttlSec: number) {
  return redis.set(key("bl", "access", tokenJti), "1", "EX", ttlSec);
}
export async function blacklistHas(tokenJti: string) {
  return (await redis.exists(key("bl", "access", tokenJti))) === 1;
}

// -----------------------------
// Streams / Event-Log
// -----------------------------
export async function streamAdd(stream: string, fields: Record<string, string | number>) {
  const flat: (string | number)[] = [];
  for (const [k, v] of Object.entries(fields)) flat.push(k, String(v));
  return (redis as any).xadd(key("stream", stream), "*", ...(flat as any));
}
