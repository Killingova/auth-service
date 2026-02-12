import type { DbClient } from "./db.js";
import {
  readIdempotentResponseCache,
  writeIdempotentResponseCache,
} from "./redis.js";

type ExistingIdempotentResponse = {
  status_code: number;
  response_body: unknown;
};

type ExistingIdempotentResponseRow = ExistingIdempotentResponse & {
  ttl_sec: number | string;
};

const IDEMPOTENCY_TTL_SEC = 60 * 60 * 24; // 24h
let hasIdempotencyTable: boolean | undefined;

async function ensureIdempotencyTable(db: DbClient): Promise<boolean> {
  if (hasIdempotencyTable !== undefined) return hasIdempotencyTable;

  const { rows } = await db.query<{ present: boolean }>(
    `
      SELECT to_regclass('auth.idempotency_keys') IS NOT NULL AS present;
    `,
  );

  hasIdempotencyTable = Boolean(rows[0]?.present);
  return hasIdempotencyTable;
}

function isTableMissing(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "42P01";
}

export function getIdempotencyKey(
  headerValue: string | string[] | undefined,
): string | undefined {
  const raw =
    typeof headerValue === "string"
      ? headerValue
      : Array.isArray(headerValue)
        ? headerValue[0]
        : undefined;

  const normalized = raw?.trim();
  return normalized && normalized.length > 0 ? normalized : undefined;
}

export async function readIdempotentResponse(
  db: DbClient,
  opts: { tenantId: string; endpoint: string; idempotencyKey: string },
): Promise<ExistingIdempotentResponse | null> {
  try {
    const cached = await readIdempotentResponseCache(opts);
    if (cached) return cached;
  } catch {
    // Redis ist Beschleuniger; DB bleibt Fallback/Source fuer Contract.
  }

  try {
    if (!(await ensureIdempotencyTable(db))) {
      return null;
    }

    const { rows } = await db.query<ExistingIdempotentResponseRow>(
      `
        SELECT
          status_code,
          response_body,
          GREATEST(1, EXTRACT(EPOCH FROM (expires_at - now()))::int) AS ttl_sec
        FROM auth.idempotency_keys
        WHERE tenant_id = $1
          AND endpoint = $2
          AND idempotency_key = $3
          AND response_body IS NOT NULL
          AND expires_at > now()
        LIMIT 1;
      `,
      [opts.tenantId, opts.endpoint, opts.idempotencyKey],
    );

    const row = rows[0];
    if (!row) return null;

    try {
      await writeIdempotentResponseCache({
        ...opts,
        statusCode: row.status_code,
        responseBody: row.response_body,
        ttlSec: Math.max(1, Number(row.ttl_sec) || IDEMPOTENCY_TTL_SEC),
      });
    } catch {
      // Cache-Fill best-effort.
    }

    return {
      status_code: row.status_code,
      response_body: row.response_body,
    };
  } catch (err) {
    if (isTableMissing(err)) {
      hasIdempotencyTable = false;
      return null;
    }
    throw err;
  }
}

export async function writeIdempotentResponse(
  db: DbClient,
  opts: {
    tenantId: string;
    endpoint: string;
    idempotencyKey: string;
    statusCode: number;
    responseBody: unknown;
  },
): Promise<void> {
  try {
    await writeIdempotentResponseCache({
      ...opts,
      ttlSec: IDEMPOTENCY_TTL_SEC,
    });
  } catch {
    // Redis write ist best-effort; DB bleibt verlässlich.
  }

  try {
    if (!(await ensureIdempotencyTable(db))) {
      return;
    }

    await db.query(
      `
        INSERT INTO auth.idempotency_keys (
          tenant_id,
          endpoint,
          idempotency_key,
          status_code,
          response_body,
          created_at,
          expires_at
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5::jsonb,
          now(),
          now() + interval '24 hours'
        )
        ON CONFLICT (tenant_id, endpoint, idempotency_key)
        DO UPDATE SET
          status_code = EXCLUDED.status_code,
          response_body = EXCLUDED.response_body,
          expires_at = GREATEST(auth.idempotency_keys.expires_at, EXCLUDED.expires_at);
      `,
      [
        opts.tenantId,
        opts.endpoint,
        opts.idempotencyKey,
        opts.statusCode,
        JSON.stringify(opts.responseBody),
      ],
    );
  } catch (err) {
    if (isTableMissing(err)) {
      hasIdempotencyTable = false;
      return;
    }
    throw err;
  }
}
