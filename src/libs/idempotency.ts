import type { DbClient } from "./db.js";

type ExistingIdempotentResponse = {
  status_code: number;
  response_body: unknown;
};

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
    const { rows } = await db.query<ExistingIdempotentResponse>(
      `
        SELECT status_code, response_body
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

    return rows[0] ?? null;
  } catch (err) {
    if (isTableMissing(err)) {
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
      return;
    }
    throw err;
  }
}
