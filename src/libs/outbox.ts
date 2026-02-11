import type { DbClient } from "./db.js";

type OutboxEventInput = {
  tenantId: string;
  eventType: string;
  aggregateType?: string;
  aggregateId?: string | null;
  payload?: Record<string, unknown>;
  idempotencyKey?: string;
};

function isTableMissing(err: unknown): boolean {
  return typeof err === "object" && err !== null && (err as { code?: string }).code === "42P01";
}

export async function appendOutboxEvent(
  db: DbClient,
  event: OutboxEventInput,
): Promise<void> {
  const payload = JSON.stringify(event.payload ?? {});

  try {
    await db.query(
      `
        INSERT INTO auth.outbox_events (
          tenant_id,
          event_type,
          aggregate_type,
          aggregate_id,
          payload,
          idempotency_key,
          created_at
        )
        VALUES ($1, $2, $3, $4, $5::jsonb, $6, now())
        ON CONFLICT (tenant_id, event_type, idempotency_key)
        DO NOTHING;
      `,
      [
        event.tenantId,
        event.eventType,
        event.aggregateType ?? "auth",
        event.aggregateId ?? null,
        payload,
        event.idempotencyKey ?? null,
      ],
    );
  } catch (err) {
    if (isTableMissing(err)) {
      return;
    }
    throw err;
  }
}
