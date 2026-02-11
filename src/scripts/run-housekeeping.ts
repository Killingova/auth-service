import pg from "pg";

const { Pool } = pg;

type StatsRow = {
  delete_expired_tokens: number;
  delete_expired_sessions: number;
  revoke_expired_refresh_tokens: number;
  delete_expired_idempotency_keys: number;
  delete_published_outbox_events: number;
};

function readArg(name: string): string | undefined {
  const prefix = `--${name}=`;
  const arg = process.argv.find((value) => value.startsWith(prefix));
  return arg ? arg.slice(prefix.length) : undefined;
}

async function main() {
  const connectionString =
    process.env.MAINTENANCE_DATABASE_URL ?? process.env.DATABASE_URL;

  if (!connectionString) {
    throw new Error(
      "Missing MAINTENANCE_DATABASE_URL or DATABASE_URL for housekeeping run.",
    );
  }

  const anonymizeTenantId = readArg("tenant-id");
  const anonymizeUserId = readArg("user-id");
  const anonymizeReason = readArg("reason") ?? "rtbf";

  const pool = new Pool({ connectionString });

  try {
    const { rows } = await pool.query<StatsRow>(
      `
        SELECT
          auth.delete_expired_tokens() AS delete_expired_tokens,
          auth.delete_expired_sessions() AS delete_expired_sessions,
          auth.revoke_expired_refresh_tokens() AS revoke_expired_refresh_tokens,
          auth.delete_expired_idempotency_keys() AS delete_expired_idempotency_keys,
          auth.delete_published_outbox_events(now() - interval '7 days') AS delete_published_outbox_events;
      `,
    );

    console.log("housekeeping", rows[0]);

    if (anonymizeTenantId || anonymizeUserId) {
      if (!anonymizeTenantId || !anonymizeUserId) {
        throw new Error("--tenant-id and --user-id must be provided together.");
      }

      const { rows: anonymizeRows } = await pool.query<{ anonymized: boolean }>(
        `SELECT auth.anonymize_user($1::uuid, $2::uuid, $3::text) AS anonymized;`,
        [anonymizeTenantId, anonymizeUserId, anonymizeReason],
      );

      console.log("anonymize_user", anonymizeRows[0]);
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error("housekeeping_failed", err);
  process.exit(1);
});
