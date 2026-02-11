// src/scripts/seed-demo-users.ts
// ============================================================================
// Seed-Skript für Demo-User
// - Setzt für alice@demo.local und bob@demo.local ein definiertes Passwort
// - Password: demo123 (für beide)
// ============================================================================

import { query } from "../libs/db.js";
import { hashPassword } from "../libs/crypto.js"; // Gegenstück zu verifyPassword

async function main() {
  const plainPassword = "demo123";
  const hash = await hashPassword(plainPassword);

  const verbose = process.argv.includes("--verbose");
  if (verbose) {
    console.log("Neuer Hash für demo-Passwort:", hash);
  }

  // 1) Prüfen, ob User existieren
  const users = await query<{ email: string }>(
    `SELECT email FROM auth.users WHERE email IN ('alice@demo.local', 'bob@demo.local')`,
  );

  if (users.length === 0) {
    console.error("Keine Demo-User in auth.users gefunden. Seed-SQL vorher ausführen?");
    process.exit(1);
  }

  // 2) Passwoerter in auth.credentials setzen/updaten
  await query(
    `
      INSERT INTO auth.credentials (tenant_id, user_id, password_hash, password_changed_at)
      SELECT tenant_id, id, $1, now()
      FROM auth.users
      WHERE email IN ('alice@demo.local', 'bob@demo.local')
      ON CONFLICT (user_id)
      DO UPDATE SET
        password_hash = EXCLUDED.password_hash,
        password_changed_at = now();
    `,
    [hash],
  );

  console.log("Demo-Passwörter gesetzt für alice@demo.local und bob@demo.local (demo123)");
}

main().catch((err) => {
  console.error("Seed fehlgeschlagen:", err);
  process.exit(1);
});
