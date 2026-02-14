// src/modules/register/routes.ts
// ============================================================================
// Fastify-Routen für Registrierung
// ----------------------------------------------------------------------------
// - POST /auth/register          → neuen User registrieren
// - GET  /auth/register/health   → Modul-Healthcheck
//
// Sicherheit / Datenschutz (ISO/OWASP/DSGVO):
// - Strikte Eingabevalidierung mit Zod
// - Keine direkte Information, ob eine bestimmte E-Mail bereits existiert
//   → Reduktion von User-Enumeration-Risiken
// - Nur minimale User-Daten im Response (id, email, createdAt)
// - Events für Auditing / Worker via Redis Streams (auth-events)
//
// RLS / Tenant-Kontext:
// - Im HTTP-Flow wird ein pro-Request-DbClient (req.db) verwendet,
//   der vom Tenant-/RLS-Plugin vorbereitet wird:
//     BEGIN;
//     SELECT set_config('app.tenant', '<UUID>', true);
//     SET LOCAL ROLE app_auth;
//   → registerUser() bekommt diesen Client explizit übergeben.
// ============================================================================

import type { FastifyInstance } from "fastify";
import { z } from "zod";

import { mapDbError } from "../../libs/error-map.js";
import { sendApiError } from "../../libs/error-response.js";
import { streamAdd } from "../../libs/redis.js";
import type { DbClient } from "../../libs/db.js";
import {
  registerUser,
  getRegisterHealth,
} from "./service.js";

// ---------------------------------------------------------------------------
// Zod-Schema für Request-Body
// ---------------------------------------------------------------------------
//
// Hinweis:
// tenantName ist aktuell optional und wird in service.ts noch nicht verwendet.
// Du kannst das später aktivieren, ohne das API zu brechen (z. B. Tenant
// dynamisch provisionieren statt Default-Tenant).
//
const RegisterBodySchema = z.object({
  email: z.string().email("Bitte eine gültige E-Mail-Adresse angeben."),
  password: z
    .string()
    .min(8, "Passwort muss mindestens 8 Zeichen lang sein.")
    .max(72, "Passwort darf maximal 72 Zeichen lang sein."),
  tenant_name: z
    .string()
    .min(3, "Tenant-Name muss mindestens 3 Zeichen lang sein.")
    .max(120, "Tenant-Name darf maximal 120 Zeichen lang sein.")
    .optional(),
});

type RegisterBody = z.infer<typeof RegisterBodySchema>;

// ---------------------------------------------------------------------------
// Routen-Plugin
// ---------------------------------------------------------------------------

export default async function registerRoutes(app: FastifyInstance) {
  // -------------------------------------------------------------------------
  // POST /auth/register
  // -------------------------------------------------------------------------
  app.post(
    "/register",
    { config: { tenant: false, auth: false, db: true } },
    async (req, reply) => {
    const parsed = RegisterBodySchema.safeParse(req.body);

    // 1) Body-Validierung
    if (!parsed.success) {
      return sendApiError(
        reply,
        400,
        "VALIDATION_FAILED",
        "Invalid register payload.",
        parsed.error.flatten(),
      );
    }

    const body: RegisterBody = parsed.data;

    // 2) RLS-gebundenen DbClient aus dem Request holen
    //
    // Hinweis:
    // - tenantDbContextPlugin hängt einen DbClient an req.db,
    //   auf dem bereits BEGIN / set_config('app.tenant', ...) / SET LOCAL ROLE
    //   ausgeführt wurden.
    // - Wir casten hier leicht, damit TypeScript weiß, dass db existiert.
    const { db } = req as typeof req & { db: DbClient };

    try {
      // 3) Business-Logik (Service-Layer)
      //    → Service muss entsprechend angepasst sein, um DbClient zu erwarten:
      //
      //    export async function registerUser(params: {
      //      db: DbClient;
      //      email: string;
      //      password: string;
      //      tenantName?: string;
      //    }): Promise<{ user: PublicUser }> { ... }
      //
      const result = await registerUser({
        db,
        email: body.email,
        password: body.password,
        tenantName: body.tenant_name,
      });

      // 4) Event für Auditing / Worker (Redis Streams)
      //    Fehler beim Stream dürfen die Registrierung NICHT abbrechen.
      try {
        await streamAdd("auth-events", {
          type: "auth.register",
          requestAccepted: result.requestAccepted ? 1 : 0,
        });
      } catch (err) {
        app.log.warn({ err }, "register_stream_failed");
      }

      // 5) Erfolgsantwort: immer gleich (Anti-Enumeration)
      return reply.code(202).send({
        ok: true,
        message: "Wenn die E-Mail-Adresse gültig ist, erhältst du einen Verifizierungs-Link.",
      });
    } catch (err: any) {
      const mapped = mapDbError(err);
      return sendApiError(reply, mapped.status, mapped.code, mapped.message);
    }
    },
  );

  // -------------------------------------------------------------------------
  // GET /auth/register/health
  // -------------------------------------------------------------------------
  app.get("/register/health", async (_req, reply) => {
    // Healthcheck verwendet typischerweise den globalen Pool / dbHealth(),
    // nicht den pro-Request-RLS-Client, um die Grund-Erreichbarkeit der DB
    // unabhängig vom Tenant-Kontext zu prüfen.
    const health = await getRegisterHealth();
    const statusCode = health.healthy ? 200 : 503;

    return reply.code(statusCode).send({
      module: "register",
      healthy: health.healthy,
      db: health.db,
    });
  });
}
