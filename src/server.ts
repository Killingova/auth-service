// src/server.ts
// ============================================================================
// Bootstrap für den Auth-Service (Fastify / RLS-Backend)
// ----------------------------------------------------------------------------
// Aufgaben:
//  - Prozessstart: buildApp() + listen()
//  - Prozessweite Fehlerwächter (unhandledRejection / uncaughtException)
//  - Geordneter Shutdown mit Timeout-Guard (SIGINT, SIGTERM, SIGUSR2)
//  - Node-HTTP Low-Level Timeouts (gegen Slowloris / hängende Verbindungen)
//  - Optionales Readiness-Flag (setReady in app.ts)
// ============================================================================

import { buildApp } from "./app.js"; // setReady wird im Shutdown dynamisch importiert (siehe unten)

// Basis-Umgebungsparameter
const PORT = Number(process.env.PORT ?? 3000);
const HOST = process.env.HOST ?? "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV ?? "development";

// Shutdown-Konfiguration
// Maximale Wartezeit für geordnetes Beenden, bevor hart terminiert wird.
const SHUTDOWN_TIMEOUT_MS = Number(process.env.SHUTDOWN_TIMEOUT_MS ?? 10_000);

// HTTP-Timeouts (Node-Server-Ebene, zusätzlich zu Fastify-Optionen)
const REQUEST_TIMEOUT_MS = Number(process.env.REQUEST_TIMEOUT_MS ?? 30_000);
const HEADERS_TIMEOUT_MS = Number(process.env.HEADERS_TIMEOUT_MS ?? 61_000);
const KEEPALIVE_TIMEOUT_MS = Number(process.env.KEEPALIVE_TIMEOUT_MS ?? 65_000);

// Doppel-Start/Mehrfach-Shutdown verhindern
let app: Awaited<ReturnType<typeof buildApp>> | undefined;
let startingUp = false;
let shuttingDown = false;

/**
 * Defensives Loggen
 * - nutzt nach Möglichkeit den Fastify-Logger (pino)
 * - fällt bei Problemen auf console.* zurück
 */
function safeLog(
  level: "info" | "warn" | "error",
  msg: string,
  extra?: unknown,
) {
  try {
    if (app?.log) {
      (app.log as any)[level]({ ctx: "server", ...((extra as object) ?? {}) }, msg);
    } else {
      const fn =
        level === "error" ? console.error : level === "warn" ? console.warn : console.log;
      fn(msg, extra ?? "");
    }
  } catch {
    // Fallback, falls sogar das Logging schiefgeht
    console.log(msg, extra ?? "");
  }
}

// ============================================================================
// Prozessweite Fehlerwächter
// ============================================================================

process.on("unhandledRejection", (reason, p) => {
  safeLog("error", "unhandled_rejection", {
    reason,
    promise: String(p),
  });
  // Kein harter Exit → Shutdown wird bewusst über Signal ausgelöst.
});

process.on("uncaughtException", (err) => {
  safeLog("error", "uncaught_exception", { err });
  // Geordneten Shutdown anstoßen
  void shutdown("uncaughtException");
});

// ============================================================================
// Start & Listen
// ============================================================================

async function start() {
  if (startingUp) return;
  startingUp = true;

  try {
    app = await buildApp();

    // Node-HTTP Low-Level Timeouts zusätzlich zu Fastify-Options
    // Hinweis: app.server ist der native Node http/https Server
    app.server.requestTimeout = REQUEST_TIMEOUT_MS;
    app.server.headersTimeout = HEADERS_TIMEOUT_MS;
    app.server.keepAliveTimeout = KEEPALIVE_TIMEOUT_MS;

    app.log.info(
      {
        env: NODE_ENV,
        pid: process.pid,
        node: process.version,
        host: HOST,
        port: PORT,
        requestTimeoutMs: REQUEST_TIMEOUT_MS,
        headersTimeoutMs: HEADERS_TIMEOUT_MS,
        keepAliveTimeoutMs: KEEPALIVE_TIMEOUT_MS,
      },
      "auth_service_bootstrap",
    );

    await app.listen({ host: HOST, port: PORT });

    const addr = app.server.address();
    app.log.info({ address: addr }, "auth_service_listening");
  } catch (err) {
    // Startfehler → sauberer Exit, damit Orchestrator (Docker/K8s) neu starten kann.
    console.error("server_start_failed", err);
    process.exitCode = 1;
    setTimeout(() => process.exit(1), 50); // kurze Verzögerung, damit Logs flushen
  }
}

// ============================================================================
// Geordneter Shutdown
// ============================================================================

async function shutdown(reason: string) {
  if (shuttingDown) return;
  shuttingDown = true;

  // Fail-Safe: falls irgendwas hängt, nach Timeout hart beenden
  const killTimer = setTimeout(() => {
    safeLog("error", "shutdown_forced_exit", {
      timeoutMs: SHUTDOWN_TIMEOUT_MS,
      reason,
    });
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);
  (killTimer as any)?.unref?.(); // hält den Prozess nicht künstlich am Leben

  try {
    safeLog("info", "shutdown_received", { reason });

    // 1) Readiness sofort degradieren (falls in app.ts exportiert)
    //    - Verhindert neue Requests; Loadbalancer nimmt Instanz aus Rotation.
    try {
      const mod = (await import("./app.js").catch(() => null)) as
        | { setReady?: (ready: boolean) => void }
        | null;
      mod?.setReady?.(false);
    } catch {
      // optional, kein harter Fehler
    }

    // 2) HTTP-Server schließen: akzeptiert keine neuen Requests mehr,
    //    offene Requests dürfen sauber auslaufen.
    if (app) {
      await app.close(); // triggert onClose-Hooks (z. B. closeDb(), Redis, etc.)
      safeLog("info", "server_closed");
    }

    clearTimeout(killTimer);
    process.exit(0);
  } catch (err) {
    safeLog("error", "shutdown_error", { err });
    clearTimeout(killTimer);
    process.exit(1);
  }
}

// ============================================================================
// Signal-Handler (einmalig registriert)
// ============================================================================
// SIGINT  = Ctrl+C / `docker stop`
// SIGTERM = Standard-Stop in Docker/Kubernetes
// SIGUSR2 = häufig von nodemon im Dev-Modus genutzt

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));
process.once("SIGUSR2", () => void shutdown("SIGUSR2"));

// ============================================================================
// Bootstrap
// ============================================================================

start();
