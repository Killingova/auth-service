// ============================================================================
// src/libs/http.ts
// ----------------------------------------------------------------------------
// HTTP-Hilfsfunktionen (Logging, Keys, Metriken)
// ============================================================================
import type { FastifyRequest } from "fastify";

/** Liefert eine stabile Routen-ID (für Logs/Keys/Metriken). */
export function getRouteId(req: FastifyRequest): string {
  const anyReq = req as any;
  return (
    anyReq.routerPath ||            // von Plugins gesetzt
    req.routeOptions?.url ||        // Fastify v4
    (req as any).url ||             // generisch
    req.raw?.url ||                 // Node-HTTP
    "unknown"
  );
}

/** Ermittelt, ob die Anfrage einen Health-Endpoint adressiert. */
export function isHealthPath(req: FastifyRequest): boolean {
  const url = req.raw.url ?? "";
  return (
    url === "/health" ||
    url === "/healthz" ||
    url === "/readyz" ||
    url.startsWith("/health/")
  );
}
