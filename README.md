Auth-Service (Fastify, PostgreSQL, Redis)
========================================

Dieser Dienst stellt einen mandantenfähigen Auth‑Service bereit: Login, Registrierung, E‑Mail‑Verifikation, Passwort‑Reset, Magic‑Link, OTP, Sessions, Tenants und Token‑Cleanup. Er ist auf Fastify v5 aufgebaut und nutzt PostgreSQL (auth‑Schema) und Redis.

## Zweck / Boundary
- Authentifizierung und Session-/Token-Management pro Tenant.
- Redis als kurzlebiger State-Layer (Blacklist, Rate, Locks), PostgreSQL bleibt Source of Truth.
- Kein direkter Public-Zugriff auf DB/Redis, nur via API/Gateway.

## Aktueller Stand (2026-02-12 15:57:21 CET)

- Container `auth-service-stack-auth-service-1` laeuft `healthy`.
- Gateway-Check `https://127.0.0.1:8443/auth/healthz` liefert `200`.
- Redis-Key-Schema ist tenant-basiert (`tenant:{tenantId}:auth:*`), Legacy-Namespace ist entfernt.
- Redis-Usecases aktiv: `jti blacklist`, tenant-aware `rate counters`, `idempotency keys` (Redis+DB) und kurze `locks` fuer `password reset`/`otp`.

## Security Contract
- `x-tenant-id` ist fuer tenant-gebundene Routen Pflicht.
- JWT Access-Tokens werden validiert, revokte JTIs werden ueber Redis geprueft.
- Secrets nur via `*_FILE`, keine Klartext-Secrets im Repo.

## Ops
- Start/Build: `docker compose up -d --build`
- Health: `GET /healthz`, `GET /health`, `GET /readyz`
- Diagnose: `docker compose logs -f auth-service`

## DoD Checks
```bash
curl -ks https://127.0.0.1:8443/auth/healthz
curl -ks https://127.0.0.1:8443/health/auth
curl -ks https://127.0.0.1:8443/healthz
```

Erwartung:
- Health-Endpunkte liefern `200`.

## Guardrails
- Kein Legacy-Redis-Namespace (`paradox:*`) mehr verwenden.
- Keine Klartext-Tokens oder PII in Redis.
- Keine Umgehung von Tenant- und JWT-Guards.

Die wichtigsten Bausteine:

- `src/app.ts` – Fastify‑App (`buildApp`), Health‑Routen, Modul‑Registrierung.
- `src/server.ts` – Bootstrap + Graceful Shutdown.
- `src/libs/*` – Infrastruktur (DB, Redis, JWT, Crypto, Mail, Rate‑Limit).
- `src/modules/*` – Fachmodule mit `repository.ts`, `service.ts`, `routes.ts`, `types.ts`.
- `src/tests/http/*` – HTTP‑Tests (Vitest) für Health, Fehlerfälle & Happy‑Path.

---

1. Infrastruktur & Health
-------------------------

**Globale Health‑Routen** (kein `x-tenant-id` notwendig):

- `GET /`  
  Basis‑Ping: `{ ok: true, service: "auth-service", ts }`.

- `GET /healthz`  
  Liveness‑Check.

- `GET /health`  
  Aggregat über Redis/DB/SMTP:
  - `status: "ok" | "degraded" | "down"`
  - `services: { redis, db, smtp }`.

- `GET /readyz`  
  Readiness‑Probe (nutzt Redis‑Health + internes `isReady`‑Flag).

- `GET /health/redis`  
  Redis‑Health (`{ ping: "PONG", mode }` oder `{ ok: true }`).

- `GET /health/db`  
  DB‑Health: `{ status: "ok" | "down", ok, error? }`.

- `GET /health/smtp`  
  SMTP/Mailpit‑Health.

- `GET /health/stack`  
  Kombinierter Stack‑Health: Redis + DB + SMTP.

---

2. Gemeinsame Anforderungen für /auth‑Routen
-------------------------------------------

Alle `/auth/...`‑Routen laufen im Kontext des `tenantDbContextPlugin`:

- Header `x-tenant-id: <UUID>` ist Pflicht (sonst 400/500).
- Pro Request wird ein RLS‑gebundener DB‑Client bereitgestellt:
  - `BEGIN;`
  - `SELECT set_config('app.tenant', '<UUID>', true);`
  - `SET LOCAL ROLE app_auth;`
  - `COMMIT/ROLLBACK` in Hooks.
- Der Client steht in Handlers unter `(req as any).db`.

Access‑Token:

- JWT im Header: `Authorization: Bearer <access_token>`.
- JTI wird in Redis geblacklistet (`blacklistAdd`, `blacklistHas`).

Refresh‑Token:

- JTI als einfacher String (`uuid`) im Body `refresh_token`.
- Gespeichert in `auth.tokens(kind = 'refresh')`.

---

3. Modul: identity (Login, Logout, Refresh, Me)
-----------------------------------------------

Datei: `src/modules/identity/routes.ts`

**POST /auth/login**

- Header:
  - `x-tenant-id: <tenant_uuid>`
- Body:
  - `email: string` – gültige E‑Mail
  - `password: string`
- Erfolg (200):
  - `access_token: string`
  - `access_expires_at: number` (Unix‑Sekunden)
  - `refresh_token: string` (JTI)
  - `refresh_expires_at: number`
  - `token_type: "bearer"`
  - `user: { id, email, ... }`
- Fehler:
  - 400: Body‑Validierung schlägt fehl.
  - 401: ungültige Credentials (immer generische Meldung).

**POST /auth/refresh**

- Header:
  - `x-tenant-id`
- Body:
  - `refresh_token: string`
- Erfolg (200):
  - `access_token, access_expires_at`
  - `refresh_token, refresh_expires_at`
  - `token_type: "bearer"`
- Fehler:
  - 400: Body‑Validierung
  - 401: ungültiges/abgelaufenes Refresh‑Token.

**GET /auth/me**

- Header:
  - `Authorization: Bearer <access_token>`
  - `x-tenant-id`
- Erfolg (200):
  - `sub: string` (User‑ID)
  - `cached: { id, email } | null` (aus Redis, wenn vorhanden)
  - `claims: { jti, exp, iat }`
- Fehler:
  - 401: fehlendes, ungültiges oder geblacklistetes Token.

**POST /auth/logout**

- Header:
  - `Authorization: Bearer <access_token>`
- Erfolg (200):
  - `{ ok: true }`  
    Access‑JTI wird mit TTL in Redis geblacklistet, Event `logout` in Redis‑Stream.
- Fehler:
  - 400: fehlendes oder ungültiges Token.

---

4. Modul: register (Registrierung)
----------------------------------

Datei: `src/modules/register/routes.ts`

**POST /auth/register**

- Header:
  - `x-tenant-id`
- Body:
  - `email: string`
  - `password: string` (8–72 Zeichen)
  - `tenant_name?: string` – optional, aktuell im Service noch nicht verwendet.
- Erfolg (201):
  - `user: { id: string; email: string; createdAt: Date }`
- Fehler:
  - 400: Body‑Validierung → `REGISTER_VALIDATION_FAILED`.
  - 400: E‑Mail bereits registriert → `REGISTER_NOT_POSSIBLE` (ohne zu verraten, dass die Adresse existiert).

**GET /auth/register/health**

- Erfolg:
  - 200/503
  - Body:
    - `module: "register"`
    - `healthy: boolean`
    - `db: { ok: boolean; error?: string | null }`

---

5. Modul: email-verify (E-Mail-Verifikation)
--------------------------------------------

Datei: `src/modules/email-verify/routes.ts`

**POST /auth/email/verify/request**

- Header:
  - `x-tenant-id`
- Body:
  - `email: string`
- Erfolg (200):
  - `{ ok: true, requestAccepted: boolean }`  
    Keine Aussage, ob E‑Mail existiert.
- Events:
  - Redis‑Stream `auth-events` mit:
    - `type: "email_verify_requested"`
    - `emailHash` (Base64‑Hash)
    - `status: "accepted" | "ignored"`.

**GET /auth/email/verify/confirm?token=...**

- Header:
  - `x-tenant-id`
- Query:
  - `token: string`
- Erfolg:
  - 200:
    - `{ verified: true, alreadyVerified: boolean, user: { id, email } }`
- Fehler (Business):
  - 400: `EMAIL_VERIFY_INVALID_TOKEN` (Token fehlt/ungültig).
  - 410: `EMAIL_VERIFY_TOKEN_EXPIRED`.
  - 200: `{ verified: true, alreadyVerified: true }` bei AlreadyVerified.

**GET /auth/email/verify/health**

- Erfolg:
  - 200/503, Body `module: "email-verify", healthy, db`.

---

6. Modul: password (Passwort vergessen / ändern)
------------------------------------------------

Datei: `src/modules/password/routes.ts`

**POST /auth/password/forgot**

- Header:
  - `x-tenant-id`
- Body:
  - `email: string`
- Erfolg (200):
  - `{ ok: true, requestAccepted: boolean }`
- Events:
  - `password_reset_requested` mit `emailHash`, `status`.

**POST /auth/password/reset**

- Header:
  - `x-tenant-id`
- Body:
  - `token: string`
  - `new_password: string` – neues Passwort (8–72 Zeichen).
- Erfolg (200):
  - `{ ok: true, user: { id, email } }`
- Fehler:
  - 400: `PASSWORD_RESET_INVALID_TOKEN`
  - 410: `PASSWORD_RESET_TOKEN_EXPIRED`

**POST /auth/password/change**

- Header:
  - `Authorization: Bearer <access_token>`
  - `x-tenant-id`
- Body:
  - `old_password: string`
  - `new_password: string`
- Erfolg (200):
  - `{ ok: true }`
- Fehler:
  - 400: `PASSWORD_CHANGE_WRONG_CURRENT_PASSWORD`
  - 401: `INVALID_TOKEN` bei JWT‑Fehlern
  - 400: Body‑Validierung

**GET /auth/password/health**

- Erfolg:
  - 200/503, Body `module: "password", healthy, db`.

---

7. Modul: magic-link (Passwortloser Login)
-----------------------------------------

Datei: `src/modules/magic-link/routes.ts`

**POST /auth/magic-link/request**

- Header:
  - `x-tenant-id`
- Body:
  - `email: string`
  - `redirect_uri?: string (URL)` – optional, aktuell noch nicht ausgewertet.
- Erfolg (200):
  - `{ ok: true, requestAccepted: boolean }`
- Events:
  - `magic_link_requested` mit `emailHash`, `status`.

**GET /auth/magic-link/consume?token=...**

- Header:
  - `x-tenant-id`
- Query:
  - `token: string`
- Erfolg (200):
  - `{ access_token, access_expires_at, refresh_token, refresh_expires_at, token_type: "bearer", user }`
- Fehler:
  - 400: `MAGIC_LINK_INVALID_TOKEN`
  - 410: `MAGIC_LINK_TOKEN_EXPIRED`

**GET /auth/magic-link/health**

- Erfolg:
  - 200/503, Body `module: "magic-link", healthy, db`.

---

8. Modul: otp (One-Time-Password / Codes)
-----------------------------------------

Datei: `src/modules/otp/routes.ts`

**POST /auth/otp/request**

- Header:
  - `x-tenant-id`
- Body:
  - `email: string`
- Erfolg (200):
  - `{ ok: true }`  
    OTP wird in DB gespeichert, Versand kann über Worker erfolgen.

**POST /auth/otp/verify**

- Header:
  - `x-tenant-id`
- Body:
  - `email: string`
  - `code: string` – 6‑stellig
- Erfolg (200):
  - `{ success: true, user: { id, email, tenantId } }`
- Fehler:
  - 400: Body‑Validierung
  - 401: `{ error: "invalid_or_expired_otp" }`

**GET /auth/otp/health**

- Erfolg:
  - 200/503, Body `module: "otp", healthy, db`.

---

9. Modul: sessions (Session-Management)
--------------------------------------

Datei: `src/modules/sessions/routes.ts`

**GET /auth/sessions?limit=...**

- Header:
  - `Authorization: Bearer <access_token>`
  - `x-tenant-id`
- Query:
  - `limit?: number` (1–100)
- Erfolg (200):
  - `{ sessions: Array<{ id, createdAt, expiresAt, ip, ua }> }`
- Fehler:
  - 400: Query‑Validierung
  - 401: `MISSING_TOKEN` oder `TOKEN_REVOKED`

**POST /auth/sessions/revoke**

- Header:
  - `Authorization: Bearer <access_token>`
  - `x-tenant-id`
- Body:
  - `session_id: string`
- Erfolg (200):
  - `{ revoked: boolean }` (idempotent)
- Fehler:
  - 400: Body‑Validierung
  - 401: fehlendes/ungültiges Token

**GET /auth/sessions/health**

- Erfolg:
  - 200/503, Body `module: "sessions", healthy, db`.

---

10. Modul: tenants (Mandanten)
------------------------------

Datei: `src/modules/tenants/routes.ts`

**GET /auth/tenants/me**

- Header:
  - `Authorization: Bearer <access_token>`
  - `x-tenant-id`
- Erfolg (200):
  - `{ tenant: { id, name, slug, createdAt, ... } }`
- Fehler:
  - 401: `MISSING_TOKEN` oder `TOKEN_REVOKED`

**GET /auth/tenants?limit=...**

- Header:
  - `Authorization: Bearer <access_token>`
  - `x-tenant-id`
- Query:
  - `limit?: number` (1–100)
- Erfolg (200):
  - `{ tenants: Tenant[] }` (unter RLS meist 1)
- Fehler:
  - 400: Query‑Validierung
  - 401: fehlendes/ungültiges Token

**GET /auth/tenants/health**

- Erfolg:
  - 200/503, Body `module: "tenants", healthy, db`.

*(Admin‑CRUD für Tenants ist aktuell nicht implementiert.)*

---

11. Modul: tokens (Token-Administration)
----------------------------------------

Datei: `src/modules/tokens/routes.ts`

**POST /auth/tokens/cleanup**

- Header:
  - `x-tenant-id`
- Body:
  - `kind: string` – wird intern als `TokenKind` interpretiert:
    `"refresh" | "reset" | "verify" | "otp" | "magic_link" | "other"`.
- Erfolg (200):
  - `{ ok: true }`
- Fehler:
  - 400: Body‑Validierung schlägt fehl.

**GET /auth/tokens/health**

- Erfolg (200):
  - `{ module: "tokens", ok: true }`

OIDC/OAuth‑Features wie JWKS, Token‑Introspection und Token‑Revocation sind noch nicht umgesetzt, können aber später in diesem Modul ergänzt werden.

---

12. Tests & Happy Paths
-----------------------

Tests sind in zwei Modi getrennt:

- **Unit** (`src/tests/unit`)
  - laufen ohne DB/Redis-Infrastruktur
- **E2E HTTP** (`src/tests/http`)
  - laufen mit realer PostgreSQL/Redis-Infrastruktur via `docker-compose.test.yml`

E2E‑Tests decken u.a. ab:

- **Health & Infrastruktur**
  - `health.test.ts`: `/health`, `/health/db`, `/health/redis`.

- **Fehlerfälle pro Modul**
  - `login.test.ts`, `register.test.ts`, `email-verify.test.ts`, `password.test.ts`,
    `magic-link.test.ts`, `otp.test.ts`, `sessions.test.ts`, `tenants.test.ts`,
    `tokens.test.ts`.

- **Happy Path**
  - `auth-flow.test.ts`:
    - legt per SQL einen Tenant `auth-flow` und einen User in `auth.users` an,
    - testet `POST /auth/login` + `GET /auth/me` mit echtem DB‑Zugriff und Token.

Lokale Ausführung:

- `make check` → lint + typecheck + unit-tests + secret-scan
- `make test-e2e` → e2e-suite (setzt laufende `postgres-test` + `redis-test` voraus)
- `make gold` → `check` + compose-basierte E2E-Infrastruktur + E2E-Tests + teardown
