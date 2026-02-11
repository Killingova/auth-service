SHELL := /bin/bash
COMPOSE ?= docker compose
TEST_COMPOSE ?= docker compose -f docker-compose.test.yml

E2E_DB_HOST ?= 127.0.0.1
E2E_DB_PORT ?= 55433
E2E_DB_USER ?= postgres
E2E_DB_NAME ?= authdb
E2E_DB_PASSWORD ?= postgres

E2E_REDIS_HOST ?= 127.0.0.1
E2E_REDIS_PORT ?= 56379
E2E_REDIS_USERNAME ?= default
E2E_REDIS_PASSWORD ?= redis-test

SVC_PROD := auth-service
SVC_DEV  := auth-service

.PHONY: prod-up prod-down prod-recreate prod-build prod-ps prod-logs prod-health prod-cid \
	dev-up dev-down dev-recreate dev-build dev-ps dev-logs \
	ps logs env-show clean-orphans lint typecheck test test-unit test-e2e e2e-up e2e-down e2e-reset e2e-wait housekeeping secret-scan check gold

prod-up:
	$(COMPOSE) up -d --build

prod-down:
	$(COMPOSE) down --remove-orphans

prod-recreate:
	$(COMPOSE) up -d --force-recreate

prod-build:
	$(COMPOSE) build

prod-ps:
	$(COMPOSE) ps

prod-cid:
	@$(COMPOSE) ps -q | head -n 1

prod-logs:
	$(COMPOSE) logs -f $(SVC_PROD)

prod-health:
	@CID="$$( $(COMPOSE) ps -q | head -n 1 )"; \
	if [ -z "$$CID" ]; then echo "(!) kein PROD-Container gefunden"; exit 1; fi; \
	echo "CID=$$CID"; \
	docker exec -it "$$CID" sh -lc 'for p in /healthz /readyz /health/redis /health/db /health; do echo "== $$p =="; wget -qO- -S "http://127.0.0.1:3000$$p" 2>&1 | head -n 60 || true; echo; done'

dev-up:
	$(COMPOSE) up -d

dev-down:
	$(COMPOSE) down --remove-orphans

dev-recreate:
	$(COMPOSE) up -d --force-recreate

dev-build:
	$(COMPOSE) build

dev-ps:
	$(COMPOSE) ps

dev-logs:
	$(COMPOSE) logs -f $(SVC_DEV)

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f

clean-orphans:
	$(COMPOSE) down --remove-orphans

env-show:
	@for f in .env .env.prod; do \
	  if [ -f "$$f" ]; then echo "---- $$f ----"; sed -n "1,200p" "$$f"; echo; \
	  else echo "(!) $$f fehlt"; fi; \
	done

lint:
	@if npm run | grep -q "  lint"; then npm run lint; else echo "(i) lint script not defined, skip"; fi

typecheck:
	npm run typecheck

test:
	$(MAKE) test-unit

test-unit:
	npm run test:unit

e2e-up:
	$(TEST_COMPOSE) up -d --build

e2e-down:
	$(TEST_COMPOSE) down -v --remove-orphans

e2e-reset: e2e-down e2e-up

e2e-wait:
	@set -euo pipefail; \
	db_cid="$$( $(TEST_COMPOSE) ps -q postgres-test )"; \
	redis_cid="$$( $(TEST_COMPOSE) ps -q redis-test )"; \
	if [ -z "$$db_cid" ] || [ -z "$$redis_cid" ]; then \
	  echo "E2E containers are not running."; \
	  exit 1; \
	fi; \
	for i in $$(seq 1 180); do \
	  db_status="$$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$$db_cid")"; \
	  redis_status="$$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$$redis_cid")"; \
	  if [ "$$db_status" = "healthy" ] && [ "$$redis_status" = "healthy" ]; then \
	    echo "E2E infra ready (postgres-test + redis-test)."; \
	    exit 0; \
	  fi; \
	  sleep 1; \
	done; \
	echo "Timed out waiting for E2E infra."; \
	exit 1

test-e2e: e2e-wait
	@DATABASE_URL="postgresql://$(E2E_DB_USER):$(E2E_DB_PASSWORD)@$(E2E_DB_HOST):$(E2E_DB_PORT)/$(E2E_DB_NAME)" \
	REDIS_URL="redis://$(E2E_REDIS_USERNAME):$(E2E_REDIS_PASSWORD)@$(E2E_REDIS_HOST):$(E2E_REDIS_PORT)" \
	REDIRECT_ALLOWLIST="https://app.example.test" \
	NODE_ENV=test \
	npm run test:e2e

housekeeping:
	npm run housekeeping

secret-scan:
	@echo "Running lightweight secret scan..."
	@! rg -n --hidden --glob '!node_modules' --glob '!dist' --glob '!.git' \
	  --glob '!Makefile' --glob '!.env.example' --glob '!.env.disabled' --glob '!src/tests/**' --glob '!docker/e2e/secrets/**' --glob '!_local/**' --glob '!docker-compose.yml' \
	  "(JWT_SECRET\\s*=\\s*[^\\s#]+|postgres(?:ql)?://[^\\s$$]+:[^\\s$$]+@|redis://[^\\s$$]+:[^\\s$$]+@|BEGIN PRIVATE KEY|-----BEGIN [A-Z ]*PRIVATE KEY-----)" .

check: lint typecheck test secret-scan

gold:
	@set -euo pipefail; \
	$(MAKE) check; \
	$(MAKE) e2e-reset; \
	trap '$(MAKE) e2e-down >/dev/null 2>&1 || true' EXIT; \
	$(MAKE) test-e2e
