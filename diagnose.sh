#!/usr/bin/env bash
set -euo pipefail

echo "================================================="
echo " DIAGNOSE-SCRIPT – READ ONLY"
echo " Verzeichnis: $(pwd)"
echo " Zeitpunkt:   $(date)"
echo "================================================="

section () {
  echo
  echo "-------------------------------------------------"
  echo " $1"
  echo "-------------------------------------------------"
}

# -------------------------------------------------
section "A1) Wichtige Dateien – Kopf (1–200)"

for f in README.md docker-compose.yml docker-compose.dev.yml Dockerfile Makefile package.json tsconfig.json; do
  if [ -f "$f" ]; then
    echo
    echo "### $f"
    sed -n '1,200p' "$f"
  else
    echo "### $f (nicht vorhanden)"
  fi
done

# -------------------------------------------------
section "A2) Makefile – Targets & Kommandos"

if [ -f Makefile ]; then
  grep -nE '^[a-zA-Z0-9_-]+:|^\t' Makefile | sed -n '1,200p'
else
  echo "Kein Makefile vorhanden"
fi

# -------------------------------------------------
section "A3) NPM Scripts"

if [ -f package.json ]; then
  node -p "Object.keys(require('./package.json').scripts||{})"
  sed -n '1,160p' package.json
else
  echo "Kein package.json vorhanden"
fi

# -------------------------------------------------
section "A4) ENV-Dateien (nur Keys, Secrets redacted)"

for env in .env.example .env.prod .env; do
  if [ -f "$env" ]; then
    echo
    echo "### $env"
    grep -nE '^[A-Z0-9_]+=' "$env" | sed 's/=.*$/=***REDACTED***/'
  fi
done

# -------------------------------------------------
section "A5) Entry-Points & Serverstarts im Code"

if [ -d src ]; then
  grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
    -E "(listen\(|createServer|fastify\(|app\.listen|server\.listen|main\(|bootstrap\()" src | head -80
else
  echo "Kein src/-Verzeichnis"
fi

# -------------------------------------------------
section "A6) Ports & URLs im Code"

if [ -d src ]; then
  grep -RIn --exclude-dir=node_modules --exclude-dir=dist \
    -E "(PORT|localhost|0\.0\.0\.0|http://|https://)" src | head -120
fi

# -------------------------------------------------
section "B1) Docker – laufende Container"

if command -v docker >/dev/null 2>&1; then
  docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
else
  echo "Docker nicht installiert"
fi

# -------------------------------------------------
section "B2) Docker Compose – Status"

if command -v docker >/dev/null 2>&1; then
  docker compose ps || true
  if [ -f docker-compose.dev.yml ]; then
    docker compose -f docker-compose.dev.yml ps || true
  fi
fi

# -------------------------------------------------
section "B3) Docker Logs (letzte 200 Zeilen)"

if command -v docker >/dev/null 2>&1; then
  docker compose logs --tail=200 || true
fi

# -------------------------------------------------
section "B4) Offene Ports (Server)"

if command -v ss >/dev/null 2>&1; then
  sudo ss -lntp
fi

# -------------------------------------------------
section "B5) Prozesse – CPU & RAM"

ps aux --sort=-%cpu | head -25
ps aux --sort=-%mem | head -25

# -------------------------------------------------
section "B6) Node-relevante Prozesse"

ps aux | grep -E 'node|tsx|ts-node|pm2|nest|fastify' | grep -v grep || true

# -------------------------------------------------
section "C1) systemd – laufende Services"

systemctl --type=service --state=running | head -60 || true

# -------------------------------------------------
section "C2) systemd – Suche nach Projektbegriffen"

systemctl list-units --type=service | grep -Ei 'auth|profile|redis|nginx|docker' || true

# -------------------------------------------------
section "C3) Docker Restart Policies"

if command -v docker >/dev/null 2>&1; then
  docker inspect -f '{{.Name}} -> RestartPolicy={{.HostConfig.RestartPolicy.Name}}' \
    $(docker ps -q) 2>/dev/null || true
fi

# -------------------------------------------------
section "D1) package.json – Start Commands"

if [ -f package.json ]; then
  node -p "require('./package.json').scripts"
fi

# -------------------------------------------------
section "D2) Dependencies"

if [ -f package.json ]; then
  node -p "Object.keys(require('./package.json').dependencies||{})"
  node -p "Object.keys(require('./package.json').devDependencies||{})"
fi

# -------------------------------------------------
section "D3) Docker Compose – definierte Services"

if [ -f docker-compose.yml ]; then
  docker compose -f docker-compose.yml config --services
fi

if [ -f docker-compose.dev.yml ]; then
  docker compose -f docker-compose.dev.yml config --services
fi

# -------------------------------------------------
section "D4) Docker Compose – finale Konfiguration"

if [ -f docker-compose.yml ]; then
  docker compose -f docker-compose.yml config
fi

echo
echo "================================================="
echo " DIAGNOSE BEENDET"
echo "================================================="
