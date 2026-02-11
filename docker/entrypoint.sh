#!/usr/bin/env sh
set -eu

if [ -n "${DATABASE_URL_FILE:-}" ] && [ -r "${DATABASE_URL_FILE}" ]; then
  export DATABASE_URL="$(cat "${DATABASE_URL_FILE}")"
fi

# optional: redis password file -> env, falls Code es erwartet
if [ -n "${REDIS_PASSWORD_FILE:-}" ] && [ -r "${REDIS_PASSWORD_FILE}" ]; then
  export REDIS_PASSWORD="$(cat "${REDIS_PASSWORD_FILE}")"
fi

exec "$@"
