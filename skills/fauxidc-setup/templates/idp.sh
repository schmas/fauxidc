#!/usr/bin/env bash
# Local OpenID Connect provider (fauxidc).
# Usage: ./idp.sh up | down | status | logs | token <user> | check
# `token` mints tokens for the app Client id with the Test API. Copy the id_token into $ISSUER_URL/debugger.
set -euo pipefail
cd "$(dirname "$0")"

BASE_URL="http://localhost:{{port}}"
ISSUER_URL="$BASE_URL/{{issuer_id}}"

usage() {
  echo "usage: $0 up | down | status | logs | token <user> | check" >&2
  exit 2
}

case "${1:-}" in
  up)
    docker compose up -d --wait
    for _ in $(seq 1 30); do
      if curl -fsS "$ISSUER_URL/.well-known/openid-configuration" >/dev/null 2>&1; then
        echo "fauxidc is ready: $ISSUER_URL"
        exit 0
      fi
      sleep 1
    done
    echo "fauxidc did not answer at $ISSUER_URL. Run: $0 logs" >&2
    exit 1
    ;;
  down)
    docker compose down
    ;;
  status)
    docker compose ps
    curl -fsS "$BASE_URL/_mock/health" && echo
    ;;
  logs)
    docker compose logs -f fauxidc
    ;;
  token)
    user="${2:-}"
    [ -n "$user" ] || usage
    curl -fsS "$BASE_URL/_mock/{{issuer_id}}/token" \
      -H 'content-type: application/json' \
      -d "{\"user\": \"$user\", \"client_id\": \"{{client_id}}\"}"
    echo
    ;;
  check)
    docker compose run --rm --no-deps fauxidc config --check
    ;;
  *)
    usage
    ;;
esac
