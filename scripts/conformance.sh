#!/usr/bin/env bash
# Runs the OpenID Foundation conformance suite plans "Basic OP" and "Config OP" against
# fauxidc. Needs Docker (with Compose), git, curl, python3 and cargo. See conformance/README.md.
#
# Exit code: the exit code of the suite's run-test-plan.py, or 1 if the setup fails.
set -euo pipefail

SUITE_TAG="${SUITE_TAG:-release-v5.3.4}"
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
SUITE_URL="https://localhost.emobix.co.uk:8443/"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE_DIR="$ROOT/target/conformance-suite"
VENV="$ROOT/target/conformance-venv"
RESULTS="$ROOT/target/conformance-results"
LOG="$ROOT/target/conformance-fauxidc.log"
export FAUXIDC_CONFORMANCE_DIR="$ROOT/conformance"

compose() {
  (cd "$SUITE_DIR" && IMAGE_TAG="$SUITE_TAG" docker compose \
    -f docker-compose-prebuilt.yml \
    -f "$FAUXIDC_CONFORMANCE_DIR/docker-compose.override.yml" "$@")
}

FAUXIDC_PID=""
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  local code=$?
  if [[ -n "$FAUXIDC_PID" ]]; then
    kill "$FAUXIDC_PID" 2>/dev/null || true
    wait "$FAUXIDC_PID" 2>/dev/null || true
  fi
  if [[ -d "$SUITE_DIR" ]]; then
    compose down -v >/dev/null 2>&1 || true
  fi
  exit "$code"
}
trap cleanup EXIT

# 1. The suite checkout at the pinned tag.
if [[ -d "$SUITE_DIR" ]] && [[ "$(git -C "$SUITE_DIR" describe --tags --exact-match 2>/dev/null)" != "$SUITE_TAG" ]]; then
  echo "conformance: suite checkout is not at $SUITE_TAG, cloning again"
  rm -rf "$SUITE_DIR"
fi
if [[ ! -d "$SUITE_DIR" ]]; then
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$SUITE_TAG" "$SUITE_REPO" "$SUITE_DIR"
fi

# 2. The suite (Mongo, server, nginx) and the Caddy TLS front.
echo "conformance: starting the suite $SUITE_TAG"
compose up -d --quiet-pull

# 3. fauxidc on the host. Build first, so that the health wait does not include the build.
cargo build --quiet --manifest-path "$ROOT/Cargo.toml"
"$ROOT/target/debug/fauxidc" --config "$FAUXIDC_CONFORMANCE_DIR/fauxidc.toml" >"$LOG" 2>&1 &
FAUXIDC_PID=$!
deadline=$((SECONDS + 30))
until curl -sf -o /dev/null http://127.0.0.1:9000/_mock/health; do
  if ! kill -0 "$FAUXIDC_PID" 2>/dev/null || ((SECONDS >= deadline)); then
    echo "conformance: fauxidc did not become healthy within 30 s; its log:" >&2
    cat "$LOG" >&2
    exit 1
  fi
  sleep 1
done
echo "conformance: fauxidc is healthy"

# 4. The suite API.
deadline=$((SECONDS + 120))
until curl -sfk -o /dev/null "${SUITE_URL}api/runner/available"; do
  if ((SECONDS >= deadline)); then
    echo "conformance: the suite did not start within 120 s" >&2
    compose logs --tail 100 server >&2 || true
    exit 1
  fi
  sleep 2
done
echo "conformance: the suite is available"

# 5. The TLS path from inside the suite network.
discovery="$(compose exec -T fauxidc-tls wget -qO- --no-check-certificate \
  https://fauxidc/conformance/.well-known/openid-configuration)" || discovery=""
if [[ "$discovery" != *'"issuer":"https://fauxidc/conformance"'* ]]; then
  echo "conformance: https://fauxidc does not serve the fauxidc discovery document:" >&2
  echo "$discovery" >&2
  compose logs --tail 50 fauxidc-tls >&2 || true
  exit 1
fi
echo "conformance: the TLS front works"

# 6. The test plans. The install runs every time, so an older venv gets the pinned set.
if [[ ! -x "$VENV/bin/python3" ]]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --disable-pip-version-check -r "$FAUXIDC_CONFORMANCE_DIR/requirements.txt"
rm -rf "$RESULTS"
mkdir -p "$RESULTS"
set +e
(cd "$SUITE_DIR" && CONFORMANCE_SERVER="$SUITE_URL" CONFORMANCE_DEV_MODE=1 \
  "$VENV/bin/python3" scripts/run-test-plan.py \
  --expected-failures-file "$FAUXIDC_CONFORMANCE_DIR/expected-failures.json" \
  --expected-skips-file "$FAUXIDC_CONFORMANCE_DIR/expected-skips.json" \
  --export-dir "$RESULTS" \
  --verbose \
  'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]' \
  "$FAUXIDC_CONFORMANCE_DIR/basic.json" \
  oidcc-config-certification-test-plan \
  "$FAUXIDC_CONFORMANCE_DIR/config-op.json")
code=$?
set -e
cp "$LOG" "$RESULTS/fauxidc.log" 2>/dev/null || true
echo "conformance: run-test-plan.py exited with $code"
exit "$code"
