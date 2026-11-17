#!/usr/bin/env bash
# Rebuilds the README media in docs/media/: the terminal GIF, the browser GIFs and the screenshots.
#
# Usage: scripts/readme-media.sh
#
# The script builds fauxidc, records docs/media/terminal.tape with vhs (the tape starts and stops
# its own server), then starts fauxidc with docs/media/fauxidc.toml (fixed clock) and runs
# scripts/readme-media.mjs (Playwright). It stops the server at the end.
#
# Needs: cargo, node, ffmpeg, jq, vhs (brew install vhs). gifski is optional (brew install gifski);
# without it, ffmpeg makes the GIFs. Playwright comes from e2e/spa/node_modules (npm ci).
#
# The media show port 9000. If port 9000 is in use, FAUXIDC_MEDIA_PORT=<port> runs the server on
# another port. The pages and commands still show port 9000, but the fauxidc log line shows the other port.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT="${FAUXIDC_MEDIA_PORT:-9000}"
APP_PORT=5180
MEDIA=docs/media
CONFIG="$MEDIA/fauxidc.toml"
TAPE="$MEDIA/terminal.tape"

fail() {
  echo "error: $*" >&2
  exit 1
}

for tool in cargo node ffmpeg jq vhs; do
  command -v "$tool" >/dev/null || fail "$tool is not installed"
done
command -v gifski >/dev/null || echo "note: gifski is not installed; ffmpeg makes the GIFs"

port_busy() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN -t >/dev/null 2>&1
}
for p in "$PORT" "$APP_PORT"; do
  if port_busy "$p"; then
    fail "port $p is in use (lsof -nP -iTCP:$p -sTCP:LISTEN). Stop that process and run the script again."
  fi
done

if [ ! -d e2e/spa/node_modules/@playwright/test ]; then
  echo "installing the Playwright dependencies (e2e/spa)"
  (cd e2e/spa && npm ci)
fi

cargo build --quiet

work="$(mktemp -d)"
server_pid=""
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

# With another port, the server listens there, but the Issuer URLs stay on port 9000.
# The tape then uses a copy that sends its curl calls to that port, and the browser maps the port.
if [ "$PORT" != 9000 ]; then
  export FAUXIDC__SERVER__PORT="$PORT"
  # Before the first Show: a hidden curl wrapper that changes ":9000" to ":$PORT" in its arguments.
  awk -v port="$PORT" '!done && $0 == "Show" {
    print "Type `curl() { command curl \"${@//:9000/:" port "}\"; }`"
    print "Enter"
    print "Type \"clear\""
    print "Enter"
    done = 1
  } { print }' "$TAPE" >"$work/terminal.tape"
  TAPE="$work/terminal.tape"
fi

rm -f "$MEDIA"/*.gif "$MEDIA"/*.png

echo "recording $MEDIA/terminal.gif"
vhs --quiet "$TAPE"
port_busy "$PORT" && fail "the server of the tape still runs on port $PORT"

echo "starting fauxidc on port $PORT"
./target/debug/fauxidc --config "$CONFIG" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 100); do
  if curl -sf "http://localhost:$PORT/_mock/health" 2>/dev/null | grep -q '"ready"'; then
    break
  fi
  kill -0 "$server_pid" 2>/dev/null || {
    cat "$work/server.log" >&2
    fail "fauxidc stopped at startup"
  }
  sleep 0.2
done
curl -sf "http://localhost:$PORT/_mock/health" | grep -q '"ready"' || fail "fauxidc is not ready after 20 s"

FAUXIDC_MEDIA_PORT="$PORT" node scripts/readme-media.mjs "$MEDIA"

echo "media in $MEDIA:"
ls -l "$MEDIA"/*.gif "$MEDIA"/*.png
for gif in "$MEDIA"/*.gif; do
  size=$(wc -c <"$gif")
  [ "$size" -lt 2097152 ] || fail "$gif is larger than 2 MB ($size bytes)"
done
