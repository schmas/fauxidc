#!/usr/bin/env bash
# Check the page styles in assets/static/. They are plain CSS without a build step
# (docs/adr/0009-plain-css-halo-stylesheet.md).
#
# - halo.css: every built-in page links it. Under 24 KB.
# - dashboard.css: the dashboard shell on top of halo.css. Under 16 KB.
# - fauxidc.css and login.css: old stylesheets, frozen. No built-in page links them;
#   they stay served for old custom templates. A change to them fails the check.
# - No stylesheet loads anything from the network.
#
# Usage: scripts/check-css.sh (no arguments). Exit 1 with one line per failed check.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root/assets/static"

fail=0
err() { echo "check-css.sh: $*" >&2; fail=1; }

# max_size <file> <bytes>
max_size() {
  local size
  size="$(wc -c < "$1" | tr -d ' ')"
  echo "$1: $size bytes (limit $2)"
  [ "$size" -lt "$2" ] || err "$1 is $size bytes, limit $2"
}

max_size halo.css 24576
max_size dashboard.css 16384
max_size fauxidc.css 61440

for f in *.css; do
  for bad in "http://" "https://" "url(//" "@import"; do
    if grep -qF -- "$bad" "$f"; then err "$f contains $bad"; fi
  done
done

# The frozen files: SHA-256 of the last generated fauxidc.css and of login.css.
frozen() {
  echo "$2  $1" | shasum -a 256 -c - >/dev/null 2>&1 || err "$1 changed; it is frozen"
}
frozen fauxidc.css "64721587f3499d6637b06b32063263be1f41c15c45652ca22b478ac6bdfd717f"
frozen login.css "7bf3a8c568ddbaa27a6bf6cb43e6b20f78ce22c3e246eb8a0cae6703c7b605b3"

exit "$fail"
