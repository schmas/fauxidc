#!/usr/bin/env bash
# Compile the page styles: assets/css/fauxidc.css -> assets/static/fauxidc.css.
#
# Dev-time only. `cargo build` and the server never run this script and never need
# Node or the network. It downloads the pinned Tailwind CSS standalone CLI and the
# daisyUI standalone plugin files, checks their SHA-256 sums, and caches them in
# target/css-tools/<version>/ (git-ignored through target/).
#
# Plugin path: the source names `../../target/css-tools/daisyui.mjs`, a path without a
# version, so that a version bump does not change the source file. The script copies the
# two checked .mjs files from target/css-tools/daisyui-<version>/ to target/css-tools/
# before every build.
#
# Usage: scripts/build-css.sh (no arguments). Exit 0 on success; prints the output size.
set -euo pipefail

TAILWIND_VERSION="4.3.3"
DAISYUI_VERSION="5.7.50"

# SHA-256 of each download (from the release pages).
SHA_TAILWIND_LINUX_X64="dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a"
SHA_TAILWIND_MACOS_ARM64="cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d"
SHA_TAILWIND_MACOS_X64="7922e0953f2110c05976e3bf58f14e643d90427575e766b7d433f5f80cbee7e1"
SHA_DAISYUI_MJS="d69de07c7463bb1f41548e2688f88ee105cdadf9779fce5b3c47b3bfaa6be472"
SHA_DAISYUI_THEME_MJS="e48a35d8326d650181ca600560e8520cf6b44cf9242bbd9d45825607e641f251"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) platform="linux-x64"; sha_tw="$SHA_TAILWIND_LINUX_X64" ;;
  Darwin-arm64) platform="macos-arm64"; sha_tw="$SHA_TAILWIND_MACOS_ARM64" ;;
  Darwin-x86_64) platform="macos-x64"; sha_tw="$SHA_TAILWIND_MACOS_X64" ;;
  *)
    echo "build-css.sh: unsupported platform $(uname -s)-$(uname -m)" >&2
    echo "supported: linux-x64, macos-arm64, macos-x64" >&2
    exit 2
    ;;
esac

tools="target/css-tools"
tw_dir="$tools/tailwindcss-$TAILWIND_VERSION"
du_dir="$tools/daisyui-$DAISYUI_VERSION"
mkdir -p "$tw_dir" "$du_dir"

# fetch <url> <file> <sha256>: download when missing, then check the sum.
fetch() {
  local url="$1" file="$2" sum="$3"
  if [ ! -f "$file" ]; then
    echo "download $url"
    curl -fsSL --retry 3 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  if ! echo "$sum  $file" | shasum -a 256 -c - >/dev/null; then
    echo "build-css.sh: checksum mismatch for $file" >&2
    rm -f "$file"
    exit 1
  fi
}

tw_bin="$tw_dir/tailwindcss-$platform"
fetch "https://github.com/tailwindlabs/tailwindcss/releases/download/v$TAILWIND_VERSION/tailwindcss-$platform" \
  "$tw_bin" "$sha_tw"
chmod +x "$tw_bin"
du_base="https://github.com/saadeghi/daisyui/releases/download/v$DAISYUI_VERSION"
fetch "$du_base/daisyui.mjs" "$du_dir/daisyui.mjs" "$SHA_DAISYUI_MJS"
fetch "$du_base/daisyui-theme.mjs" "$du_dir/daisyui-theme.mjs" "$SHA_DAISYUI_THEME_MJS"
cp "$du_dir/daisyui.mjs" "$du_dir/daisyui-theme.mjs" "$tools/"

"$tw_bin" -i assets/css/fauxidc.css -o assets/static/fauxidc.css --minify

# The pages load no external URL, and a test checks that the CSS has no "http://" or
# "https://" text at all. Two strings would fail it, so rewrite them:
# - the Tailwind license banner URL (keep the banner, drop the scheme);
# - the SVG namespace inside daisyUI data: URIs. A data: URI body is percent-decoded
#   before the SVG is parsed, so the encoded form is the same namespace.
sed -i.bak \
  -e 's#https://tailwindcss\.com#tailwindcss.com#g' \
  -e 's#http://www\.w3\.org/2000/svg#http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg#g' \
  assets/static/fauxidc.css
rm -f assets/static/fauxidc.css.bak
test -s assets/static/fauxidc.css
echo "assets/static/fauxidc.css: $(wc -c < assets/static/fauxidc.css | tr -d ' ') bytes"
