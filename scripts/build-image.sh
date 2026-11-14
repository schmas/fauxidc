#!/usr/bin/env bash
# Build the musl release binary for the host arch and a local scratch image.
# Usage: scripts/build-image.sh [tag]   (default tag: fauxidc:dev)
set -euo pipefail

tag="${1:-fauxidc:dev}"
cd "$(dirname "$0")/.."

case "$(uname -m)" in
  x86_64 | amd64) rust_arch=x86_64; docker_arch=amd64 ;;
  aarch64 | arm64) rust_arch=aarch64; docker_arch=arm64 ;;
  *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

target="${rust_arch}-unknown-linux-musl"
cargo zigbuild --release --target "$target"

mkdir -p "dist/${docker_arch}"
cp "target/${target}/release/fauxidc" "dist/${docker_arch}/fauxidc"

docker build --build-arg TARGETARCH="$docker_arch" -t "$tag" .
