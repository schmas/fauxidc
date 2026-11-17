# Footprint

fauxidc is written in Rust. It is one binary with no runtime dependencies, and it uses little memory and starts fast.
This page gives measured numbers and the commands to measure them again.

## Measured numbers

Measured on 2026-11-17 with fauxidc 0.6.0 on macOS 27.2 arm64 (Apple M1 Pro), Rust 1.100.0.
The server ran in Zero config (one Issuer `default`, Users `alice` and `bob`).

| What | Value | How |
| --- | --- | --- |
| Release binary (`aarch64-apple-darwin`) | 3.3 MB (3 320 496 bytes) | `cargo build --release`, size of `target/release/fauxidc` |
| Container image `ghcr.io/schmas/fauxidc:0.6.0` (linux/arm64) | 6.3 MB (6 329 426 bytes) | `docker image inspect --format '{{.Size}}'` |
| Startup to the first `"key":"ready"` health answer | median 53 ms, range 27 to 589 ms (5 runs) | Time from process start to `GET /_mock/health` with `"key":"ready"` |
| Memory (RSS) at idle, 1 s after startup | median 5.6 MiB (5 776 KiB, 5 runs) | `ps -o rss= -p <pid>` |
| Memory (RSS) after 100 token requests | median 5.9 MiB (6 064 KiB, 5 runs) | 100 requests to `POST /_mock/default/token`, then `ps -o rss=` |

The first run was the slowest (589 ms). The other four runs took 27 to 93 ms.
The startup time includes the generation of the RSA signing key.
Other platforms and versions give other numbers.

## Measure again

Build the release binary and show its size:

```sh
cargo build --release
ls -l target/release/fauxidc
```

Show the size of the published image:

```sh
docker pull ghcr.io/schmas/fauxidc:0.6.0
docker image inspect ghcr.io/schmas/fauxidc:0.6.0 --format '{{.Size}}'
```

Measure startup time and memory. This uses port 9200, so it does not touch a server on port 9000:

```sh
start=$(python3 -c 'import time; print(time.time())')
./target/release/fauxidc --port 9200 >/dev/null 2>&1 &
pid=$!
until curl -sf http://localhost:9200/_mock/health | grep -q '"ready"'; do sleep 0.002; done
python3 -c "import time; print(f'startup: {(time.time() - $start) * 1000:.0f} ms')"
sleep 1
echo "idle RSS: $(ps -o rss= -p $pid) KiB"
for i in $(seq 100); do
  curl -s http://localhost:9200/_mock/default/token --json '{"user": "alice"}' >/dev/null
done
echo "RSS after 100 tokens: $(ps -o rss= -p $pid) KiB"
kill $pid
```
