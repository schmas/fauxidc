# 5. Sign tokens on the blocking pool

Date: 2026-11-15
Status: accepted

## Context

The server runs on a tokio `current_thread` runtime (spec 13.2). Up to v0.1.0, every JWT is signed on that thread.
One RS256 signature with the pure-Rust `rsa` crate (RSA 2048) takes about 1.9 ms of CPU, so the server signs on one core only.
A 2-CPU container served about 470 `client_credentials` tokens/s. A mock server on the JVM, which signs on many worker threads, served about 1,100.

A higher `opt-level` does not help. A release build at `opt-level = 3` signs RS256 in the same 1.9 ms as at `"z"`.
The cost is the constant-time bignum math in `rsa` 0.10, not the build profile.

## Decision

- `tokens::sign_jwt` signs on the tokio blocking pool with `spawn_blocking`. The ID token, access token and refresh token signers all use it, so they are `async`.
- The task clones the `EncodingKey` (about 1 KB), because it needs owned data.
- The binary caps the blocking pool at one thread per CPU, two at least (`main.rs`). Two threads let a key generation run without stopping signing.
- The runtime stays `current_thread`. Request handling, the `Store` and the `std::sync::Mutex` state do not change.
- The release profile keeps `opt-level = "z"`. Only `p256` gets `opt-level = 3`, because ES256 signing is 1.7x faster with it (311 µs to 177 µs).

## Rejected options

- A `multi_thread` runtime. It reverses the spec choice and adds lock contention on the shared state, but only signing needs more cores.
- `aws-lc-rs` or `ring` for RSA. Both need a C toolchain, and the default build has no C code.
- `opt-level = 3` for `rsa` and its crates. It made no measurable change (see Context).

## Consequences

Measured on Apple Silicon with `oha`, `client_credentials` grant, examples/generic.toml:

| Setup | Before (tokens/s, p50) | After (tokens/s, p50) |
|---|---|---|
| Docker, 2 CPUs, 1 GB, 50 connections | 467, 82 ms (p99 198 ms) | 840, 59 ms (p99 72 ms) |
| Native, 10 CPUs, 16 connections | 497, 32 ms | 3,809, 3.9 ms |

- Throughput scales with the CPU count. The musl x86_64 binary grows from 4,285,600 to 4,362,184 bytes.
- Peak memory under load stays near 5 MiB.
- An embedder that calls `Server::start` on its own runtime also signs on that runtime's blocking pool.
- `tests/signing_speed.rs` (ignored by default) measures one signature per algorithm in a release build.
