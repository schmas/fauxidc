# AGENTS.md

This file provides guidance to coding agents (Claude Code, Codex and others) when working with code in this repository.

## Project Overview

fauxidc is a small OAuth 2.0 / OpenID Connect mock server for local development and integration tests.
It is a single static binary with no external infrastructure. It must never be used in production.
The repo is public: use neutral names only (`example-app`, `alice@example.com`, `http://localhost:9000/auth0/`).

**Further reading:** `docs/spec.md` (approved spec), `GLOSSARY.md` (domain terms), `docs/adr/`.

## Stack

| Domain | Crate |
|---|---|
| Runtime | `tokio` (`current_thread`) |
| HTTP | `axum` 0.8, `tower-http` |
| JWT | `jsonwebtoken` with `rust_crypto` (not `aws_lc_rs`) |
| Keys | `rsa`, `p256` |
| Data | `serde`, `serde_json`, `toml` |
| Templates | `minijinja`, `rust-embed` |
| CLI | `clap` derive |
| Logs | `tracing`, `tracing-subscriber` |
| Errors | `thiserror` v2 (lib), `anyhow` (`main.rs` only) |
| IDs, random | `uuid` v4 (`jti`, `sid`), `rand` / `getrandom` |
| Statics | `std::sync::LazyLock` |
| Time | `std::time` (Unix seconds only) |
| Locks | `std::sync::Mutex` |
| Hot reload (M3) | `arc-swap` |
| TLS (M3, optional) | `rustls` (ring) |
| Dev only | `reqwest`, `openidconnect` |

Rejected, with reason:

- `figment` / `config`: they do not meet the config validation and source rules. See `docs/adr/0002-own-layered-config-merge.md`.
- `jiff`: no date formatting needed. Add it if `/debugger` needs one.
- `color-eyre` / `miette`: the main user errors are config errors, and `toml` already prints them with spans. Use `miette` for config only if those errors read poorly.
- `parking_lot` / `dashmap`: there is no contention on a `current_thread` runtime.
- `dotenvy`: docker-compose already reads `.env`. A mock that reads `.env` on its own is surprising.
- `utoipa`: the Test API is small. The README documents it.
- YAML crates: no maintained standard crate.
- `josekit`, `openssl`, `aws-lc-rs`: C toolchain, no clean musl static build.
- `cargo-dist`: our own release workflow is small.

A new dependency needs a reason in the PR.

Toolchain: Rust edition 2024, pinned in `rust-toolchain.toml`. MSRV is stable minus 2 (`rust-version` in `Cargo.toml`).

## Commands

```bash
# Build / run
cargo build
cargo run

# Test
cargo test
cargo test <name>          # single test

# Lint / format
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# Release build
cargo build --release

# SPA exit test (see docs/testing/m2-exit-test.md)
cd e2e/spa && npm ci && npx playwright test

# OpenID conformance suite (see conformance/README.md)
scripts/conformance.sh
```

## Directory Structure

```
.
├── src/         # lib.rs (library API, unstable before 1.0) and main.rs (CLI)
├── tests/       # integration tests on the router (no network)
├── examples/    # example configs and docker-compose (read by tests/examples.rs)
├── assets/      # embedded templates and static files
├── e2e/spa/     # SPA exit test (Node and Playwright, outside Cargo)
├── conformance/ # OpenID conformance suite plans and expected results
├── scripts/     # image build, binary check, conformance runner
├── docs/        # spec.md, adr/ and testing/ (exit-test runbooks)
└── .agents/     # plans and work files, git-ignored
```

## Conventions

- One crate: `src/lib.rs` + `src/main.rs`. The lib exposes `fauxidc::Server::start(config).await`.
- Use the terms in `GLOSSARY.md` in code, docs and tests (Issuer, Client, User, Strict mode, Lenient mode).
- Tests: unit tests next to the code. Integration tests in `tests/` with `tower::ServiceExt::oneshot`. Compatibility tests use the `openidconnect` crate.
- Errors: typed `thiserror` errors in the lib. `OAuthError` implements `IntoResponse`.
- Commits: Conventional Commits. `release-plz` builds versions and the CHANGELOG from them.
- Plans go in `.agents/plans/<date>-<slug>/`. `.agents/` is git-ignored.

## Rules

### Always

- Write the test first (TDD).
- Pass `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` before a commit.
- Record a significant design decision as an ADR in `docs/adr/`.

### Never

- `unsafe` code (`#![forbid(unsafe_code)]`).
- `unwrap()` / `expect()` outside tests and startup invariants (clippy denies them).
- Crates that need a C toolchain. The release build is a static musl binary.
- Names of real companies, client projects, internal hosts or email domains in code, docs, tests or commits.
