# 2. Our own layered config merge instead of `figment` / `config`

Date: 2026-11-14
Status: accepted

## Context

Config comes from five optional sources: built-in defaults, config files, inline config (`FAUXIDC_CONFIG_INLINE`), env var overrides (`FAUXIDC__<PATH>`) and CLI flags. Later sources win.

The spec requires:

- Every source rejects unknown keys, including any `FAUXIDC__*` env var that maps to no key.
- Each error names its source: file and line, `inline`, `env FAUXIDC__...`, or the flag.
- `fauxidc config` prints the merged config with the source of each value.
- Config keys are lowercase ids (`[a-z0-9_]+`). Env var names are matched without case.

We checked two crates:

- `figment`: no release since 2024-05.
- `config`: lowercases keys and keeps no source per value.

Neither meets the per-value source and the error rules above.

## Decision

Write our own merge, about 200 lines:

1. Parse each source to `toml::Value`.
2. Deep-merge the values in order, and keep a source map from each key path to its source.
3. Deserialize the result with `serde` and `deny_unknown_fields`.
4. Map each error back to its source through the source map.

## Consequences

- We own about 200 lines of merge code and its tests.
- Error messages and `fauxidc config` output can name the exact source of each value.
- No dependency on an unmaintained crate.
