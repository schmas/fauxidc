# Contributing

## Setup

- Install Rust with `rustup`. `rust-toolchain.toml` selects the toolchain.
- Optional: install [`bacon`](https://github.com/Canop/bacon) for a background check and test loop: `cargo install bacon`, then run `bacon`.
- Optional: install `cargo-nextest` and `cargo-deny`. CI uses both.

## Checks

Run these before you open a PR:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

## Rules

- Use [Conventional Commits](https://www.conventionalcommits.org/). Releases and the CHANGELOG are generated from them.
- Write tests first. Unit tests go next to the code. Integration tests go in `tests/`.
- A new dependency needs a reason in the PR. See the "Stack" section in [AGENTS.md](AGENTS.md).
- No `unwrap()` or `expect()` outside tests and startup invariants.

## License

Unless you state otherwise, any contribution you submit is dual-licensed as MIT OR Apache-2.0, with no additional terms.
