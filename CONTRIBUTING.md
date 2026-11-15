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

## Page styles

The built-in pages use `assets/static/fauxidc.css`, compiled with Tailwind CSS and daisyUI from `assets/css/fauxidc.css`.
After you change a file in `assets/templates/` or `assets/css/`, run `scripts/build-css.sh` and commit the new `assets/static/fauxidc.css` in the same commit.
The script downloads the pinned tools into `target/css-tools/` (needs `curl` and `shasum`). `cargo build` does not need it.
The CI job `css` fails when the committed file differs from a fresh build.

## Rules

- Every change goes through a pull request. `main` blocks direct pushes, also for maintainers. A PR merges when the CI jobs and the Conformance check pass. [docs/releasing.md](docs/releasing.md) shows how a merge becomes a release.
- Use [Conventional Commits](https://www.conventionalcommits.org/). Releases and the CHANGELOG are generated from them.
- Write tests first. Unit tests go next to the code. Integration tests go in `tests/`.
- A new dependency needs a reason in the PR. See the "Tech Stack" section in [AGENTS.md](AGENTS.md) and [docs/spec.md](docs/spec.md) section 13.2.
- No `unwrap()` or `expect()` outside tests and startup invariants.

## License

Unless you state otherwise, any contribution you submit is dual-licensed as MIT OR Apache-2.0, with no additional terms.
