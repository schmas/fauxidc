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

Every built-in page links `assets/static/halo.css`. The dashboard also links `assets/static/dashboard.css`.
Both files are plain CSS. They have no build step, and `cargo build` embeds them as they are.
The design file is kept outside the repository. Light and dark follow `prefers-color-scheme`.

`assets/static/fauxidc.css` and `assets/static/login.css` are old stylesheets. No built-in page links them.
They stay served for old custom templates, and they are frozen.
Run `scripts/check-css.sh` to check the size limits, the frozen files and that no stylesheet loads from the network.
The CI job `css` runs the same script.

## Rules

- Every change goes through a pull request. `main` blocks direct pushes, also for maintainers. A PR merges when the CI jobs and the Conformance check pass. [docs/releasing.md](docs/releasing.md) shows how a merge becomes a release.
- Use [Conventional Commits](https://www.conventionalcommits.org/). Releases and the CHANGELOG are generated from them.
- Write tests first. Unit tests go next to the code. Integration tests go in `tests/`.
- A new dependency needs a reason in the PR. See the "Tech Stack" section in [AGENTS.md](AGENTS.md) and [docs/spec.md](docs/spec.md) section 13.2.
- No `unwrap()` or `expect()` outside tests and startup invariants.

## License

Unless you state otherwise, any contribution you submit is dual-licensed as MIT OR Apache-2.0, with no additional terms.
