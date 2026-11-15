# fauxidc

[![CI](https://github.com/schmas/fauxidc/actions/workflows/ci.yml/badge.svg)](https://github.com/schmas/fauxidc/actions/workflows/ci.yml)
[![Conformance](https://github.com/schmas/fauxidc/actions/workflows/conformance.yml/badge.svg)](https://github.com/schmas/fauxidc/actions/workflows/conformance.yml)
[![Release](https://img.shields.io/github/v/release/schmas/fauxidc)](https://github.com/schmas/fauxidc/releases)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-schmas%2Ffauxidc-blue)](https://github.com/schmas/fauxidc/pkgs/container/fauxidc)

fauxidc is a small OAuth 2.0 / OpenID Connect mock server for local development and integration tests.
It ships as a single static binary and needs no external infrastructure.
It gives your app a real login flow, real signed tokens and a Test API to mint tokens and inject failures.
It is pre-alpha: the config and the library API can change before 1.0.
Anyone who can reach a fauxidc server can mint tokens, so never trust a fauxidc Issuer in production.
See [SECURITY.md](SECURITY.md).

> fauxidc was designed and built with AI coding agents (Claude Code), under human direction and review. Every change passes the test suite, clippy, and the OpenID conformance suite in CI. Report problems in GitHub issues.

## Start in 60 seconds

The image and the binaries are available after the first release.
Start the server with Docker:

```sh
docker run --rm -p 9000:9000 ghcr.io/schmas/fauxidc
```

Or download the binary from the [GitHub releases](https://github.com/schmas/fauxidc/releases).
The targets are `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, `x86_64-apple-darwin` and `aarch64-apple-darwin`.
Each archive has a `.sha256` file next to it. This example is for an Apple silicon Mac:

```sh
gh release download --repo schmas/fauxidc --pattern '*aarch64-apple-darwin.tar.gz'
tar -xzf fauxidc-*-aarch64-apple-darwin.tar.gz
sudo mv ./fauxidc-*-aarch64-apple-darwin/fauxidc /usr/local/bin/   # put it on your PATH
fauxidc
```

If macOS blocks a binary that a browser downloaded, run `xattr -d com.apple.quarantine /usr/local/bin/fauxidc`.

Or install it from crates.io with Cargo (needs Rust 1.98 or newer), after the first release:

```sh
cargo install fauxidc --locked
```

Or build it from source, from the Git repository:

```sh
cargo install --git https://github.com/schmas/fauxidc --locked
```

Add `--tag v0.1.0` (or another release tag) to the `--git` command to pin a version.
The archive also has the `examples/` directory. From a checkout, use `cargo run --` in place of `fauxidc`.

With no config, fauxidc starts in Zero config mode: one Issuer `default` in Lenient mode,
one public Client `test`, and the Users `alice` and `bob`. In a second terminal:

```sh
# Discovery document
curl -s http://localhost:9000/default/.well-known/openid-configuration
# Tokens for alice, without a browser
curl -s http://localhost:9000/_mock/default/token -H 'content-type: application/json' -d '{"user": "alice"}'
# Health check
curl -s http://localhost:9000/_mock/health
```

Point your app at the Issuer URL `http://localhost:9000/default` with the client id `test`.
Open `http://localhost:9000/default/debugger` and click "Run login flow" to see the login page.

## Recipes

The recipes use [examples/generic.toml](examples/generic.toml). Start fauxidc with it:

```sh
# Docker: the image has the examples in /examples/
docker run --rm -p 9000:9000 ghcr.io/schmas/fauxidc --config /examples/generic.toml
# Binary: download the file (the release archive has it in examples/ too)
curl -sO https://raw.githubusercontent.com/schmas/fauxidc/main/examples/generic.toml
fauxidc --config generic.toml
# Checkout
cargo run -- --config examples/generic.toml
```

### SPA with PKCE

`generic.toml` has the public Client `spa` with the redirect URI `http://localhost:5173/`.
Configure your OIDC library with these values:

| Setting | Value |
| --- | --- |
| Authority (Issuer URL) | `http://localhost:9000/generic` |
| Client id | `spa` |
| Redirect URI | `http://localhost:5173/` |
| Scope | `openid profile email` (add `offline_access` for a refresh token) |

A public Client needs PKCE in Strict mode. The library sends `S256` for you.
CORS on `/token`, `/userinfo` and `/revoke` allows the Client `web_origins`, or the origins of its `redirect_uris` when `web_origins` is not set.
With `auth0-spa-js` and `useRefreshTokens`, see the note in [docs/configuration.md](docs/configuration.md#examples).

### Backend with a client secret

`generic.toml` has the confidential Client `web` (secret `local`) with the redirect URI `http://localhost:3000/callback`.
Your backend sends the browser to `/authorize`, the User picks `alice` or `bob`, and the backend exchanges the code:

```sh
curl -s http://localhost:9000/generic/token -u web:local \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri=http://localhost:3000/callback
```

The Client can also send the secret in the body (`client_secret_post`) or use `private_key_jwt`.
See [docs/features.md](docs/features.md#private_key_jwt).
A backend that wants the code in a POST body (for example ASP.NET Core) can send `response_mode=form_post`.
See [docs/features.md](docs/features.md#response_modeform_post).

### Machine-to-machine

`generic.toml` has the Client `service` with the `client_credentials` grant, the scope `api`
and the audience `https://api.example.test`:

```sh
curl -s http://localhost:9000/generic/token -u service:local \
  -d grant_type=client_credentials -d scope=api
```

### Mint a token in a test

The Test API issues tokens without a browser. Your test code calls it before it calls your API:

```sh
curl -s http://localhost:9000/_mock/generic/token \
  -H 'content-type: application/json' \
  -d '{"user": "alice", "claims": {"roles": ["viewer"]}, "audience": "https://api.example.test", "expires_in": 300}'
```

Send `"sub"` in place of `"user"` for a Custom user that is not in the config.
A negative `expires_in` gives an expired token, to test that your API rejects it.
Rust tests can also start fauxidc in the same process with `fauxidc::Server::start(config).await`.
The library API is unstable before 1.0.

### Fixed time for reproducible tokens

Set `server.fixed_time = "2020-01-21T00:00:00Z"` (or `FAUXIDC__SERVER__FIXED_TIME`).
Then `iat`, `exp`, `auth_time` and `expires_in` are the same in every run, and fauxidc checks tokens with the same clock.
See [docs/configuration.md](docs/configuration.md#fixed-time).

### Random host port (Testcontainers)

With a mapped port, set `FAUXIDC_ISSUER_FROM_HOST=true`. Then `iss` and the discovery `issuer` use the host and port of the request,
so a client can use `http://localhost:<mapped port>/default` as its issuer. Zero config stays on.
Tokens are then valid only through the host that minted them.
See [docs/configuration.md](docs/configuration.md#issuer-url-and-endpoint-urls).
For JVM tests, [docs/testcontainers.md](docs/testcontainers.md) has the `GenericContainer` setup, the wait strategy,
a Spring Boot example and token minting from Java.

### Simulate a provider outage

Make the next two token requests fail with 503, then remove all Injected failures:

```sh
curl -s -X POST http://localhost:9000/_mock/generic/fail-next \
  -H 'content-type: application/json' -d '{"endpoint": "token", "status": 503, "count": 2}'
curl -s -X DELETE http://localhost:9000/_mock/generic/fail-next
```

Send `"delay_ms": 5000` without `status` to make an endpoint slow, not broken.
To test key rotation, call `POST /_mock/generic/rotate-key`.

### Use with an agent

The repo has an agent skill, [skills/fauxidc](skills/fauxidc/SKILL.md). It tells a coding agent how to start fauxidc,
write a config, mint tokens, inject failures and avoid the common pitfalls.
Install it: copy or symlink the `skills/fauxidc` directory into `.claude/skills/` (one project),
`~/.claude/skills/` (all projects, Claude Code) or `~/.agents/skills/` (other agents that read it).

```sh
git clone https://github.com/schmas/fauxidc.git ~/src/fauxidc
mkdir -p .claude/skills && ln -s ~/src/fauxidc/skills/fauxidc .claude/skills/fauxidc
```

[llms.txt](llms.txt) lists the docs for agents that read it.
The schema of the config file is [schema/fauxidc.schema.json](schema/fauxidc.schema.json).

## Configuration

fauxidc reads five sources. A later source overrides an earlier one:
built-in defaults, config files (`--config`, `FAUXIDC_CONFIG` or `./fauxidc.toml`),
inline config (`FAUXIDC_CONFIG_INLINE`), env vars for single keys (`FAUXIDC__SERVER__PORT=9000`) and CLI flags.
Every source rejects unknown keys. Invalid config stops the server with exit code 2.

- `fauxidc config` prints the merged config and the source of each value.
- `fauxidc config --check` only validates the config.
- `fauxidc config --schema` prints the JSON Schema of the config file. It reads no config.

For completion and key checks in an editor with Taplo or Even Better TOML, add this first line to your config file:

```toml
#:schema https://raw.githubusercontent.com/schmas/fauxidc/main/schema/fauxidc.schema.json
```

A small config:

```toml
[issuer.app]
issuer_url = "http://localhost:9000/app"

[client.web]
client_secret = "local"
redirect_uris = ["http://localhost:3000/callback"]

[user.alice]
claims = { email = "alice@example.com", name = "Alice Example" }
```

The [examples/](examples/) directory has six configs and a compose file:
`auth0.toml`, `okta.toml`, `generic.toml`, `keycloak.toml`, `entra.toml`, `cognito.toml` and `docker-compose.yml`.
Each one imitates the paths and claims of one provider style.

[docs/configuration.md](docs/configuration.md) has the details: the sources table, Zero config, Docker,
the examples, Strict and Lenient mode, the Issuer URL rules and the signing keys.
The full key reference is [docs/spec.md](docs/spec.md), section 5.

## Test API

The Test API lives under `/_mock/` and has no authentication.

| Route | Purpose |
| --- | --- |
| `POST /_mock/{issuer-id}/token` | Mint tokens for a User or a Custom user. |
| `POST /_mock/{issuer-id}/rotate-key` | Give the Issuer a new signing key. |
| `POST` / `DELETE /_mock/{issuer-id}/fail-next` | Add or remove Injected failures. |
| `GET` / `DELETE /_mock/requests` | Read or clear the Request log. |
| `GET /_mock/health` | Health check. |

[docs/test-api.md](docs/test-api.md) has every field, status code and limit.

## Templates

You can replace the login page, the error page, the signed-out page, the debugger page and the `form_post` page with your own templates.
The built-in pages link one embedded stylesheet, `/_mock/static/fauxidc.css`, and need no network.

For a Custom user from one username, set a claims template on the Issuer. The "Custom…" entry
(here "Other…") then shows one `username` field instead of the subject and JSON fields:

```toml
[issuer.app.custom_user]
label = "Other…"
[issuer.app.custom_user.claims]
email = "{username}@example.test"
email_verified = true
```

`sub` is the username, trimmed and in lowercase (a `sub` in Override claims wins). `{username}` is filled in every string value, nested values too.
[docs/templates.md](docs/templates.md) has the template context (version 2) and the override rules.

## Debugger

Each Issuer serves a debugger page at `{issuer}/debugger`.
Paste a JWT to decode it and check its signature, `exp` and `iss`.
Or click "Run login flow" to run the code flow with PKCE and see the decoded tokens.
The flow uses the built-in public Client `debugger`. A configured Client with
`client_id = "debugger"` must list `{issuer}/debugger/callback` in `redirect_uris`.
See [docs/features.md](docs/features.md#debugger).

## TLS

A build with the optional `tls` feature serves HTTPS from PEM files that you provide (`server.tls.cert_file` and `server.tls.key_file`).
fauxidc does not generate certificates. The release binaries and the container image are built without the `tls` feature.
See [docs/features.md](docs/features.md#tls).

## Hot reload

fauxidc polls the config files every second and also reloads on SIGHUP.
A change applies only after two polls in a row see the same new file state, so it applies 1 to 2 s after the save.
If a change fails to load, fauxidc keeps the old config and logs the error.
SIGHUP reloads the config, so closing the terminal does not stop a foreground fauxidc; stop it with Ctrl-C or SIGTERM.
Some `server` keys need a restart. See [docs/features.md](docs/features.md#hot-reload).

Sessions, token exchange and `private_key_jwt` are in [docs/features.md](docs/features.md) too.

## Conformance

CI runs two plans of the OpenID Foundation conformance suite against fauxidc on each push to `main`:
`oidcc-basic-certification-test-plan` (Basic OP, static Clients) and `oidcc-config-certification-test-plan` (Config OP).
Each run uploads the suite's result export as the `conformance-results` artifact.
See [conformance/README.md](conformance/README.md) for the known results and how to run the suite locally.

## Not supported

These are not planned (spec non-goals):

- Production use.
- Provider management APIs, for example the Auth0 Management API or the Okta Users API.
- RFC 7591 dynamic client registration, RFC 9126 PAR, RFC 9449 DPoP, RFC 8628 device flow,
  front-channel and back-channel logout.
- The implicit grant and the password grant.

Current limits:

- `jwks_uri` must be an `http://` URL.
- The `tls` feature uses the PEM files you give. fauxidc does not generate certificates.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
