# fauxidc

A small OAuth 2.0 / OpenID Connect mock server for local development and integration tests.
It ships as a single static binary and needs no external infrastructure.

## Status

Pre-alpha, milestone M1. Login with the authorization code flow works.
See [docs/spec.md](docs/spec.md) for the plan.

## Not for production

Anyone who can reach a fauxidc server can mint tokens.
Never trust a fauxidc issuer in a production system. See [SECURITY.md](SECURITY.md).

## Quick start

Docker, for the published image (the image is not published yet):

```sh
docker run -p 9000:9000 ghcr.io/schmas/fauxidc
```

The image `HEALTHCHECK` runs `fauxidc healthcheck`, which probes the configured port.
To change the port, set it in `/config/fauxidc.toml` or with `FAUXIDC__SERVER__PORT`, not only with a `--port` flag in `CMD`. Else override the `HEALTHCHECK`.
A `FAUXIDC__*` env var turns off Zero config, so use it together with a config that has an Issuer.

Cargo, for the published crate (not published yet). From a checkout, use `cargo run --` instead:

```sh
cargo install fauxidc
fauxidc
```

With no config, fauxidc starts in Zero config mode. It has one Issuer `default`, one public Client `test`, and the Users `alice` and `bob`.
The discovery URL is:

```
http://localhost:9000/default/.well-known/openid-configuration
```

Check that the server runs:

```sh
curl http://localhost:9000/_mock/health
fauxidc healthcheck
```

To use one of the example configs:

```sh
fauxidc --config examples/auth0.toml
```

The `examples/` directory has:

- `auth0.toml`: Issuer `auth0` at `http://localhost:9000/auth0/`.
- `okta.toml`: Issuer `okta` at `http://localhost:9000/oauth2/default`.
- `docker-compose.yml`: runs the published image with `auth0.toml`.

Both configs define the Client `example-app` and the Users `alice` and `bob`.

## Configuration

fauxidc reads five sources. A later source overrides an earlier one.

| Order | Source | Example |
| --- | --- | --- |
| 1 | Built-in defaults (Zero config if nothing else is set) | |
| 2 | Config files | `--config a.toml --config b.toml`, or `FAUXIDC_CONFIG`, or `./fauxidc.toml` |
| 3 | Inline config | `FAUXIDC_CONFIG_INLINE` (TOML, or JSON if it starts with `{`) |
| 4 | Env var overrides for single keys | `FAUXIDC__SERVER__PORT=9000` |
| 5 | CLI flags | `--port`, `--bind`, `--log-format` |

Every source rejects unknown keys. Invalid config stops the server with exit code 2.

- `fauxidc config` prints the merged config and the source of each value.
- `fauxidc config --check` only validates the config.

The full reference is in [docs/spec.md](docs/spec.md), section 5.

## Templates

You can replace the login page and the error page. See [docs/templates.md](docs/templates.md).

## Test API

`POST /_mock/{issuer-id}/token` issues tokens without a browser. The body is JSON:

| Field | Meaning |
| --- | --- |
| `user` | A configured User id. Send exactly one of `user` and `sub`. |
| `sub` | The `sub` of a Custom user. |
| `claims` | Claim overrides (with `user`) or the Custom user claims (with `sub`). |
| `client_id` | Default `test-api`. An unknown id is not registered; it only labels the tokens. |
| `scope` | Default `openid profile email`. |
| `audience` | Audience of the access token. |
| `expires_in` | Lifetime in seconds of the id_token and the access token. Negative values give expired tokens. |

The response has the same JSON shape as `/token`. An unknown Issuer id gives 404.
A bad body, an unknown User or an unknown field gives 400 `invalid_request`.

```sh
curl -s http://localhost:9000/_mock/auth0/token \
  -H 'content-type: application/json' \
  -d '{"user": "alice"}'
```

The endpoint has no authentication. Never run fauxidc in production.

## Request log

fauxidc keeps the raw requests it received in memory. It is a ring buffer of `server.request_log_size` entries
(default 500). Size 0 turns the log off. The log resets on restart. Requests to `/_mock/*` are not logged.

- `GET /_mock/requests` returns the entries as a JSON array, oldest first.
  Filters: `?issuer=<id>` (exact Issuer id) and `?path=<path>` (exact request path). Both are optional.
- `DELETE /_mock/requests` clears the log and returns 204. Entry ids are never reused.

Each entry has `id`, `time` (Unix seconds), `method`, `path`, `query`, `issuer`, `headers` (lowercase names),
`body` (raw, UTF-8 lossy) and `status`.

The log stores headers and bodies raw. That includes `Authorization` headers and `client_secret` values.
A request body over 1 MiB gets 413 while the log is on.

## Conformance

[![Conformance](https://github.com/schmas/fauxidc/actions/workflows/conformance.yml/badge.svg)](https://github.com/schmas/fauxidc/actions/workflows/conformance.yml)

CI runs two plans of the OpenID Foundation conformance suite against fauxidc on each push to `main`:
`oidcc-basic-certification-test-plan` (Basic OP, static Clients) and `oidcc-config-certification-test-plan` (Config OP).
Each run uploads the suite's result export as the `conformance-results` artifact.
See [conformance/README.md](conformance/README.md) for the known results and how to run the suite locally.

## Not yet supported

M1 does not include these. They are planned for M2 and M3.

M2:

- `client_credentials` grant, refresh tokens, rotation and reuse check.
- `/endsession`, `/introspect`, `/revoke` and more client authentication methods.
- The `paths` and `logout_param_aliases` Issuer keys. M1 rejects them as unknown keys.

M3:

- Token exchange, Sessions with `prompt` and `max_age`, hot reload, and a debugger page.
- Per-Issuer keys, ES256 and PS256, key rotation, and `private_key_jwt`.
- Injected failures and an optional TLS feature.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
