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

## Not yet supported

M1 does not include these. They are planned for M2 and M3.

M2:

- `client_credentials` grant, refresh tokens, rotation and reuse check.
- `/endsession`, `/introspect`, `/revoke` and more client authentication methods.
- The `paths` and `logout_param_aliases` Issuer keys. M1 rejects them as unknown keys.
- CORS, a test API for token issue, and a request log.

M3:

- Token exchange, Sessions with `prompt` and `max_age`, hot reload, and a debugger page.
- Per-Issuer keys, ES256 and PS256, key rotation, and `private_key_jwt`.
- Injected failures and an optional TLS feature.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
