# fauxidc

A small OAuth 2.0 / OpenID Connect mock server for local development and integration tests.
It ships as a single static binary and needs no external infrastructure.

## Status

Pre-alpha, milestone M2. Login with the authorization code flow and the full OAuth surface for tests work.
See [docs/spec.md](docs/spec.md) for the plan.

M2 features:

- Refresh tokens with `offline_access`, rotation and the reuse check.
- The `client_credentials` grant.
- `/endsession` (RP-Initiated Logout) with `logout_param_aliases`.
- `/introspect` (RFC 7662) and `/revoke` (RFC 7009).
- Client authentication methods `client_secret_basic`, `client_secret_post` and `none`.
- `paths` overrides for endpoint paths, published in discovery.
- CORS on `/token`, `/userinfo` and `/revoke` from the Client `web_origins`.
- The Test API token endpoint and the Request log.

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

The two example configs merge. This command serves both Issuers:

```sh
fauxidc --config examples/auth0.toml --config examples/okta.toml
```

The `examples/` directory has:

- `auth0.toml`: Issuer `auth0` at `http://localhost:9000/auth0/`, with the token path `/oauth/token`,
  the logout path `/v2/logout` and the logout alias `returnTo`.
- `okta.toml`: Issuer `okta` at `http://localhost:9000/oauth2/default`, with `/v1/*` endpoint paths
  (for example `/v1/token` and `/v1/keys`).
- `docker-compose.yml`: runs the published image with `auth0.toml`.

Both configs define the confidential Client `example-app`, the public SPA Client `example-spa`
(redirect URIs `http://localhost:5173/` and `http://localhost:5174/`) and the Users `alice` and `bob`.

With `auth0-spa-js` and `useRefreshTokens`, set `cacheLocation: "localstorage"` against `auth0.toml`.
The default `"memory"` uses a web worker that accepts only `/oauth/token`. See
[docs/testing/m2-exit-test.md](docs/testing/m2-exit-test.md).

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

Each Issuer signs with `issuer.<id>.signing_alg`: `RS256` (default), `ES256` or `PS256`.
An RS256 Issuer without `issuer.<id>.key_file` shares the server key (`FAUXIDC_KEY_PEM`, else `server.key_file`, else generated).
Any other Issuer has its own key: from its `key_file` if the file exists, else generated and saved to `key_file` when it is set.
See [ADR 0003](docs/adr/0003-per-issuer-key-sets.md).

### Hot reload

fauxidc checks the config files for changes every second (modification time and length) and also reloads on SIGHUP.
Env vars, inline config and CLI flags change only at restart.
If the new config is invalid, fauxidc keeps the old config and logs the error.
Codes, Sessions, refresh tokens, revocations and the Request log stay valid across a reload.
A Session for a removed User fails at its next use.
These keys need a restart; a change logs a warning and has no effect until then:
`server.port`, `server.bind`, `server.log_format`, `server.request_log_size`, `server.key_file`,
`issuer.<id>.signing_alg`, `issuer.<id>.key_file`.
See [ADR 0004](docs/adr/0004-hot-reload-router-swap.md).

A Client can authenticate with `private_key_jwt` (RFC 7523) at `/token`, `/introspect` and `/revoke`.
Give it its public keys in `client.<key>.jwks` (an inline JWK set) or `client.<key>.jwks_uri`, not both.
`jwks_uri` must be an `http://` URL; fauxidc caches the fetched set for 60 seconds and fetches it again for an unknown `kid`.
The assertion `alg` must be `RS256`, `PS256` or `ES256`. A Client may also have a `client_secret` and use either method.

```toml
[client.backend]
grant_types = ["client_credentials"]
scopes = ["api"]
jwks = { keys = [ { kty = "EC", crv = "P-256", kid = "backend-1", x = "...", y = "..." } ] }
# or: jwks_uri = "http://localhost:8080/.well-known/jwks.json"
```

## Token exchange

`/token` supports RFC 8693 token exchange (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`).
The Client must authenticate and must list the grant in `grant_types`. It is not a default grant.
`subject_token_type` is `urn:ietf:params:oauth:token-type:access_token`, `...:id_token` or `...:jwt`.

- Strict mode: the subject token must be a JWT from any fauxidc Issuer. fauxidc checks the signature
  (key by `kid` from the key set of the Issuer that `iss` names), `exp`, and the revocation list.
  A refresh token is never accepted. Any other token gives `invalid_request`.
- Lenient mode: fauxidc tries the same check. If it fails, fauxidc logs a warning and uses the claims unverified.
  A value that is not a JWT fails in both modes.

The result is an access token of this Issuer, with no id_token and no refresh token.
It has `sub` and the User claims of the subject token. `aud` is `audience`, else `resource`,
else the Client `audience`, else the `client_id`. `scope` is the `scope` parameter, else the subject token `scope`.
An `actor_token` (with `actor_token_type`, checked like the subject token) adds `act = {"sub": <actor sub>}`.
If the subject token has an `act` claim, it goes inside as `act.act`. Without an `actor_token`, the result has no `act`.

```toml
[client.gateway]
client_secret = "gw"
grant_types = ["urn:ietf:params:oauth:grant-type:token-exchange"]
```

```sh
curl -s http://localhost:9000/auth0/token -u gateway:gw \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d subject_token="$ACCESS_TOKEN" \
  -d audience=https://orders.example.com
```

## Debugger

Each Issuer serves a debugger page at `{issuer}/debugger` (the `paths.debugger` key changes the path).

- Paste a JWT and submit the form. The page shows the header and the payload,
  checks the signature against the Issuer keys (by `kid`), and shows `exp` as "expires in N s" or "expired N s ago".
- "Run login flow" (`{issuer}/debugger/start?scope=...`, default scope `openid profile email`) runs the
  authorization code flow with PKCE (S256). The page then shows the decoded tokens.

The flow uses the built-in public Client `debugger`. It needs no config. Its only allowed redirect URI is the
debugger callback of the same Issuer (`{issuer}/debugger/callback`), on any host. A configured Client with
`client_id = "debugger"` replaces it. The PKCE verifier stays on the server for 600 s.

The page also shows "Signed in as <label> · change" when the Auto-select cookie names a configured User.
The "change" link (`{issuer}/debugger?forget=1`) clears the cookie.

## Templates

You can replace the login page, the error page and the signed-out page. See [docs/templates.md](docs/templates.md).

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

`POST /_mock/{issuer-id}/rotate-key` gives the Issuer a new active signing key with its `signing_alg`.
JWKS lists the new key first and keeps the older keys, so tokens signed before the rotation still verify.
Add `?retire=true` to remove every older key in the same call; their tokens then fail.
The response is `{"kid": <new kid>, "keys": [<kids in JWKS order>], "retired": [<removed kids>]}`.
An unknown Issuer id gives 404.
Rotated keys live in memory only: after a restart the Issuer returns to its configured key.
Rotating an RS256 Issuer that shares the server key does not change the key of the other Issuers.

```sh
curl -s -X POST http://localhost:9000/_mock/auth0/rotate-key
curl -s -X POST 'http://localhost:9000/_mock/auth0/rotate-key?retire=true'
```

### Injected failures

`POST /_mock/{issuer-id}/fail-next` makes the next requests to one endpoint of the Issuer fail or slow down.
The body is JSON `{endpoint, status, error, count, delay_ms}`; unknown fields give 400 `invalid_request`.

| Field | Meaning |
| --- | --- |
| `endpoint` | `authorize`, `token`, `userinfo`, `jwks`, `endsession`, `introspect`, `revoke`, `debugger` or `discovery` (all discovery forms). |
| `status` | 400 to 599. Default 500. |
| `error` | The `error` value of the response. Default `server_error`. |
| `count` | How many requests fail. Default 1. `0` removes the entry. |
| `delay_ms` | Wait before the answer, at most 60000. Default 0. Without `status`, the request is only delayed and then handled normally. |

A failed request gets the status and `{"error": <error>, "error_description": "injected failure"}`.
A new POST for the same endpoint replaces the old entry. CORS preflights do not use up an entry.
Entries live in memory and survive a hot reload. An unknown Issuer id gives 404.
`DELETE /_mock/{issuer-id}/fail-next` removes all entries of the Issuer and returns 204.

```sh
curl -X POST localhost:9000/_mock/auth0/fail-next -H 'content-type: application/json' -d '{"endpoint":"token","status":503,"count":2}'
curl -X DELETE localhost:9000/_mock/auth0/fail-next
```

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

M2 does not include these. They are planned for M3.

- Sessions with `prompt` and `max_age`, hot reload, and a debugger page.
- Per-Issuer keys, ES256 and PS256, key rotation, and `private_key_jwt`.
- Injected failures and an optional TLS feature.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option.
