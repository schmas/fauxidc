---
name: fauxidc
description: Use when a project needs a local OAuth 2.0 / OpenID Connect provider for development or tests, or when working with a fauxidc config, token, login page, debugger or failure injection.
---

# fauxidc

fauxidc is a small OAuth 2.0 / OpenID Connect mock server for local development and integration tests.
It is one static binary. It never belongs in production: anyone who can reach it can mint tokens.

Terms: an Issuer is one mock provider with its own URL. A Client is an app registered with an Issuer.
A User is a configured person that the login page lists. A Custom user is typed in at login or sent to the Test API.

## Start fauxidc

The binaries and the image are available after the first fauxidc release.

Binary from the GitHub releases (targets: x86_64 and aarch64 Linux musl, x86_64 and aarch64 macOS):

```sh
gh release download --repo schmas/fauxidc --pattern '*aarch64-apple-darwin.tar.gz'
tar -xzf fauxidc-*-aarch64-apple-darwin.tar.gz
./fauxidc-*-aarch64-apple-darwin/fauxidc --config fauxidc.toml
```

From crates.io with Cargo (Rust 1.98 or newer), once releases exist:

```sh
cargo install fauxidc --locked
```

From source with Cargo. Add `--tag v0.1.0` (or another release tag) to pin a version:

```sh
cargo install --git https://github.com/schmas/fauxidc --locked
```

Docker (the image binds `0.0.0.0` and reads `/config/fauxidc.toml`):

```sh
docker run --rm -p 9000:9000 -v "$PWD/fauxidc.toml:/config/fauxidc.toml:ro" ghcr.io/schmas/fauxidc
```

The image has the example configs in `/examples/` (`--config /examples/generic.toml`); the release archive has them in `examples/`.
Arguments to `docker run` add to the entrypoint `fauxidc --bind 0.0.0.0`. To change the bind address in the image, pass `--bind`: the entrypoint flag overrides `server.bind` and `FAUXIDC__SERVER__BIND`.
In a fauxidc checkout, use `cargo run -- --config <file>`.

- `--config` is repeatable. Files merge in order. Without `--config`, fauxidc reads `FAUXIDC_CONFIG`, then `./fauxidc.toml`.
- Zero config: with no file, no inline config and no `FAUXIDC__*` env var, fauxidc starts with one Issuer `default`
  at `http://localhost:9000/default` in Lenient mode, one public Client `test`, and the Users `alice` and `bob`.
- A `FAUXIDC__*` env var (for example `FAUXIDC__SERVER__PORT=9100`) turns off Zero config. Give a config with an Issuer too.
- The default port is 9000 and the default bind address is `127.0.0.1`. Health: `curl -s http://localhost:9000/_mock/health` gives `{"key":"ready","status":"ok"}`. `fauxidc healthcheck` exits 0 when it is up.

## Write a config

Every config file can start with the schema line. Editors with Taplo or Even Better TOML then complete and check the keys:

```toml
#:schema https://raw.githubusercontent.com/schmas/fauxidc/main/schema/fauxidc.schema.json

[issuer.app]
issuer_url = "http://localhost:9000/app"   # the exact iss of every token

[client.web]                                # confidential: it has a secret
client_id = "web"                           # default: the table key
client_secret = "local"
redirect_uris = ["http://localhost:3000/callback"]
post_logout_redirect_uris = ["http://localhost:3000/"]

[client.spa]                                # public: no secret, needs PKCE
redirect_uris = ["http://localhost:5173/"]

[client.service]
client_secret = "local"
grant_types = ["client_credentials"]
scopes = ["api"]
audience = "https://api.example.test"

[user.alice]
label = "Alice Example"
claims = { email = "alice@example.com", email_verified = true, name = "Alice Example", roles = ["admin"] }
```

- The schema file is `schema/fauxidc.schema.json` in the fauxidc repo. `fauxidc config --schema` prints it.
- Check a config without starting the server: `fauxidc config --check --config fauxidc.toml` (exit 0 or 2).
- `fauxidc config --config fauxidc.toml` prints the merged config and the source of each value. A running server shows it at `GET /_mock/config`.
- Unknown keys are errors in every source. Ids of Issuers, Clients and Users use `a-z`, `0-9` and `_`.
- A Client without `issuer` belongs to every Issuer (`issuer = "*"`). Set `issuer = "<id>"` to limit it.
- Copy an example from the fauxidc repo `examples/`: `generic.toml` (default paths), `auth0.toml`, `okta.toml`,
  `keycloak.toml`, `entra.toml`, `cognito.toml`. Each imitates the paths and claims of one provider style.
- Provider paths: `paths = { token = "/oauth/token", endsession = "/v2/logout" }` on the Issuer. Discovery publishes them.
- `issuer.<id>.custom_user` adds a "Custom…" login option with one `username` field and a claims template with `{username}`.

## Mint a token with the Test API

`POST /_mock/{issuer-id}/token` issues tokens without a browser. The response has the same shape as `/token`.

```sh
curl -s http://localhost:9000/_mock/app/token \
  -H 'content-type: application/json' \
  -d '{"user": "alice", "claims": {"roles": ["viewer"]}, "audience": "https://api.example.test", "expires_in": 300}'
```

- Send exactly one of `user` (a configured User id) and `sub` (a Custom user). `claims` overrides or sets claims.
- `client_id` defaults to `test-api`. `scope` defaults to `openid profile email`. A negative `expires_in` gives an expired token.
- For fixed token times, set `server.fixed_time = "2020-01-21T00:00:00Z"` (RFC 3339). Then `iat` is always that time, and fauxidc checks codes and tokens with the same clock. Your app checks `exp` with its own clock, so a past time gives tokens that it rejects.
- An unknown Issuer id gives 404. A bad body or an unknown field gives 400 `invalid_request`.
- `POST /_mock/{issuer-id}/rotate-key` adds a new signing key. `?retire=true` also removes the old keys.

A real code flow without a browser: POST the login form to `/authorize` with the authorize parameters and `user=alice`.
The 302 `Location` has the code. With `response_mode=form_post`, the answer is a 200 HTML page with the code in a hidden `code` input instead.

```sh
curl -s -D - -o /dev/null -X POST http://localhost:9000/app/authorize \
  -d response_type=code -d client_id=web -d redirect_uri=http://localhost:3000/callback \
  -d scope=openid -d state=s1 -d user=alice
```

## Inject failures

`POST /_mock/{issuer-id}/fail-next` makes the next requests to one endpoint fail or slow down.

```sh
curl -s -X POST http://localhost:9000/_mock/app/fail-next \
  -H 'content-type: application/json' -d '{"endpoint": "token", "status": 503, "count": 2}'
curl -s -X DELETE http://localhost:9000/_mock/app/fail-next   # remove all entries, 204
```

- `endpoint`: `authorize`, `token`, `userinfo`, `jwks`, `endsession`, `introspect`, `revoke`, `debugger` or `discovery`.
- `status` 400 to 599 (default 500), `error` (default `server_error`), `count` (default 1, `0` removes the entry).
- `delay_ms` (at most 60000) without `status` only delays the request.
- The failed response is `{"error": <error>, "error_description": "injected failure"}`.

## Add or change Users and Clients

`/_mock/users` and `/_mock/clients` list the Users and Clients. `POST`, `PUT`, `PATCH` (JSON Merge Patch) and `DELETE` change the last config file and apply at once.

```sh
curl -s http://localhost:9000/_mock/users -H 'content-type: application/json' -d '{"id": "carol", "claims": {"email": "carol@example.com"}}'
curl -s http://localhost:9000/_mock/clients -H 'content-type: application/json' -d '{"key": "worker", "client_secret": "local", "grant_types": ["client_credentials"]}'
```

- Without a server: `fauxidc users list|get|create|update [--merge]|delete` (for example `fauxidc users create carol --claims '{"email": "carol@example.com"}'`), and `fauxidc clients ...` with `--from <file|->` for the Client body.
- A Client path uses the config key, not the `client_id`. Reads show `client_secret` as `"***"`. Lenient-registered Clients show `"lenient": true` and are read-only (409).
- 409 (exit 1): no config file is loaded, the id exists, or an env var, inline config or an earlier file sets the entry.

## Read the Request log

fauxidc keeps the last `server.request_log_size` requests (default 500) in memory. `/_mock/*` requests are not logged.

```sh
curl -s 'http://localhost:9000/_mock/requests?issuer=app&path=/app/token'
curl -s -X DELETE http://localhost:9000/_mock/requests
```

Each entry has `id`, `time`, `method`, `path`, `query`, `issuer`, `headers`, `body` and `status`.
Use it to see what the app under test really sent, for example a wrong `redirect_uri` or a missing `code_verifier`.
The log holds raw secrets (`Authorization` headers, `client_secret` values).
Between tests, `curl -s -X DELETE http://localhost:9000/_mock/state` clears codes, Sessions, revocations, Injected failures and the log (`?issuer=<id>` for one Issuer).

## Use /debugger

Each Issuer serves `{issuer}/debugger`, for example `http://localhost:9000/app/debugger`.

- Paste a JWT: the page shows the header and payload, checks the signature against the Issuer keys,
  and shows the `exp` and `iss` checks. A token of another Issuer that shares the server key still verifies; read the `iss` line.
- "Run login flow" runs the code flow with PKCE through the built-in public Client `debugger` and shows the tokens.
  The flow must finish in the browser that started it.
- A configured Client with `client_id = "debugger"` must list `{issuer}/debugger/callback` in `redirect_uris`.

## Common pitfalls

- `iss` vs `Host`: the `iss` claim is always the exact `issuer_url`, including a trailing slash. Exception: with `issuer_from_host = true` (or `FAUXIDC_ISSUER_FROM_HOST=true`), `iss` follows the request host, and a token is valid only through the host that minted it.
  The endpoint URLs in discovery follow the request `Host` (ADR 0001). An app in Docker that calls
  `http://fauxidc:9000/...` gets endpoints on `fauxidc:9000`, but `iss` stays `http://localhost:9000/...`.
  Make the app expect the `issuer_url`, or set `issuer_url` to the URL the app uses (for example `http://fauxidc:9000/app`).
  `server.public_base_url` changes only the endpoint URLs, never `iss`.
- Strict mode vs Lenient mode: Issuers are Strict by default. An unknown `client_id`, a wrong `redirect_uri`,
  a missing PKCE for a public Client or a wrong secret fails. With `lenient = true` on the Issuer, these only log a warning,
  an unknown Client is accepted, and a refresh token is always issued. Zero config is Lenient.
  Prefer Strict mode in tests, so that the app's real mistakes fail.
- Redirect URI rules: the `redirect_uri` must match a Client `redirect_uris` entry exactly.
  One `*` is allowed only as the last path segment (`http://localhost:3000/api/auth/callback/*`).
  Scheme, host and port always match exactly. On a mismatch fauxidc shows an error page and never redirects.
- Access tokens have the JWT header `typ` `at+jwt` (RFC 9068). ID tokens have `typ` `JWT`.
  A resource server library that requires `typ` `JWT` rejects the access token; allow `at+jwt`.
- Refresh tokens need the `offline_access` scope and the `refresh_token` grant on the Client.
- The `aud` of an access token is the request `audience`, else the Client `audience`, else the `client_id`.
- Config files reload 1 to 2 s after a save, or at once with `POST /_mock/reload` (422 lists the errors). Env vars, inline config and CLI flags change only at restart.
  SIGHUP reloads; it does not stop the server. Stop it with Ctrl-C or SIGTERM.
- In-memory state (codes, Sessions, rotated keys, Injected failures, the Request log) resets on restart.
- Login state: the Session cookie makes `prompt=none` work. `/endsession` clears it.

## More

The fauxidc repo has the details: `README.md`, `docs/configuration.md`, `docs/test-api.md`,
`docs/features.md` (Sessions, hot reload, debugger, TLS, token exchange, `private_key_jwt`), `docs/templates.md`
and `docs/testcontainers.md` (JVM tests with Testcontainers: wait strategy, random host port, Spring Boot).
