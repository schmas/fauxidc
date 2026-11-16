# Test API

The Test API lives under `/_mock/`. It has no authentication. Anyone who can reach the server can mint tokens,
so never run fauxidc in production. See [SECURITY.md](../SECURITY.md).
The [dashboard](#dashboard) at `/_mock/` gives a browser page for every route below.

| Route | Purpose |
| --- | --- |
| `GET /_mock/` | The [dashboard](#dashboard). `GET /` and `GET /_mock` redirect to it. |
| `GET /_mock/health` | Health check: 200 with `{"key":"ready","status":"ok"}`, or `"pending"` until every Issuer has its first key. `fauxidc healthcheck` calls it. |
| `POST /_mock/{issuer-id}/token` | [Mint tokens](#mint-tokens) without a browser. |
| `POST /_mock/{issuer-id}/rotate-key` | [Rotate the signing key](#rotate-the-signing-key) of an Issuer. |
| `POST /_mock/{issuer-id}/fail-next` | [Inject failures](#injected-failures) into an endpoint. |
| `DELETE /_mock/{issuer-id}/fail-next` | Remove the Injected failures of an Issuer. |
| `GET /_mock/users` | List the [Users](#users). |
| `GET /_mock/users/{user-id}` | Show one User. |
| `POST /_mock/users` | Add a User to the config file. |
| `PUT /_mock/users/{user-id}` | Replace a User in the config file. |
| `PATCH /_mock/users/{user-id}` | Merge changes into a User (JSON Merge Patch). |
| `DELETE /_mock/users/{user-id}` | Remove a User from the config file. |
| `GET /_mock/clients` | List the [Clients](#clients), with secrets masked. |
| `GET /_mock/clients/{client-key}` | Show one Client. |
| `POST /_mock/clients` | Add a Client to the config file. |
| `PUT /_mock/clients/{client-key}` | Replace a Client in the config file. |
| `PATCH /_mock/clients/{client-key}` | Merge changes into a Client (JSON Merge Patch). |
| `DELETE /_mock/clients/{client-key}` | Remove a Client from the config file. |
| `GET /_mock/config` | [Show the running config](#show-the-running-config) and the source of each value. |
| `DELETE /_mock/state` | [Reset the runtime state](#reset-the-runtime-state) of all Issuers or one Issuer. |
| `POST /_mock/reload` | [Reload the config files](#reload-the-config-files) at once. |
| `GET /_mock/requests` | Read the [Request log](#request-log). |
| `DELETE /_mock/requests` | Clear the Request log. |

## Mint tokens

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
The Issuer `custom_user` template applies only to the login page. With `sub`, the token gets only `sub` and the claims you send, so send the template claims (for example `email`) in `claims`.

```sh
curl -s http://localhost:9000/_mock/auth0/token \
  -H 'content-type: application/json' \
  -d '{"user": "alice"}'
```

The endpoint has no authentication. Never run fauxidc in production.

## Rotate the signing key

`POST /_mock/{issuer-id}/rotate-key` gives the Issuer a new active signing key with its `signing_alg`.
JWKS lists the new key first and keeps the older keys, so tokens signed before the rotation still verify.
Add `?retire=true` to remove every older key in the same call; their tokens then fail.
An Issuer keeps at most 10 keys: a rotation above the cap removes the oldest key.
The response is `{"kid": <new kid>, "keys": [<kids in JWKS order>], "retired": [<removed kids>]}`.
`retired` also lists a key that the cap removed.
An unknown Issuer id gives 404.
A request with an `Origin` header that is not the server's own origin gets 403 `access_denied`, so a web page cannot rotate the keys.
`curl` and server-side test code send no `Origin` and are not affected.
Rotated keys live in memory only: after a restart the Issuer returns to its configured key.
Rotating an RS256 Issuer that shares the server key does not change the key of the other Issuers.

```sh
curl -s -X POST http://localhost:9000/_mock/auth0/rotate-key
curl -s -X POST 'http://localhost:9000/_mock/auth0/rotate-key?retire=true'
```

## Injected failures

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
A new POST for the same endpoint replaces the old entry. CORS preflights and requests with a wrong method (405) do not use up an entry.
Entries live in memory and survive a hot reload. An unknown Issuer id gives 404.
`DELETE /_mock/{issuer-id}/fail-next` removes all entries of the Issuer and returns 204.

```sh
curl -X POST localhost:9000/_mock/auth0/fail-next -H 'content-type: application/json' -d '{"endpoint":"token","status":503,"count":2}'
curl -X DELETE localhost:9000/_mock/auth0/fail-next
```

## Users

The Users routes read and change the `[user.<id>]` tables of the config.
Reads show the running config. Writes change the last config file and apply the new config at once.
The change stays after a restart, and the login page, `/userinfo` and the Test API token route use it in the next request.

A User has the same shape as `[user.<id>]`:

```json
{
  "id": "carol",
  "label": "Carol Example",
  "claims": {"email": "carol@example.com", "roles": ["viewer"]},
  "issuer": {"auth0": {"claims": {"org_id": "org-1"}}}
}
```

| Route | Body | Answer |
| --- | --- | --- |
| `GET /_mock/users` | | 200 with all Users, by id. |
| `GET /_mock/users/{user-id}` | | 200 with the User, or 404. |
| `POST /_mock/users` | A User with `id` | 201 with the User and a `Location` header. 409 if the id exists. |
| `PUT /_mock/users/{user-id}` | A User without `id` | 200 with the new User. 404 if it does not exist. |
| `PATCH /_mock/users/{user-id}` | A JSON Merge Patch (RFC 7396) | 200 with the new User. `null` removes a field or a claim. 404 if it does not exist. |
| `DELETE /_mock/users/{user-id}` | | 204. 404 if it does not exist. |

```sh
curl -s localhost:9000/_mock/users -H 'content-type: application/json' \
  -d '{"id": "carol", "label": "Carol", "claims": {"email": "carol@example.com"}}'
curl -s -X PATCH localhost:9000/_mock/users/carol -H 'content-type: application/json' \
  -d '{"claims": {"roles": ["admin"]}}'
curl -s -X DELETE localhost:9000/_mock/users/carol
```

Rules for writes:

- The write target is the last config file: the last `--config`, else the last `FAUXIDC_CONFIG` file, else `./fauxidc.toml`.
  With no config file (Zero config, inline config or env vars only), a write gives 409 `conflict`.
- A User with a value from an earlier file, inline config or a `FAUXIDC__*` env var cannot change: 409 `conflict` names the source.
- Ids must match `[a-z0-9_]+`. Unknown fields, `null` values in a new User and an invalid config give 400 `invalid_request`. The file does not change.
- Comments and formatting of the file stay. A comment inside a replaced or removed User is lost.
- A request with an `Origin` header of another origin gives 403 `access_denied`.
- A Session of a removed User fails at its next use. Issued tokens stay valid until they expire.

The `fauxidc users` commands do the same without a running server:

```sh
fauxidc users list [--json]
fauxidc users get carol [--json]
fauxidc users create carol --label Carol --claims '{"email": "carol@example.com"}' --issuer-claims auth0='{"org_id": "org-1"}'
fauxidc users update carol --claims '{"roles": ["admin"]}' --merge
fauxidc users update carol --from carol.toml      # replace; JSON or TOML, `-` reads stdin
fauxidc users delete carol
```

They read the same config sources as the server (`--config`, `FAUXIDC_CONFIG`, `./fauxidc.toml`) and follow the same rules.
`update` without `--merge` replaces the User. A running server applies the change with its hot reload.
Exit codes: 0 on success, 2 on invalid input or config, 1 on a conflict, an unknown User or a write error.

## Clients

The Clients routes read and change the `[client.<key>]` tables of the config. They follow the same rules as the [Users](#users) routes.
Writes change the last config file and apply the new config at once. The next `/authorize` or `/token` request uses the change.

The path uses the config key (`[client.<key>]`), not the `client_id`. The `client_id` is the key when it is not set.
A Client has the same shape as `[client.<key>]`. A read adds `key` and `lenient`, sets `client_id`, shows every default,
and masks the secrets the same as `fauxidc config`: `client_secret` and the private members of a JWK in `jwks`
(`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) are `"***"`:

```json
{
  "key": "backend",
  "lenient": false,
  "issuer": "*",
  "client_id": "backend",
  "client_secret": "***",
  "grant_types": ["client_credentials"],
  "scopes": ["api"],
  "audience": "https://api.example.test"
}
```

The example leaves out some default fields.

| Route | Body | Answer |
| --- | --- | --- |
| `GET /_mock/clients` | | 200 with the configured Clients by key, then the Lenient-registered Clients. |
| `GET /_mock/clients/{client-key}` | | 200 with the Client, or 404. |
| `POST /_mock/clients` | A Client with `key` | 201 with the Client and a `Location` header. 409 if the key exists. |
| `PUT /_mock/clients/{client-key}` | A Client without `key` | 200 with the new Client. 404 if it does not exist. |
| `PATCH /_mock/clients/{client-key}` | A JSON Merge Patch (RFC 7396) | 200 with the new Client. `null` sets a field back to its default. 404 if it does not exist. |
| `DELETE /_mock/clients/{client-key}` | | 204. 404 if it does not exist. |

```sh
curl -s localhost:9000/_mock/clients -H 'content-type: application/json' \
  -d '{"key": "backend", "client_secret": "local", "grant_types": ["client_credentials"], "scopes": ["api"]}'
curl -s -X PATCH localhost:9000/_mock/clients/backend -H 'content-type: application/json' \
  -d '{"audience": "https://api.example.test"}'
curl -s -X DELETE localhost:9000/_mock/clients/backend
```

- The file gets only the fields that differ from the default. It gets `client_id` only when it differs from the key.
- `PUT` replaces the whole Client. Send `client_secret` again, or the Client becomes public. Send the real `jwks`, not the masked one from a read.
  `PATCH` keeps the fields that it does not name, also the secrets.
- Lenient-registered Clients are in memory only. `GET` lists them with `"lenient": true` and their `client_id` as `key`.
  A `PUT`, `PATCH` or `DELETE` on one gives 409 `conflict`. To keep one, `POST` a Client with the same `client_id`: the configured Client wins.
- The write rules of the Users routes apply: the target file, 409 for a value from another source, 400 for invalid input, 403 for another origin.
- In Strict mode, a token request of a removed Client fails, also for an issued code or refresh token. Issued access tokens stay valid until they expire.

The `fauxidc clients` commands do the same without a running server. A Client has many fields, so `create` and `update` read it from `--from`:

```sh
fauxidc clients list [--json]
fauxidc clients get backend [--json]
fauxidc clients create backend --from backend.toml       # JSON or TOML, `-` reads stdin
echo '{"scopes": ["api", "admin"]}' | fauxidc clients update backend --from - --merge
fauxidc clients update backend --from backend.toml       # replace
fauxidc clients delete backend
```

The `--from` file has the fields of `[client.<key>]`, without the header. `get` and `list` mask `client_secret` and the private JWK members in `jwks`.
The commands do not see the Lenient-registered Clients of a running server.
Exit codes: 0 on success, 2 on invalid input or config, 1 on a conflict, an unknown Client or a write error.

## Show the running config

`GET /_mock/config` returns the config that the server uses now, with the source of each value.
It is the same data as `fauxidc config`, but from the running process, also inside a container.
The answer follows hot reload and the Users routes.

```json
{
  "config": {"server": {"port": 9000, "bind": "127.0.0.1"}, "client": {"app": {"client_secret": "***"}}},
  "sources": {"server.port": "env FAUXIDC__SERVER__PORT", "server.bind": "default", "client.app.client_secret": "/etc/fauxidc.toml:12"}
}
```

- `config` is the merged config. `sources` has one entry for each value that `fauxidc config` prints, by the same dotted path.
- A source is `default`, `<file>:<line>`, `inline`, `env <name>` or `flag <name>`, the same text as `fauxidc config`.
- Secrets are `"***"`: each `client_secret`, and the private members of a JWK in a Client `jwks` (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`).
- The server loads its config sources again for the sources. If that load does not give the running value, the source is `unknown`.
  This happens for a restart-only key that changed in a file, for a file change before the next poll or `POST /_mock/reload`, and for an invalid file.
  A server that the library API started without load inputs has only `unknown` sources.
- `?format=toml` returns the merged config as TOML (`application/toml`), with secrets masked and without sources.
- An unknown format or query parameter gives 400 `invalid_request`.

```sh
curl -s localhost:9000/_mock/config
curl -s 'localhost:9000/_mock/config?format=toml'
```

## Reset the runtime state

`DELETE /_mock/state` clears the runtime state without a restart, for example between two tests that share one fauxidc process.
It returns 204.

It clears codes, Sessions, used refresh token `jti`s, the revocation list, used client assertion `jti`s,
Lenient-registered Clients, debugger flows, Injected failures, the Client JWKS cache and the Request log.
Config and signing keys do not change.

`?issuer=<id>` clears only the data of one Issuer: codes, Sessions, Lenient-registered Clients, debugger flows,
Injected failures and the Request log entries of that Issuer. The `jti` lists, the revocation list and the JWKS cache
have no Issuer id, so they stay. An unknown Issuer id gives 404. An unknown query parameter gives 400.

Refresh tokens and access tokens are signed JWTs, not stored state. They stay valid after a reset until they expire.
A reset also forgets revocations and used refresh tokens, so a revoked or used refresh token works again.
The "Remember me" (Auto-select) cookie lives in the browser. A reset does not clear it; open `{issuer}/endsession` in the browser.

```sh
curl -X DELETE localhost:9000/_mock/state
curl -X DELETE 'localhost:9000/_mock/state?issuer=auth0'
```

## Reload the config files

`POST /_mock/reload` loads the config files again and applies them at once.
Hot reload applies a file change only after 1 to 2 s. After this call, the next request uses the new config.

- 200 with `{"changed": true, "warnings": [...]}` when the new config applied.
  `warnings` lists the keys that need a restart, for example `issuer.auth0.signing_alg changed; it needs a restart`.
- 200 with `{"changed": false, "warnings": []}` when the files did not change.
- 422 `invalid_config` when the new config is invalid. The old config stays. `errors` lists each error with its file and line.
- 409 `conflict` when no config file is loaded (Zero config, inline config or env vars only).
- 403 `access_denied` for a request with an `Origin` header that is not the server's own origin.

The call reloads files only. Env vars, inline config and CLI flags change only at restart.

```sh
curl -s -X POST localhost:9000/_mock/reload
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

## Dashboard

`GET /_mock/` is an HTML page for the Test API. `GET /` (303) and `GET /_mock` (308) redirect to it.
An Issuer route at `/` wins over the redirect. The dashboard has no authentication, the same as the Test API.
A sidebar opens one section at a time. The URL fragment names the section, for example `/_mock/#token`.
At a narrow width, a select box replaces the sidebar.

| Section | What it does | Route |
| --- | --- | --- |
| Issuers | Shows each Issuer with its `iss`, its mode, and links to discovery, JWKS and the debugger. Resets the state of one Issuer. | `DELETE /_mock/state?issuer=` |
| Issuers: Sign out | A link to `{issuer}/endsession`. It clears the Session and the "Remember me" (Auto-select) cookie of this browser, so the next `/authorize` shows the login page. | `/endsession` |
| Keys | Shows the algorithm, the active `kid` and the key count from JWKS. Rotates the key, with or without `retire`. | `rotate-key` |
| Users, Clients | Lists, shows, adds, changes and deletes entries in a JSON editor dialog. | `/_mock/users`, `/_mock/clients` |
| Mint a token | Mints tokens for a User or a Custom user. A button decodes the `id_token` in the Debugger view. | `POST /_mock/{issuer-id}/token` |
| Debugger | Shows the debugger page of the chosen Issuer (`{issuer}/debugger?embed=1`) in a frame, with an Issuer select and an "Open in new tab" link. The URL fragment keeps the Issuer, for example `#debugger/default`. The login flow of "Run login flow" runs in the frame. | `/debugger` |
| Injected failures | Sets a failure for one endpoint, or clears all failures of an Issuer. | `fail-next` |
| Request log | Shows the log with the Issuer and path filters, and clears it. | `/_mock/requests` |
| Config | Shows the running config as JSON with sources or as TOML, and reloads the config files. | `/_mock/config`, `POST /_mock/reload` |
| Reset state | Resets the state of all Issuers or of one Issuer. | `DELETE /_mock/state` |

- The page calls the JSON routes with `fetch`. It sends the same requests as `curl`, so the rules of each route apply.
  Its requests come from the same origin, so the `Origin` check of the write routes lets them through.
- An error shows the status and the `error_description` of the answer, for example the 409 of a value from another source, or the `errors` list of a 422 reload.
- Edit sends only the changed fields as a JSON Merge Patch. A masked secret (`"***"`) is not sent unless you change it, so the secret stays.
- Lenient-registered Clients are read-only. They show `Lenient · in memory`.
- The Remember me cookie lives in the browser, on the Issuer path. Only a browser visit to `/endsession` clears it. `DELETE /_mock/state` and the CLI cannot.
- The signed-out page of `/endsession` links back to the dashboard.
- The page needs JavaScript (`/_mock/static/dashboard.js`, embedded, no framework). The Issuer links work without it.
- The page links `/_mock/static/halo.css`, the stylesheet of every built-in page, and `/_mock/static/dashboard.css`, its shell.
  Light and dark follow the browser `prefers-color-scheme` setting. The design is in [fauxidc-design.pen](fauxidc-design.pen) (pen.dev).
- The answer has `Cache-Control: no-store`, `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`, so another site cannot put the page in a frame.
- The Debugger view frames a page of the same origin. The debugger page, the login page, the error page and the other Issuer pages send
  `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`. A page of another origin cannot frame them.
- The login flow in the frame goes to the endpoint URLs of the Issuer. If `public_base_url` names another origin than the dashboard URL,
  the browser blocks the login page in the frame. Then use "Open in new tab".
- `server.templates_dir` can replace `dashboard.html` and `server.static_dir` can replace `dashboard.js`, `dashboard.css` and `halo.css`. See [templates.md](templates.md#dashboardhtml).
