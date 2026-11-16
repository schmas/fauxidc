# Test API

The Test API lives under `/_mock/`. It has no authentication. Anyone who can reach the server can mint tokens,
so never run fauxidc in production. See [SECURITY.md](../SECURITY.md).

| Route | Purpose |
| --- | --- |
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
