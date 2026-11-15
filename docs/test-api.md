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
