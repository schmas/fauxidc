# fauxidc: spec

Date: 2026-11-14
Status: approved through grilling session, 2026-11-14.
Terms: [`GLOSSARY.md`](../GLOSSARY.md).

## 1. Goal

fauxidc is a small OAuth 2.0 / OpenID Connect mock server written in Rust. It is used for local development and integration tests. It replaces `navikt/mock-oauth2-server` (JVM).

Any client that follows the standards in section 3 works with no provider-specific code. Auth0 and Okta setups are example config files, not code.

Targets:

- Single static binary, 3 to 5 MB. Less than 15 MB RSS at idle. Less than 50 ms to listen.
- No external infrastructure. No database.
- Configured from files, inline config, env vars or CLI flags. Each source is optional.

Non-goals:

- Production use. A fauxidc Issuer must never be trusted in production.
- Provider management APIs (Auth0 Management API, Okta Users API). fauxidc does not copy their routes or bodies. Its own Test API can list and change the Users and Clients of the config file (5.9); that is a fauxidc API, not a provider API.
- RFC 7591 dynamic client registration, RFC 9126 PAR, RFC 9449 DPoP, RFC 8628 device flow, front-channel and back-channel logout.
- Implicit grant and password grant. If users ask, the password grant can be added later behind `enable_password_grant`.

## 2. Terms

See [`GLOSSARY.md`](../GLOSSARY.md). Main terms: Issuer, Issuer URL, Issuer id, Client, User, Custom user, Claim override, Strict mode, Lenient mode, Session, Auto-select, Zero config, Test API, Request log, Injected failure.

## 3. Standards

| Standard | Milestone |
|---|---|
| RFC 6749 OAuth 2.0: `authorization_code` | M1 |
| RFC 6749: `client_credentials`, `refresh_token` | M2 |
| RFC 6750 bearer token use | M1 |
| RFC 7636 PKCE (`S256`, `plain`) | M1 |
| RFC 7515/7517/7518/7519 JWS, JWK, JWA, JWT | M1 |
| OIDC Discovery 1.0 + RFC 8414 metadata | M1 |
| OIDC Core 1.0: `id_token`, `nonce`, `/userinfo`, scopes and claims | M1 |
| OIDC Core: `prompt`, `max_age`, `auth_time` with Sessions | M3 |
| RFC 9068 JWT access tokens | M1 |
| OIDC RP-Initiated Logout 1.0 | M2 |
| RFC 7662 introspection, RFC 7009 revocation | M2 |
| RFC 8693 token exchange | M3 |
| RFC 7523 `private_key_jwt` client auth | M3 |
| RFC 7523 section 2.1 jwt-bearer grant (On-Behalf-Of) | after M4 |
| OAuth 2.0 Form Post Response Mode (`response_mode=form_post`) | after M4 |

Conformance proof: CI runs the OpenID Foundation conformance suite ("Basic OP" and "Config OP" plans) from M2. The README links the results.

## 4. Issuers and routing

- Each Issuer has an Issuer id (config key, `[a-z0-9_]+`) and an `issuer_url` (exact string, a trailing slash is allowed).
- `iss` and discovery `issuer` are the exact `issuer_url`. They never change with the request host, unless the Issuer sets `issuer_from_host = true` (ADR 0006).
- With `issuer_from_host = true`, `iss` and discovery `issuer` are the endpoint base of the request (the same order as the endpoint URLs below), plus the trailing slash of `issuer_url`. `issuer_url` still gives the Issuer path. fauxidc checks its own tokens (introspect, revoke, userinfo, refresh, `id_token_hint`, token exchange, debugger, the `private_key_jwt` audience) against the `iss` of the current request only. A token minted through one host fails through another host.
- The path of `issuer_url` decides which requests the Issuer gets. Routing ignores a trailing slash.
- Startup fails if two Issuer paths are equal or one is a prefix of the other. A root-path Issuer (`/`) is then only possible when it is the only Issuer.
- Reserved prefixes: `/_mock` and `/.well-known`. An Issuer path must not start with them.
- Default endpoint paths below the Issuer path: `/authorize`, `/token`, `/userinfo`, `/jwks`, `/endsession`, `/introspect`, `/revoke`, `/debugger`.
- `paths` overrides any endpoint path per Issuer (M2). Example: `token = "/oauth/token"`. Discovery publishes the override.
- Discovery is served at `{issuer path}/.well-known/openid-configuration` and `{issuer path}/.well-known/oauth-authorization-server`. The RFC 8414 form `/.well-known/oauth-authorization-server{issuer path}` is also served. All three return the same document (M1).
- Endpoint URLs in discovery use `server.public_base_url` if set (per-Issuer override allowed). Otherwise they use the listener scheme + the request `Host` header: `https://` when `server.tls` is set, else `http://`. One process can then serve a browser at `localhost:9000` and a container at `fauxidc:9000`, with one fixed `iss`.
- `X-Forwarded-Proto` / `X-Forwarded-Host` are used only when `server.trust_forwarded_headers = true`. Without `X-Forwarded-Proto`, the scheme is `https` when `server.tls` is set, else `http`.
- `logout_param_aliases` maps provider parameter names to standard ones (M2). Example: `returnTo = "post_logout_redirect_uri"`.

## 5. Configuration

### 5.1 Sources and precedence

Later wins:

1. Built-in defaults. If no other source is given, this is Zero config (5.6).
2. Config files: `--config a.toml --config b.toml` (repeatable), else `FAUXIDC_CONFIG` (comma-separated paths), else `./fauxidc.toml` if it exists. Files are deep-merged in order.
3. `FAUXIDC_CONFIG_INLINE`: the whole config as a string. TOML, or JSON if the first non-space character is `{`.
4. Env var overrides on single keys: `FAUXIDC__<PATH>` with `__` between path segments. Example: `FAUXIDC__SERVER__PORT=9000`, `FAUXIDC__ISSUER__AUTH0__ISSUER_URL=http://localhost:9000/auth0/`. Env var names are matched without case. Config keys are lowercase.
5. CLI flags for common keys: `--port`, `--bind`, `--log-format`.

Separate env vars outside the tree: `FAUXIDC_KEY_PEM` (7), `FAUXIDC_LOG` (EnvFilter syntax, default `info`).

### 5.2 Env var values

The value is parsed as a TOML value. If parsing fails, it is a plain string. Examples:

- `9000` is an integer, `true` is a bool.
- `["http://a/*","http://b/cb"]` is an array.
- `{ email = "a@example.com", roles = ["admin"] }` is a table.

Type checks run against the schema after the merge.

### 5.3 Validation

- Every source rejects unknown keys. This includes any `FAUXIDC__*` env var that maps to no key.
- Each error names its source: file and line, `inline`, `env FAUXIDC__...`, or the flag.
- Config keys (Issuer, Client and User ids) must match `[a-z0-9_]+`, because shell env var names cannot contain `-`.
- Invalid config at startup: exit with code 2 and the error list.
- `server.fixed_time` (after M4) must be empty or an RFC 3339 date-time with an offset, at or after 1970-01-01T00:00:00Z. Another value is a config error at startup and at reload.

### 5.4 Shape

Issuers, Clients and Users are tables keyed by id. They are not arrays. This keeps every env var path stable, and an env var can add a new entry.

```toml
[server]
port = 9000
bind = "127.0.0.1"            # image default: 0.0.0.0
public_base_url = ""          # empty: derive from Host
trust_forwarded_headers = false
key_file = "./data/signing.pem"
templates_dir = ""            # files here replace embedded templates one by one
static_dir = ""
log_format = "text"           # text | json
request_log_size = 500
fixed_time = ""               # after M4: RFC 3339, for example "2020-01-21T00:00:00Z"; empty: system clock

[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"
issuer_from_host = false      # true: iss follows the request host (ADR 0006)
lenient = false
auto_login = false            # login_hint=<user id> signs in at once
show_user_list = false        # login page opens on the User dropdown
require_nonce = false
sub_template = "auth0|{user_id}"
default_claims = {}
login_template = ""           # per-Issuer login page
# M2:
paths = { token = "/oauth/token", endsession = "/v2/logout" }
logout_param_aliases = { returnTo = "post_logout_redirect_uri" }

[issuer.auth0.custom_user]    # M4, optional: "Custom…" asks for one username
label = "Other…"              # dropdown label, default "Custom…"
[issuer.auth0.custom_user.claims]   # only {username} is allowed; no sub
email = "{username}@example.test"
email_verified = true
name = "{username} Example"

[issuer.auth0.lifetimes]      # seconds
id_token = 3600
access_token = 3600
refresh_token = 86400
code = 60

[client.example_app]
issuer = "*"                  # Issuer id, or "*" for all
client_id = "example-app"     # default: the key
client_secret = "local"       # absent: public Client
redirect_uris = ["http://localhost:3000/api/auth/callback/*"]
post_logout_redirect_uris = ["http://localhost:3000/"]
web_origins = []              # absent: origins of redirect_uris
grant_types = ["authorization_code", "refresh_token"]
scopes = ["openid", "profile", "email", "offline_access"]
audience = ""                 # default access token aud
require_pkce = false          # public Clients always need PKCE in Strict mode
rotate_refresh_tokens = true
refresh_reuse_leeway_secs = 0
id_claims = {}
access_claims = {}
# lifetimes table: same as Issuer, overrides it

[user.alice]
label = "Alice Admin"
claims = { email = "alice@example.com", given_name = "Alice", family_name = "Admin", name = "Alice Admin", roles = ["admin"] }

[user.alice.issuer.okta]      # claims for one Issuer only
claims = { sub = "00u-alice" }
```

### 5.5 Assets and templates

- Default templates and static files are embedded in the binary.
- `templates_dir` and `static_dir` replace them file by file. A missing file falls back to the embedded one.
- `issuer.<id>.login_template` gives one Issuer its own login page.
- Every built-in page links the embedded stylesheet `/_mock/static/halo.css`: plain CSS, light and dark, no build step (ADR 0009). The design file is kept outside the repository.
- The dashboard (`dashboard.html`) also loads the embedded files `/_mock/static/dashboard.css` and `/_mock/static/dashboard.js`. The script calls only the JSON routes of the Test API.
- `/_mock/static/fauxidc.css` and `/_mock/static/login.css` are old, frozen stylesheets. No built-in page links them. They stay served for old custom templates.
- Framing: the HTML pages of an Issuer (login, error, signed out, `form_post`, debugger) send `X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`. The dashboard sends `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`. A page of another origin cannot frame any of them.
- The template context is a documented, versioned contract. A breaking change to it is a breaking release.

### 5.6 Zero config

If no file, no inline config and no `FAUXIDC__*` vars are given:

- One Issuer `default` at `http://localhost:9000/default`, in Lenient mode. The port in this URL follows `server.port`, for example `--port 9100`.
- One public Client `test`.
- Two Users `alice` and `bob` with `example.com` emails and full name claims.

`--issuer-from-host` or `FAUXIDC_ISSUER_FROM_HOST=true` sets `issuer_from_host` on every Issuer. It keeps Zero config, as other flags do. Other values than `true` and `false` are a config error.

### 5.7 `fauxidc config`

- `fauxidc config` prints the merged config with the source of each value (default, `file:line`, inline, env, flag), then exits. Secrets are masked: each `client_secret`, and the private members of a JWK in a Client `jwks` (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`).
- `GET /_mock/config` shows the running config the same way, as JSON. It follows hot reload. Section 10 and `docs/test-api.md` have the details.
- `fauxidc config --check` only validates. Exit 0 or 2. For CI.
- `fauxidc config --schema` prints the JSON Schema (draft 2020-12) of the config file, derived from the config structs. It reads no config and conflicts with `--check`. The output is committed as `schema/fauxidc.schema.json`; a test fails on drift.

### 5.8 Implementation

Our own merge, about 200 lines. Parse each source to `toml::Value`, deep-merge, keep a source map, then deserialize with `deny_unknown_fields`. `figment` (no release since 2024-05) and `config` (lowercases keys, no per-value source) do not meet 5.3 and 5.7. ADR required (section 13).

### 5.9 Config writes

The Test API (`/_mock/users`, `/_mock/clients`) and `fauxidc users`, `fauxidc clients` change Users and Clients in the config file (ADR 0008):

- The write target is the last config file (5.1, source 2). With no file, a write fails: 409, or exit code 1.
- A write to an entry fails if any value of the entry comes from another source (an earlier file, inline config or an env var). The error names the source.
- The file keeps its comments and formatting (`toml_edit`). The new config is loaded and checked before the file changes. On an error the file does not change.
- The write is atomic: a temporary file in the same directory, then a rename.
- On the server, the change applies at once, without the file poller. If it does not apply, the old file text is written back.
- The CLI needs no running server. A running server applies the change with its hot reload.
- Clients are named by their config key, not by `client_id`. Reads mask the secrets as in 5.7: `client_secret` and the private JWK members in `jwks` are `"***"`. A write adds only the fields that differ from the default.
- `GET /_mock/clients` also lists the Lenient-registered Clients with `"lenient": true`. They are in memory only, so a write to one gives 409.

## 6. Clients and checks

### 6.1 Strict mode (default)

- Unknown `client_id`: error page at `/authorize`, `invalid_client` at `/token`.
- `redirect_uri`: exact match. One `*` is allowed only as the last path segment. Scheme, host and port always match exactly. On a mismatch, the mock shows an error page and never redirects.
- Client secret: checked for confidential Clients.
- PKCE: required for public Clients. Confidential Clients need it only with `require_pkce = true`. A wrong verifier returns `invalid_grant`.
- `nonce`: if sent, it is echoed in the id_token. `require_nonce = true` rejects an authorize request with no `nonce`.
- `offline_access`: a refresh token is issued only with this scope, and only if the Client allows the `refresh_token` grant (M2).
- Unknown scope on `client_credentials`: `invalid_scope` (M2).
- Each failure logs the rule that failed, for example `redirect_uri not registered: http://...`.

### 6.2 Lenient mode (`lenient = true` per Issuer)

- All checks in 6.1 only log a warning.
- An unknown Client is accepted and registered in memory.
- A refresh token is always issued.
- `/introspect` and `/revoke` need no client authentication.
- CORS reflects any origin.

### 6.3 Client authentication

- M2: `client_secret_basic`, `client_secret_post`, `none`.
- M3: `private_key_jwt` with a Client `jwks` or `jwks_uri`.
- Assertion `alg` (after M4): RS256, RS384, RS512, PS256, PS384, PS512, ES256 and ES384 (M3: RS256, PS256 and ES256). A Client key is an RSA key, an EC P-256 key (ES256) or an EC P-384 key (ES384). Discovery lists these algorithms in `token_endpoint_auth_signing_alg_values_supported`, `introspection_endpoint_auth_signing_alg_values_supported` and `revocation_endpoint_auth_signing_alg_values_supported`.
- `jwks_uri` (M4): the fetched set is cached for 60 s. An unknown `kid` refetches it, at most once every 10 s per URL. A key with a `use` other than `sig` is not used to verify an assertion.
- Discovery lists only the supported methods.

## 7. Keys and signing

- RS256 in M1. One key shared by all Issuers, with one `kid`.
- Key source order: `FAUXIDC_KEY_PEM`, then `server.key_file` if the file exists, then generate.
- Generation runs on a background task after the listener binds. JWKS, `/token` and the Test API token endpoint wait for the key. Discovery does not wait. If `key_file` is set and writable, the generated key is saved there, unless the server stops before generation ends. Then no key is saved, and the next start generates a new key.
- After M4: RS384, RS512, PS384, PS512 and ES384. The RSA algorithms (RS* and PS*) use an RSA 2048 key, ES256 a P-256 key and ES384 a P-384 key. RS256 stays the default, and only RS256 Issuers share the server key. A `key_file` key that does not fit the `signing_alg` (another key type or another curve) is a config error at startup and at reload. A rotated key has the Issuer's `signing_alg`. Discovery `id_token_signing_alg_values_supported` lists only the configured algorithm.
- M3: per-Issuer keys, ES256 and PS256. `POST /_mock/{issuer-id}/rotate-key` adds a new active key and keeps the old one in JWKS. `?retire=true` removes the old key. An Issuer keeps at most 10 keys; a rotation above the cap removes the oldest key. M4: a request with an `Origin` header that is not the server's own origin (scheme + `Host`) gets 403 `access_denied`, so a web page cannot rotate the keys. A request without `Origin` is not affected.

## 8. Users and claims

### 8.1 Claim merge order

Later wins:

1. Issuer `default_claims`.
2. `sub` from the Issuer `sub_template` (placeholder `{user_id}`). Default `sub` is the User id.
3. User `claims`. An explicit `sub` here wins over the template.
4. User per-Issuer claims (`[user.<id>.issuer.<issuer-id>]`).
5. Client `id_claims` / `access_claims`.
6. Claim overrides from the login page, or Custom user claims.
7. Protocol claims: `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `azp`, `jti`, `sid`, `client_id`, `scope`. These can never be overridden.

### 8.2 Scopes

- `profile` releases the OIDC profile claims (`name`, `given_name`, `family_name`, `nickname`, `picture`, ...).
- `email` releases `email` and `email_verified`.
- Custom claims (not defined in OIDC Core) are always included.
- The same rule applies to the id_token and `/userinfo`.

### 8.3 Login page

- A dropdown of Users (by `label`), and a "Custom…" option for a Custom user (`sub` + claims JSON).
- With `issuer.<id>.custom_user`, "Custom…" (or its `label`) shows one `username` field instead: `sub` is the username (trimmed, lowercase), and the claims are the template with `{username}` filled in every string value.
- A collapsed "Override claims" JSON field for Claim overrides.
- Shows the `client_id` and the Issuer id.
- Checkbox "Remember me and skip this page" (Auto-select). It sets a cookie per Issuer with the User id. The next `/authorize` signs in that User with no page. `prompt=login` still shows the page. Logout clears the cookie. The debugger page has a "Signed in as … · change" link that clears it.
- `login_hint=<user id>` with `auto_login = true` signs in that User at once. This is for E2E tests.
- `issuer.<id>.show_user_list` (default false) opens the login page on the User dropdown.

## 9. Tokens

- id_token: JWT, signed.
- Access token: always a JWT in RFC 9068 shape (`typ: at+jwt`). `aud` comes from the `audience` / `resource` parameter, else the Client `audience`, else `client_id`. More than one `audience` or more than one `resource` parameter gives 400 `invalid_request` (M4), in both modes and for every grant type.
- Refresh token: signed JWT. It carries the User id plus any Claim overrides or Custom user claims. On refresh, claims are merged again from the current config (M2).
- Rotation (M2): on by default per Client. Using an old refresh token again returns `invalid_grant`, unless it is within `refresh_reuse_leeway_secs` (default 0). No family revocation.
- `client_credentials` (M2): `sub = client_id`, claims from Client `access_claims`. No id_token and no refresh token.
- Fixed clock (after M4): `server.fixed_time` sets the server clock to one RFC 3339 time, in whole seconds. The clock does not advance. Every issued time uses it: `iat`, `exp`, `auth_time`, `expires_in`, the code and refresh token lifetimes and the Session `auth_time`. Every check of token time uses it too: code expiry, refresh token `exp`, `max_age`, the client assertion `exp` and `nbf` (`private_key_jwt`), the jwt-bearer and token exchange `exp`, `/introspect`, `/userinfo`, `/revoke`, the revocation list, the refresh reuse window and the `/debugger` expiry note. Empty: the system clock. A reload applies a new, changed or removed value. There is no Test API route for it. See ADR 0007.
- Token exchange (M3): if the subject token is a JWT from any fauxidc Issuer, the mock verifies the signature and `exp`. In Strict mode, any other token is rejected. In Lenient mode it is accepted unverified. The result has `sub` and User claims from the subject token, and `aud` from `audience` / `resource`. An `act` claim is added only when an `actor_token` is sent.
- Token exchange token types (M4): `subject_token_type` and `actor_token_type` must fit the token. `...:access_token` needs the header `typ` `at+jwt`, `...:id_token` needs another `typ`, `...:jwt` accepts any. Strict mode rejects a mismatch; Lenient mode logs a warning.
- Token exchange `may_act` (M4): when the subject token has `may_act.sub` and an `actor_token` is sent, the actor `sub` must equal it (RFC 8693 4.4). Strict mode rejects a mismatch; Lenient mode logs a warning.
- jwt-bearer grant (after M4, RFC 7523 section 2.1): the Client must list `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types`. It is not a default grant. The `assertion` is checked like a token exchange subject token: Strict mode verifies a JWT of any fauxidc Issuer (signature, `exp`, revocation, no refresh token); Lenient mode uses a JWT that fails the check unverified, with a warning. A rejected assertion gives `invalid_grant`. `scope` is the `scope` parameter, else the assertion `scope` claim; without both, `invalid_scope` in both modes. The result is an access token only, with `sub` and the User claims of the assertion and `aud` as for the other grants. No id_token, no refresh token and no `act` claim.
- Default lifetimes: id_token and access token 1 h, refresh token 24 h, code 60 s. They can be set per Issuer and per Client.

## 10. Endpoints

Paths are below the Issuer path unless they start with `/_mock`.

| Endpoint | Behavior | Milestone |
|---|---|---|
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` (both forms) | Discovery. CORS `*`. | M1 |
| `/jwks` | JWKS. CORS `*`. | M1 |
| `/authorize` | Code flow, PKCE, `state`, `nonce`, `login_hint`, Auto-select. `response_mode` `query` (default) and `form_post` (after M4, section 10.1). | M1, after M4 |
| `/token` | `authorization_code` (M1). `client_credentials`, `refresh_token` (M2). Token exchange (M3). jwt-bearer (after M4). | M1 to M3, after M4 |
| `/userinfo` | Bearer access token. Scope-filtered claims. | M1 |
| `/endsession` | `id_token_hint` optional. In Strict mode, `post_logout_redirect_uri` must match the Client, which is found by `client_id` or `id_token_hint`. With no redirect: "signed out" page. `state` passed through. Clears the Session and the Auto-select cookie. Aliases apply. | M2 |
| `/introspect` | Requires an authenticated confidential Client of the same Issuer. | M2 |
| `/revoke` | Confidential Clients, or public Clients by `client_id` for their own tokens. Limitation: a revoked JWT stays valid for resource servers that verify it locally. Only `/introspect` sees the revocation. | M2 |
| `/debugger` | Decodes a pasted JWT and checks it against this Issuer's JWKS. Runs a code + PKCE flow with a built-in `debugger` Client and shows the decoded tokens. M4: the built-in Client allows only the exact callback URL that `/debugger/start` builds, and needs PKCE S256 in both modes. `/debugger/start` sets the cookie `fauxidc_debugger_<issuer id>` with the flow `state`; without the matching cookie the callback gives 400. The server keeps at most 10 000 pending flows and drops the one that expires first. `?embed=1` on the page, the form post and `/debugger/start` hides the brand row and the footer for the dashboard frame; a flow started with it ends on the embedded callback page. `X-Frame-Options: SAMEORIGIN`, `Content-Security-Policy: frame-ancestors 'self'` (5.5). | M3, M4 |
| `GET /_mock/` | Admin dashboard: one HTML page for every Test API operation, built on the JSON routes. Its Debugger section shows the `/debugger` page of the chosen Issuer (`?embed=1`) in a same-origin frame, with an Issuer select (in the URL fragment, for example `#debugger/default`) and an "Open in new tab" link. `GET /` and `GET /_mock` redirect to it when no Issuer route is at that path. `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`. | after M4 |
| `GET /_mock/health` | Health check. | M1 |
| `POST /_mock/{issuer-id}/token` | Issues tokens without a browser: User id, extra claims, `expires_in` (negative allowed). | M2 |
| `GET /_mock/requests?issuer=&path=`, `DELETE /_mock/requests` | Request log. Ring buffer of `request_log_size`, raw bodies. | M2 |
| `POST /_mock/{issuer-id}/rotate-key` | Key rotation. A foreign `Origin` header gives 403 `access_denied` (M4). | M3, M4 |
| `POST /_mock/{issuer-id}/fail-next` | Injected failure: `{endpoint, status, error, count, delay_ms}`. | M3 |
| `POST /_mock/reload` | Reloads the config files at once (section 11). 200 `{changed, warnings}`, 422 `invalid_config` with `errors`, 409 with no config file. A foreign `Origin` header gives 403. | after M4 |
| `GET /_mock/config` | The running config as `{config, sources}`, with the masking of 5.7. The sources come from a new load of the config inputs. A value that the new load does not give (a restart-only key changed in a file, a change before the next poll, a server without load inputs) has the source `unknown`. `?format=toml` gives TOML without sources. | after M4 |

CORS (M2) on `/token`, `/userinfo` and `/revoke`: allowed origins come from the Client `web_origins`. If `web_origins` is not set, the origins of its redirect URIs are allowed.

### 10.1 `response_mode` (after M4)

- `query` (or no `response_mode`, or an empty value): a 302 to the `redirect_uri` with the response in the query. No change.
- `form_post`: a 200 HTML page (`form_post.html`, `Cache-Control: no-store`) with a form that a script posts to the `redirect_uri`. A visible submit button is the fallback without JavaScript.
  It posts the same parameters as the query: `code` and `state`, or `error`, `error_description` and `state`. `state` is sent only when the request has it. All values are HTML-escaped.
- The `redirect_uri` check is the same for both modes. An error before the `redirect_uri` is trusted (unknown Client, `redirect_uri` mismatch) stays an error page, also with `form_post`.
  An error after it (for example `unsupported_response_type`, `invalid_request`, `login_required`) uses the response mode of the request.
- `form_post` with a `redirect_uri` that is not `http://` or `https://` (for example `com.example.app:/cb`) gives an error page with `invalid_request`. Only Lenient mode can reach this check, because a configured Client has only `http` and `https` redirect URIs; it is an error there too, not a warning.
- An unknown `response_mode` (also `fragment`) gives `invalid_request`, in both modes (not only a warning in Lenient mode). The `redirect_uri` is already trusted, so it is a 302 with the error in the query, as for the other parameter errors.
- The built-in `debugger` flow always uses `query`. Its callback accepts only `GET`.

## 11. Runtime state

- In memory: codes (single use, TTL), Sessions, used refresh token `jti`s, the revocation list, the Request log, Injected failures, Lenient-registered Clients. All of it resets on restart.
- `DELETE /_mock/state` resets it without a restart: all of the above, used client assertion `jti`s, debugger flows and the Client JWKS cache. `?issuer=<id>` resets only the data that has that Issuer id. Config and keys do not change.
- Durable across restarts: refresh tokens and access tokens, while the signing key stays the same.
- Sessions (M3): one cookie per Issuer. `prompt=none` with a Session returns a code. Without one, it redirects with `login_required`. `prompt=login` always shows the page. `max_age` is checked against `auth_time`.
- Hot reload (M3): the mock polls config file mtimes every 1 s, applies a change when two polls in a row see the same new file state, and also reloads on SIGHUP. Env and inline config change only at restart. If the new config is invalid, the mock keeps the old one and logs the error. In-flight codes, Sessions and refresh tokens stay valid. A Session for a removed User fails at its next use. A key change needs a restart, and the mock logs a warning.
- `POST /_mock/reload` (after M4) reloads the config files at once, without the poll delay. It returns the restart warnings, or 422 with the config errors and the old config stays. It reloads files only.

## 12. Operations

### 12.1 CLI

- `fauxidc` (serve), `fauxidc config [--check]`, `fauxidc healthcheck [--url]`.
- `fauxidc users list|get|create|update|delete`: read and change the Users of the last config file (5.9). Exit 2 on invalid input or config, 1 on a conflict.
- `fauxidc clients list|get|create|update|delete`: the same for Clients. `create` and `update` read the Client from `--from <file|->` (JSON or TOML). `update --merge` merges it.
- Global flags: `--config`, `--port`, `--bind`, `--log-format`, `--issuer-from-host`.
- `clap` derive.

### 12.2 Logging

- `tracing` + `tracing-subscriber` (`fmt`, `json`, `env-filter`) + `tower-http` `TraceLayer`.
- Logs go to stderr. Text by default, `--log-format json` for CI.
- Each request gets a span with Issuer id, endpoint and `client_id`.
- At startup, the mock logs a warning when it binds to a non-loopback address: anyone who can reach it can mint tokens and use the dashboard at `/_mock/`.

### 12.3 Distribution

- GitHub Releases: static musl binaries (x86_64, aarch64) and macOS binaries. Each archive has the binary, the licenses, `README.md` and `examples/`.
- Image `ghcr.io/schmas/fauxidc`, multi-arch, `FROM scratch`, `WORKDIR /config`, `EXPOSE 9000`, entrypoint `fauxidc --bind 0.0.0.0` (a later `--bind` wins), the example configs in `/examples/`, `HEALTHCHECK CMD ["/fauxidc","healthcheck"]`. With no mount and no env, it starts Zero config.
- crates.io: each release publishes the `fauxidc` crate. Install options: `cargo install fauxidc --locked`, `cargo install --git https://github.com/schmas/fauxidc --locked` (from source), the GitHub release binaries, or the image.
- No Homebrew tap until someone asks for it.

### 12.4 TLS

None in M1 and M2. M3 adds an optional `tls` cargo feature with `rustls` (ring) and `tokio-rustls`, off by default. The default build, the release binaries and the image do not include it. At most 256 TLS handshakes run at once (M4); more clients wait until one ends.

## 13. Project standards

### 13.1 Repo

- Name `fauxidc` ("faux" + "OIDC") for the repo, crate, binary and image. Owner `schmas`. License MIT OR Apache-2.0.
- One crate with `src/lib.rs` + `src/main.rs`. The lib exposes `fauxidc::Server::start(config).await`, which returns the bound address, for in-process use in Rust tests. The lib API is marked unstable before 1.0.
- Root files: `README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `CHANGELOG.md` (generated), `CONTRIBUTING.md` (mentions `bacon`), `AGENTS.md`, `SECURITY.md`. `SECURITY.md` says: never trust a fauxidc Issuer in production.
- `examples/`: `auth0.toml`, `okta.toml`, `generic.toml`, `keycloak.toml`, `entra.toml`, `cognito.toml`, `docker-compose.yml`. Neutral names only (`example-app`, `alice@example.com`).
- `docs/adr/` with the ADRs in 13.6.

### 13.2 Stack

`AGENTS.md` lists only the pinned or unusual choices in its "Tech Stack" section. This table and the rejected crates stay here. A new dependency needs a reason in the PR.

| Domain | Crate |
|---|---|
| Runtime | `tokio` (`current_thread`); JWT signing on the blocking pool (ADR 0005) |
| HTTP | `axum` 0.8, `tower-http` |
| JWT | `jsonwebtoken` with `rust_crypto` (not `aws_lc_rs`) |
| Keys | `rsa`, `p256`, `p384` (ES384, after M4) |
| Data | `serde`, `serde_json`, `toml` |
| Config schema | `schemars` |
| Templates | `minijinja`, `rust-embed` |
| CLI | `clap` derive |
| Logs | `tracing`, `tracing-subscriber` |
| Errors | `thiserror` v2 (lib), `anyhow` (`main.rs` only) |
| IDs, random | `uuid` v4 (`jti`, `sid`), `rand` / `getrandom` |
| Statics | `std::sync::LazyLock` |
| Time | `std::time` (Unix seconds only); `time` with only the `parsing` feature, to read `server.fixed_time` (after M4) |
| Locks | `std::sync::Mutex` |
| Hot reload (M3) | `arc-swap` |
| TLS (M3, optional, `tls` feature) | `rustls` (ring), `tokio-rustls` |
| Dev only | `reqwest`, `openidconnect` |

Rejected, with reason:

- `figment` / `config`: see 5.8.
- `jiff`: no date formatting needed. Add it if `/debugger` needs one. `time` reads `server.fixed_time`, because `jsonwebtoken` already depends on it.
- `color-eyre` / `miette`: the main user errors are config errors, and `toml` already prints them with spans. Use `miette` for config only if those errors read poorly.
- `parking_lot` / `dashmap`: there is no contention on a `current_thread` runtime.
- `dotenvy`: docker-compose already reads `.env`. A mock that reads `.env` on its own is surprising.
- `utoipa`: the Test API is small. The README documents it.
- YAML crates: no maintained standard crate.
- `josekit`, `openssl`, `aws-lc-rs`: C toolchain, no clean musl static build.
- `cargo-dist`: our own release workflow is small.

### 13.3 Errors

- Typed `thiserror` errors in the lib. Config errors carry their source.
- `OAuthError` implements `IntoResponse`. It returns the RFC error JSON, or a redirect with `error` when a redirect is allowed. With `response_mode=form_post`, `/authorize` sends the same error by the form_post page (after M4).
- No `unwrap()` / `expect()` outside tests and startup invariants. Clippy `unwrap_used` and `expect_used` are set to deny.

### 13.4 Toolchain and lints

- Edition 2024. `rust-toolchain.toml` pins stable. MSRV = stable minus 2, checked in CI.
- `#![forbid(unsafe_code)]`.
- `rustfmt` default. `clippy -D warnings`, `pedantic` at warn, allowed lints listed in `Cargo.toml` `[lints]`.
- `cargo-deny`: licenses (MIT, Apache-2.0, BSD, ISC only), advisories, duplicate crates.
- Release profile: LTO, `opt-level = "z"`, `codegen-units = 1`, strip, `panic = "abort"`.

### 13.5 Tests and CI

- Unit tests next to the code.
- Integration tests in `tests/`, run on the router with `tower::ServiceExt::oneshot`. No network.
- Compatibility tests use the `openidconnect` crate as a real relying party (code + PKCE).
- OIDF conformance suite in CI from M2.
- `cargo-nextest` in CI.
- GitHub Actions jobs: fmt, clippy, test (Linux + macOS), deny, MSRV, musl build with checks on binary size and startup time. A regression past the targets fails CI.
- `release-plz` handles versions, CHANGELOG, tags and the GitHub release, from Conventional Commits, in registry mode: it reads the last version from crates.io and publishes the crate there with crates.io trusted publishing: the release job runs in the `release` GitHub environment with `id-token: write`, and `rust-lang/crates-io-auth-action` exchanges the OIDC token for a short-lived crates.io token. When it creates a release, the release workflow builds the release binaries and the multi-arch image.

### 13.6 ADRs to write

1. Fixed `iss`, with discovery endpoint URLs derived from the request `Host`.
2. Our own layered config merge instead of `figment` / `config`.

## 14. Milestones

### M1: login works with standard clients

- Config: all 5 sources, keyed tables, unknown-key errors, `fauxidc config [--check]`, Zero config.
- Issuer routing, discovery (all 3 paths), JWKS, RS256 key (env, file, or background generation).
- `/authorize` with the login page, Custom user, Claim overrides, Auto-select, `login_hint` + `auto_login`, Strict and Lenient mode, PKCE, `nonce`.
- `/token` (`authorization_code`), `/userinfo`, scope-based claims, RFC 9068 access tokens.
- Template and static overrides.
- `/_mock/health`, `fauxidc healthcheck`, non-loopback warning, logging.
- Static image, release workflow, CI with size and startup checks.
- Exit test: an Auth.js app logs in through both example configs (`auth0.toml` and `okta.toml`). A Spring resource server accepts the access token when its JWT decoder allows `typ: at+jwt`. The default validator in Spring Security 7.x accepts only `JWT`; `docs/testing/m1-exit-test.md` shows the decoder setup. The `openidconnect` compatibility test passes.

### M2: full OAuth surface for tests

- `client_credentials`, refresh with `offline_access`, rotation and reuse check.
- `/endsession` with aliases, `/introspect`, `/revoke`, client auth methods.
- `paths` overrides, CORS.
- Test API: token issue, Request log.
- OIDF conformance suite in CI.
- Exit test: auth0-spa-js and oidc-client-ts SPAs log in, refresh and log out. The OIDF "Basic OP" and "Config OP" plans pass.

### M3: advanced

- Token exchange, Sessions with `prompt` and `max_age`, hot reload, `/debugger`.
- Per-Issuer keys, ES256 and PS256, key rotation, `private_key_jwt`.
- Injected failures.
- Optional `tls` feature.
