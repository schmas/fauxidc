# Features

This page has the details of the protocol features. The [README](../README.md) has a short summary of each.
The full reference is [spec.md](spec.md).

## Feature list

Login with the authorization code flow, the full OAuth surface for tests and the advanced features work.

M2 features:

- Refresh tokens with `offline_access`, rotation and the reuse check.
- The `client_credentials` grant.
- `/endsession` (RP-Initiated Logout) with `logout_param_aliases`.
- `/introspect` (RFC 7662) and `/revoke` (RFC 7009).
- Client authentication methods `client_secret_basic`, `client_secret_post` and `none`.
- `paths` overrides for endpoint paths, published in discovery.
- CORS on `/token`, `/userinfo` and `/revoke` from the Client `web_origins`, else from the origins of its `redirect_uris`.
- The Test API token endpoint and the Request log.

M3 features:

- Per-Issuer keys with `RS256`, `ES256` or `PS256`, and key rotation through the Test API.
  After M4 also `RS384`, `RS512`, `PS384`, `PS512` and `ES384`.
- `private_key_jwt` client authentication (RFC 7523) with a Client `jwks` or `jwks_uri`.
- Token exchange (RFC 8693).
- The jwt-bearer grant (RFC 7523 section 2.1, On-Behalf-Of).
- Sessions: `prompt=none`, `prompt=login`, `max_age` and `auth_time`.
- Hot reload of the config files, also on SIGHUP.
- The `/debugger` page: decode a JWT, or run a code + PKCE flow and see the tokens.
- Injected failures through the Test API.
- An optional `tls` cargo feature for HTTPS.

M4 features:

- A new design for the built-in pages, and the Custom user template (`custom_user`).
- Example configs in the style of a generic provider, Keycloak, Entra and Cognito.
- `fauxidc config --schema` and the committed JSON Schema.
- Releases publish the crate to crates.io (`cargo install fauxidc --locked`).

After M4:

- [`response_mode=form_post`](#response_modeform_post) at `/authorize`.
- A fixed server clock, `server.fixed_time`, for reproducible token times.
  See [configuration.md](configuration.md#fixed-time).
- The signing algorithms `RS384`, `RS512`, `PS384`, `PS512` and `ES384`, for Issuer keys and for
  `private_key_jwt` assertions. See [configuration.md](configuration.md#signing-keys).

The exit test runbooks are in [testing/](testing/): [M1](testing/m1-exit-test.md),
[M2](testing/m2-exit-test.md) and [M3](testing/m3-exit-test.md). The M4 page checks are in [testing/m4-pages.md](testing/m4-pages.md).

## Sessions

A Session records that a User signed in at an Issuer. Sessions are in memory (at most 10 000) and reset on restart.

- The cookie is `fauxidc_session_<issuer id>`. Its Path is the Issuer path. It is `HttpOnly`, `SameSite=Lax` and lasts for the browser session.
- Every sign-in at `/authorize` creates a Session with `auth_time` set to now and a `sid`.
- `prompt=none` returns a code if a Session exists. Else it returns `login_required`.
- `prompt=login` and `prompt=select_account` always show the page.
- `max_age` reuses a Session that is not older than `max_age` seconds. `max_age=0` acts as `prompt=login`.
- A request without `prompt=none` and without `max_age` does not use the Session. Auto-select and `login_hint` with `auto_login` work as before.
- If `max_age` is sent, Session reuse wins over `login_hint` with `auto_login` and over Auto-select.
- `/endsession` deletes the Session and both cookies.

## Login page

- The built-in page opens on the Custom user form: Subject and Claims.
- The switch "Choose a configured User" shows the dropdown of the configured Users. The dropdown has no Custom user entry. An Issuer without Users has no switch.
- The switch saves the view in the cookie `fauxidc_login_view_{issuer_id}` (`list` or `form`). Its Path is the Issuer path and it lasts one year. It is not `HttpOnly`, because the page script writes it.
  The page then shows "Saved in this browser · Sign out clears it".
- `{issuer}/endsession` clears the cookie. The next `/authorize` opens on the Issuer view again.
- The start view is the first rule that applies: no Users (form); an error on the `user` field (dropdown); the posted `user` after a rejected form; a `login_hint` that names a User (dropdown); the cookie; `issuer.<id>.show_user_list`.
- `show_user_list` is `false` by default. Change it in the config, with `PUT /_mock/{issuer-id}/login` or with the Login page switch in the dashboard. See [ADR 0010](adr/0010-login-view-cookie-and-setting.md).

### Custom user template

For a Custom user from one username, set a claims template on the Issuer. The Custom user form
(label "Other…" for a custom template) then shows one `username` field instead of the subject and JSON fields:

```toml
[issuer.app.custom_user]
label = "Other…"
[issuer.app.custom_user.claims]
email = "{username}@example.test"
email_verified = true
```

`sub` is the username, trimmed and in lowercase (a `sub` in Override claims wins). `{username}` is filled in every string value, nested values too.
[templates.md](templates.md) has the template context (version 3) and the override rules.

## Hot reload

fauxidc polls the config files every second (modification time and length) and also reloads on SIGHUP.
A change applies only after two polls in a row see the same new file state, so it applies 1 to 2 s after the save.
This keeps a half-written file from being loaded. If a change fails to load or to apply, fauxidc keeps the old config and logs the error.
It tries again on SIGHUP and on the next file change that passes the same check; a poll that sees no new change does not try again.
SIGHUP reloads the config. So closing the terminal does not stop a foreground fauxidc; stop it with Ctrl-C or SIGTERM.
Env vars, inline config and CLI flags change only at restart.
`POST /_mock/reload` reloads the files at once and returns the errors or warnings ([Test API](test-api.md#reload-the-config-files)).
Codes, Sessions, refresh tokens, revocations and the Request log stay valid across a reload.
A Session for a removed User fails at its next use.
A new, changed or removed `server.fixed_time` applies at once to new tokens and to every time check.

These keys need a restart; a change logs a warning and has no effect until then:
`server.port`, `server.bind`, `server.log_format`, `server.request_log_size`, `server.key_file`,
`server.tls`, `issuer.<id>.signing_alg`, `issuer.<id>.key_file`.
See [ADR 0004](adr/0004-hot-reload-router-swap.md).

## Debugger

Each Issuer serves a debugger page at `{issuer}/debugger` (the `paths.debugger` key changes the path).

- Paste a JWT and submit the form. The page shows the header and the payload,
  checks the signature against the Issuer keys (by `kid`), and shows `exp` as "expires in N s" or "expired N s ago".
  It also compares `iss` with the Issuer URL, because Issuers that share the server key verify each other's tokens.
- "Run login flow" (`{issuer}/debugger/start?scope=...`, default scope `openid profile email`) runs the
  authorization code flow with PKCE (S256). The page then shows the decoded tokens.

The flow uses the built-in public Client `debugger`. It needs no config. Its only allowed redirect URI is the
exact debugger callback URL that `/start` builds for the request (`{issuer}/debugger/callback` on the request
host, or on `public_base_url` when it is set). It needs PKCE with S256, also in Lenient mode.
A configured Client with `client_id = "debugger"` replaces it. It must list `{issuer}/debugger/callback` in `redirect_uris`.
The PKCE verifier stays on the server for 600 s.
`/start` sets the cookie `fauxidc_debugger_<issuer id>` with the flow `state`; the callback needs it, so the flow
must finish in the browser that started it. Without the matching cookie, the callback answers 400, also for an error from `/authorize`.

The page also shows "Signed in as <label> · change" when the Auto-select cookie names a configured User.
The "change" link (`{issuer}/debugger?forget=1`) clears the cookie.
The signed-out page never shows this line, because the same response clears the cookie.

The dashboard Debugger view (`/_mock/#debugger/<issuer id>`) shows the same page in a frame, with `?embed=1`.
`?embed=1` hides the brand row and the footer. The form, "Run login flow" and "change" keep it, so the whole
login flow stays in the frame. The page allows a frame of the same origin only (`X-Frame-Options: SAMEORIGIN`).

You can replace the page with a `debugger.html` template. The default template writes its links with the `href`
filter; see [templates.md](templates.md).

## TLS

fauxidc can serve HTTPS from PEM files that you provide. This needs a build with the optional `tls` feature
(`rustls` with the `ring` provider, which needs a C compiler):

```sh
cargo build --release --features tls
```

```toml
[server.tls]
cert_file = "cert.pem"  # PEM certificate chain, server certificate first
key_file = "key.pem"    # PEM private key: PKCS#8, PKCS#1 or SEC1
```

Set both keys or neither. Relative paths resolve against the working directory, as `server.key_file` does,
not against the config file directory. fauxidc does not generate certificates.
With TLS on, discovery publishes `https://` endpoint URLs (unless `public_base_url` is set); the `iss` stays the exact `issuer_url`.
With `trust_forwarded_headers = true`, a request with `X-Forwarded-Host` but no `X-Forwarded-Proto` also gets `https://` when TLS is on.
At most 256 TLS handshakes run at once; more clients wait until one ends.
A config with `server.tls` fails with exit code 2 in a build without the feature.

```sh
curl --cacert cert.pem https://localhost:9000/_mock/health
```

The release binaries and the container image are built without the `tls` feature.

### Local certificate with mkcert

[mkcert](https://github.com/FiloSottile/mkcert) makes a local CA and certificates that your machine trusts.
Install it (`brew install mkcert` on macOS; see the mkcert README for other systems).
Then add its CA to the system trust store once:

```sh
mkcert -install
```

Run the next commands in one directory, because relative paths resolve against the working directory.
With `cargo run`, that directory is the clone.
Make a certificate for the local host names:

```sh
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1 ::1
```

Point the config at the files and use `https://` in the `issuer_url`:

```toml
[server.tls]
cert_file = "cert.pem"
key_file = "key.pem"

[issuer.app]
issuer_url = "https://localhost:9000/app"
```

Run fauxidc with the `tls` feature from a clone:

```sh
cargo run --features tls -- --config fauxidc.toml
```

Or install it from crates.io with the feature:

```sh
cargo install fauxidc --features tls --locked
fauxidc --config fauxidc.toml
```

Check it:

```sh
curl https://localhost:9000/app/.well-known/openid-configuration
```

If your `curl` does not use the system trust store, add `--cacert "$(mkcert -CAROOT)/rootCA.pem"`.

Some runtimes do not read the system trust store:

- Node.js: set `NODE_EXTRA_CA_CERTS="$(mkcert -CAROOT)/rootCA.pem"`.
- JVM: the CA must be in the JVM truststore. `mkcert -install` adds it there only when `JAVA_HOME` is set.

The container image has no `tls` feature, so this recipe does not apply to it.

## Token exchange

`/token` supports RFC 8693 token exchange (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`).
The Client must authenticate and must list the grant in `grant_types`. It is not a default grant.
`subject_token_type` is `urn:ietf:params:oauth:token-type:access_token`, `...:id_token` or `...:jwt`.

- Strict mode: the subject token must be a JWT from any fauxidc Issuer. fauxidc checks the signature
  (key by `kid` from the key set of the Issuer that `iss` names), `exp`, and the revocation list.
  A refresh token is never accepted. Any other token gives `invalid_request`.
- Lenient mode: fauxidc tries the same check. If it fails, fauxidc logs a warning and uses the claims unverified.
  A value that is not a JWT fails in both modes.

Three more rules apply:

- The token type must fit the token: `...:access_token` needs the JWT header `typ` `at+jwt`, `...:id_token` needs another `typ`, and `...:jwt` accepts any.
  Strict mode gives `invalid_request`; Lenient mode logs a warning. The same rule applies to `actor_token_type`.
- When the subject token has a `may_act` object with `sub` and an `actor_token` is sent, the actor `sub` must equal `may_act.sub` (RFC 8693 4.4), with the same Strict and Lenient behavior.
- More than one `audience` or more than one `resource` parameter gives `invalid_request` "multiple audience values are not supported", in both modes and for every grant type.

A public Client (auth method `none`) can use token exchange when it lists the grant.
fauxidc does not check the requested `scope` against the subject token or the Client `scopes`.
In Lenient mode a subject token that fails the check is still accepted, unverified, with a warning.

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

## jwt-bearer grant

`/token` supports the RFC 7523 jwt-bearer grant (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`), the On-Behalf-Of flow.
The Client must authenticate and must list the grant in `grant_types`. It is not a default grant.

- The `assertion` is checked like a token exchange `subject_token`, with the same Strict and Lenient behavior.
  A rejected assertion gives `invalid_grant` (RFC 7523 3.1). A missing `assertion` gives `invalid_request`.
- `scope` is the `scope` parameter, else the `scope` claim of the assertion. Without both, the request gives `invalid_scope`, in both modes.
- The result is an access token of this Issuer with `sub` and the User claims of the assertion.
  `aud` is `audience`, else `resource`, else the Client `audience`, else the `client_id`. There is no id_token, no refresh token and no `act` claim.

```toml
[client.orders]
client_secret = "s"
grant_types = ["urn:ietf:params:oauth:grant-type:jwt-bearer"]
```

```sh
curl -s http://localhost:9000/auth0/token -u orders:s \
  -d grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer \
  -d assertion="$ACCESS_TOKEN" \
  -d scope=orders:read \
  -d audience=https://orders.example.com
```

## response_mode=form_post

`/authorize` accepts `response_mode=query` (the default) and `response_mode=form_post`. Discovery lists both in `response_modes_supported`.

- With `form_post`, `/authorize` answers 200 with an HTML page (`Cache-Control: no-store`) instead of a 302.
  A script on the page posts a form to the `redirect_uri`. The page also shows a "Continue" button for a browser without JavaScript.
- The form has the same parameters as the query mode: `code` and `state`, or `error`, `error_description` and `state`.
- The `redirect_uri` check is the same as for `query`. If the Client or the `redirect_uri` is wrong, you get the error page and nothing is posted.
- `form_post` needs an `http://` or `https://` `redirect_uri`. A custom scheme such as `com.example.app:/cb` gives `invalid_request`.
- Any other `response_mode`, also `fragment`, gives `invalid_request` in Strict and in Lenient mode, as a redirect with the error in the query.
- The `/debugger` login flow always uses `query`.

You can replace the page with a `form_post.html` template; see [templates.md](templates.md#form_posthtml).

## private_key_jwt

A Client can authenticate with `private_key_jwt` (RFC 7523) at `/token`, `/introspect` and `/revoke`.
Give it its public keys in `client.<key>.jwks` (an inline JWK set) or `client.<key>.jwks_uri`, not both.
`jwks_uri` must be an `http://` URL; fauxidc caches the fetched set for 60 seconds and fetches it again for an unknown `kid`,
at most once every 10 seconds per URL. A key with a `use` other than `sig` is not used to verify an assertion.
The assertion `alg` must be `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256` or `ES384`.
The Client key is an RSA key for RS* and PS*, an EC P-256 key for `ES256` and an EC P-384 key for `ES384`. A Client may also have a `client_secret` and use either method.

```toml
[client.backend]
grant_types = ["client_credentials"]
scopes = ["api"]
jwks = { keys = [ { kty = "EC", crv = "P-256", kid = "backend-1", x = "...", y = "..." } ] }
# or: jwks_uri = "http://localhost:8080/.well-known/jwks.json"
```
