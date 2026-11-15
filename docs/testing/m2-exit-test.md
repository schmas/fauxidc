# M2 exit test

This runbook covers the M2 exit test in `docs/spec.md`, section 14:
"auth0-spa-js and oidc-client-ts SPAs log in, refresh and log out. The OIDF 'Basic OP' and 'Config OP' plans pass."

It has four parts:

1. Automated: the SPA exit test with Playwright.
2. Automated: the OpenID Foundation conformance suite.
3. Manual: both SPAs in a desktop Chrome and a desktop Firefox.
4. Manual: a `client_credentials` call and an introspection call with `curl`.

CI runs parts 1 and 2 on each push to `main` (jobs `spa-e2e` and `conformance`).
Parts 3 and 4 are manual. Record the results in the table at the end: tool versions, pass or fail, and notes.

## Prerequisites

- A fauxidc checkout. Build it with `cargo build`.
- Node.js LTS with npm.
- For part 2: Docker with Compose, git, curl and Python 3.
- For part 3: a desktop Chrome and a desktop Firefox.
- For part 4: `curl` and Python 3 (to read JSON).

Ports 9000, 5173 and 5174 must be free.

## Part 1: SPA exit test (automated)

The test is in `e2e/spa/`. It is a Node project outside Cargo.

| File | Use |
|---|---|
| `package.json`, `package-lock.json` | The pinned versions of `@playwright/test`, `@auth0/auth0-spa-js` and `oidc-client-ts` |
| `serve.mjs` | A static server with Node built-ins only. Port 5173 serves the auth0-spa-js page, port 5174 the oidc-client-ts page. |
| `auth0/index.html` | SPA with auth0-spa-js against the Issuer `auth0` (`http://localhost:9000/auth0/`) |
| `oidc/index.html` | SPA with oidc-client-ts against the Issuer `okta` (`http://localhost:9000/oauth2/default`) |
| `playwright.config.ts` | Chromium only. Starts fauxidc with both example configs and `serve.mjs`. |
| `tests/spa.spec.ts` | One test for each SPA |

Both SPAs use the public Client `example-spa` from `examples/auth0.toml` and `examples/okta.toml`.

Run:

```sh
cd e2e/spa
npm ci
npx playwright install chromium
npx playwright test
```

Expected: `2 passed`.

Playwright starts fauxidc with `cargo run` and waits up to 180 s for `/_mock/health`.
On a local run it uses a fauxidc or `serve.mjs` that already runs on the port.

Each test does these steps:

| Step | Action | What it proves |
|---|---|---|
| 1 | `DELETE /_mock/requests` and collect the browser console. | The Request log has only the requests of this test. |
| 2 | Click `#login`, sign in as alice on the mock login page. Wait for `#status` = `logged-in:alice@example.com`. | The code flow with PKCE works from a browser. The token call passes the CORS check. auth0-spa-js accepts the `iss` and the provider paths (`/oauth/token`). oidc-client-ts reads discovery with the `/v1/*` paths. |
| 3 | Click `#refresh`. Wait for a new access token `jti` in `#token`. | The Request log has a `POST` to the token path with `grant_type=refresh_token` and status 200. So the library used the refresh grant, not a second login. |
| 4 | Click `#logout`. Wait for the SPA URL and `#status` = `logged-out`. | The Request log has a 302 from the logout path. Strict mode accepted the `post_logout_redirect_uri` (auth0-spa-js sends it as the alias `returnTo`). |
| End | Check the console. | The test fails on any console error that contains `CORS`. A CORS failure shows only in the browser console. |

The token and logout paths:

| SPA | Token path | Logout path |
|---|---|---|
| auth0-spa-js | `/auth0/oauth/token` | `/auth0/v2/logout` |
| oidc-client-ts | `/oauth2/default/v1/token` | `/oauth2/default/v1/logout` |

If the test fails in CI, download the `playwright-report` artifact of the run.
Each test attaches the browser console as `console-errors`.

### Known issue: auth0-spa-js with an Issuer path

The auth0-spa-js page uses `cacheLocation: "localstorage"`, not `"memory"`.
With `"memory"` and `useRefreshTokens: true`, auth0-spa-js 2.30.0 makes the token calls in a Web Worker.
The worker accepts only the exact path `/oauth/token` on the origin of `domain`.
The example Issuer has the path prefix `/auth0`, so the worker refuses `/auth0/oauth/token` with the error `Unauthorized fetch URL`.

If your app uses `cacheLocation: "memory"` with refresh tokens, do one of these:

- Use `cacheLocation: "localstorage"` in local tests.
- Give the fauxidc Issuer no path prefix, for example `issuer_url = "http://localhost:9001/"`.

auth0-spa-js accepts an `http://` domain. It adds `https://` only to a domain without a scheme.

## Part 2: OIDF conformance suite (automated)

CI runs the job `conformance` in `.github/workflows/conformance.yml` on each push to `main`.
Each run uploads the result export as the `conformance-results` artifact.

To run the suite locally:

```sh
scripts/conformance.sh
```

Expected: exit code 0. The results go to `target/conformance-results`.

The run passes with a list of expected failures, warnings and skips.
The list and the reason for each entry are in "Known results" in `conformance/README.md`.
The two expected failures need Sessions, which come in M3.

## Part 3: SPAs in desktop browsers (manual)

The automated test runs Chromium only. This part checks a desktop Chrome and a desktop Firefox.

1. In a terminal, start the mock: `cargo run -- --config examples/auth0.toml --config examples/okta.toml`.
2. In a second terminal, install the SPA dependencies once: `cd e2e/spa && npm ci`.
3. In the second terminal, start the SPA server: `node serve.mjs`.
4. In Chrome, open the devtools. Select the Console panel and the Network panel.
5. Open `http://localhost:5173/` (auth0-spa-js).
6. Click "Log in". On the mock login page, select Alice Admin and click "Sign in".
   Expected: the status is `logged-in:alice@example.com`.
7. Click "Refresh".
   Expected: the access token `jti` changes. The Network panel shows a `POST` to `/auth0/oauth/token` with `grant_type=refresh_token` in the form data.
8. Click "Log out".
   Expected: the Network panel shows a 302 from `/auth0/v2/logout` to `http://localhost:5173/`. The status is `logged-out`.
9. Check the Console panel.
   Expected: no CORS error.
10. Do steps 5 to 9 again with `http://localhost:5174/` (oidc-client-ts).
    The token path is `/oauth2/default/v1/token` and the logout path is `/oauth2/default/v1/logout`.
11. Do steps 4 to 10 again in Firefox.

On page load, auth0-spa-js can try `prompt=none` in an iframe. fauxidc answers `login_required`, because Sessions come in M3.
The page then shows `logged-out`. This is correct.

You can also read the requests from the mock:

```sh
curl -s 'http://localhost:9000/_mock/requests?path=/auth0/oauth/token'
```

## Part 4: client_credentials and introspection (manual)

1. Write a second config file outside the repo, for example `/tmp/fauxidc-service.toml`:

```toml
[client.example_service]
issuer = "auth0"
client_id = "example-service"
client_secret = "service-secret"
grant_types = ["client_credentials"]
scopes = ["read:items"]
access_claims = { team = "backend" }
```

2. Start the mock: `cargo run -- --config examples/auth0.toml --config /tmp/fauxidc-service.toml`.
3. Get a token with the `client_credentials` grant:

```sh
curl -s -u example-service:service-secret \
  -d grant_type=client_credentials -d scope=read:items \
  http://localhost:9000/auth0/oauth/token
```

Expected: status 200 with no `id_token` and no `refresh_token`:

```json
{"access_token":"eyJ...","expires_in":3600,"scope":"read:items","token_type":"Bearer"}
```

4. Introspect the token as the confidential Client `example-app`:

```sh
AT=$(curl -s -u example-service:service-secret \
  -d grant_type=client_credentials -d scope=read:items \
  http://localhost:9000/auth0/oauth/token \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
curl -s -u example-app:local --data-urlencode "token=$AT" \
  http://localhost:9000/auth0/introspect
```

Expected (`exp`, `iat` and `jti` change for each token):

```json
{
  "active": true,
  "aud": "example-service",
  "client_id": "example-service",
  "exp": 1794708962,
  "iat": 1794705362,
  "iss": "http://localhost:9000/auth0/",
  "jti": "24195758-5126-48b5-9e59-acd99d1e04be",
  "scope": "read:items",
  "sub": "example-service",
  "team": "backend",
  "token_type": "Bearer"
}
```

5. Check these negative cases:

| Command | Expected |
|---|---|
| Step 3 with `scope=write:items` | 400 `{"error":"invalid_scope","error_description":"unknown scope: write:items"}` |
| Introspect `token=not-a-token` as `example-app` | 200 `{"active":false}` |
| Introspect as the public Client: `-d client_id=example-spa` instead of `-u example-app:local` | 401 `{"error":"invalid_client","error_description":"introspection needs a confidential client"}` |
| Revoke `$AT` as `example-service` at `/auth0/revoke`, then introspect it again | Revoke 200, then `{"active":false}` |
| Revoke `$AT` as `example-app` (another Client), then introspect it again | Revoke 200, then still `"active": true`. A token of another Client is a no-op in Strict mode. |

A revoked JWT stays valid for a resource server that verifies it locally. Only `/introspect` sees the revocation (spec 10).

## Results

| Part | Result | Date | Notes |
|---|---|---|---|
| 1. SPA exit test | pass | 2026-11-14 | `2 passed` locally (also with `--repeat-each=5`) and in the CI job `spa-e2e`. |
| 2. Conformance | pass | 2026-11-14 | CI job `conformance` green with the known results in `conformance/README.md`. |
| 3. Desktop browsers | pass | 2026-11-14 | Scripted with the same Playwright test: desktop Google Chrome through the `chrome` channel, and the Playwright Firefox build. Stock Firefox 160 was not used, because Playwright cannot drive it. Run the manual steps above to check stock Firefox. |
| 4. client_credentials and introspection | pass | 2026-11-14 | All responses as above. |

Tool versions:

| Tool | Version |
|---|---|
| Node.js | 26.13.1 locally; CI uses `lts/*` |
| `@playwright/test` | 1.64.1 |
| Chromium (Playwright) | 156.0.8078.4 |
| Google Chrome (desktop) | 157.0.8103.79 |
| Firefox (Playwright build) | 157.0 |
| `@auth0/auth0-spa-js` | 2.30.0 |
| `oidc-client-ts` | 3.5.0 |
| Conformance suite tag | `release-v5.3.4` |

## Clean up

Stop the mock and `serve.mjs`.
Remove the second config file of part 4.
To remove the SPA test files that are not tracked: `rm -rf e2e/spa/node_modules e2e/spa/test-results e2e/spa/playwright-report`.
