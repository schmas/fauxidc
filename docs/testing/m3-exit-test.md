# M3 exit test

`docs/spec.md`, section 14, defines no M3 exit test.
This runbook and `tests/m3_exit.rs` are the M3 exit test.
The M3 scope is: token exchange, Sessions with `prompt` and `max_age`, hot reload, `/debugger`,
per-Issuer keys with ES256 and PS256, key rotation, `private_key_jwt`, Injected failures and the optional `tls` feature.

It has five parts:

1. Automated: `tests/m3_exit.rs` on real loopback sockets.
2. Automated: the OpenID Foundation conformance suite, with the Session modules passing.
3. Manual: hot reload with the real binary.
4. Manual: `/debugger` in a desktop browser.
5. Manual: the `tls` build with `curl`.

CI runs parts 1 and 2 on each push to `main` (jobs `test`, `tls` and `conformance`).
Parts 3 to 5 are manual. Record the results in the table at the end.

## Prerequisites

- A fauxidc checkout. Build it with `cargo build`.
- For part 2: Docker with Compose, git, curl and Python 3.
- For part 4: a desktop browser.
- For part 5: a C compiler (for `ring`) and `curl`.

Port 9000 must be free.

## Part 1: `tests/m3_exit.rs` (automated)

Run:

```sh
cargo test --test m3_exit
```

Expected: `1 passed`.

The test writes a `fauxidc.toml` to a temp dir with three Issuers (`auth0` RS256, `es` ES256, `ps` PS256),
the Client `example-app`, the Client `backend` (an ES256 `jwks`, the grants `client_credentials` and token exchange)
and the Users `alice` and `bob`. It starts the server on a random loopback port and watches the file every 50 ms.
Each request sends `Host: localhost:9000`. The steps run in this order:

| Step | Action | What it proves |
|---|---|---|
| 1 | `GET /es/jwks` and `GET /ps/jwks` | Each Issuer has its own key: an `EC` key and a `PS256` key. |
| 2 | `client_credentials` at `/es/token` with a `private_key_jwt` assertion | RFC 7523 Client authentication works. The access token header `alg` is `ES256`. |
| 3 | Token exchange at `/auth0/token` with the token of step 2 as `subject_token` | RFC 8693 across Issuers: fauxidc verifies a token of another fauxidc Issuer. The result has `iss` = `http://localhost:9000/auth0/` and `sub` = `backend`. |
| 4 | Sign in as alice at `/auth0/authorize`, then `prompt=none` with and without the Session cookie | A sign-in creates a Session. `prompt=none` with it returns a `code`; without it, `login_required`. |
| 5 | `POST /_mock/es/rotate-key`, introspect the step 2 token, then `?retire=true` and introspect again | Rotation keeps the old key (2 keys, `active: true`). Retire removes it (`active: false`). |
| 6 | `POST /_mock/auth0/fail-next` with `{"endpoint":"jwks","status":503}` | The next `/auth0/jwks` gets 503, the one after it 200. |
| 7 | Add the User `carol` to the file | Within 3 s the Test API issues a token for `carol`, with no restart (same address). The Session cookie of step 4 still works with `prompt=none`. |
| 8 | Write invalid TOML to the file, then a valid file with the User `dave` instead of `carol` | After 500 ms the Test API still issues a token for `carol`: fauxidc keeps the old config. Then `dave` works and `carol` gives 400: the watcher still applies the next valid file. |

## Part 2: OIDF conformance suite (automated)

CI runs the job `conformance` in `.github/workflows/conformance.yml` on each push to `main`.
`oidcc-prompt-none-logged-in` and `oidcc-id-token-hint` are no longer expected failures: they pass with Sessions.
`oidcc-max-age-1` and `oidcc-max-age-10000` pass too.
See "Known results" in [conformance/README.md](../../conformance/README.md) for the remaining entries and their reasons.

To run the suite locally: `scripts/conformance.sh`. Expected: exit code 0.

## Part 3: hot reload with the real binary (manual)

1. Copy a config: `cp examples/auth0.toml /tmp/m3.toml`.
2. Start the mock: `cargo run -- --config /tmp/m3.toml`. Note the process id (`pgrep -n fauxidc`).
3. Open the login page:
   `http://localhost:9000/auth0/authorize?client_id=example-app&response_type=code&scope=openid&redirect_uri=http://localhost:3000/api/auth/callback/auth0&state=st`.
4. In `/tmp/m3.toml`, change the label of alice to `Alice Changed` and save.
   Expected: the log shows `config reloaded` within about 1 s. Reload the page: it shows `Alice Changed`.
5. Add the line `broken [` at the end of the file and save.
   Expected: the log shows `config reload failed; keeping the old config`. The page still works.
6. Remove the line, change the label to `Alice HUP`, and send `kill -HUP <pid>`.
   Expected: the log shows `SIGHUP received` and `config reloaded`. The page shows `Alice HUP`.

## Part 4: `/debugger` in a desktop browser (manual)

Start the mock: `cargo run -- --config examples/auth0.toml`.

1. Get a token: `curl -s localhost:9000/_mock/auth0/token -H 'content-type: application/json' -d '{"user":"alice"}'`.
2. Open `http://localhost:9000/auth0/debugger`, paste the `id_token` and submit.
   Expected: the header and payload, `Signature: valid (kid ..., RS256)` and `expires in 3600 s`.
3. Click "Run login flow". On the login page, select Alice Admin, check "remember" and sign in.
   Expected: the debugger callback shows the decoded id_token and access token, both with a valid signature.
4. The page shows "Signed in as Alice Admin · change". Click "change".
   Expected: a redirect to `/auth0/debugger`, and the "Signed in as" line is gone.

## Part 5: the `tls` build (manual)

```sh
cat > /tmp/m3-tls.toml <<EOF
[server.tls]
cert_file = "$PWD/tests/fixtures/tls/cert.pem"
key_file = "$PWD/tests/fixtures/tls/key.pem"

[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"
EOF
cargo run --features tls -- --config /tmp/m3-tls.toml
```

In a second terminal:

```sh
curl --cacert tests/fixtures/tls/cert.pem https://localhost:9000/_mock/health
curl -s --cacert tests/fixtures/tls/cert.pem https://localhost:9000/auth0/.well-known/openid-configuration
```

Expected: the health check answers 200. Discovery shows `https://localhost:9000/auth0/...` endpoint URLs
and `"issuer": "http://localhost:9000/auth0/"`. The log line `listening` has `scheme="https"`.
Without `--features tls`, the same config exits with code 2 and the message
`server.tls needs a build with the tls feature (cargo build --features tls)`.

The fixture pair is a self-signed test certificate for `localhost` and `127.0.0.1`. Never use it for anything else.

## Results

| Part | Result | Date | Notes |
|---|---|---|---|
| 1. `tests/m3_exit.rs` | pass | 2026-11-15 | `1 passed` locally and in the CI jobs `test` (Linux, macOS) and `tls`. |
| 2. Conformance | pass | 2026-11-15 | CI job `conformance` green with the Session modules removed from the expected failures. |
| 3. Hot reload | pass | 2026-11-15 | The label change applied in about 0.2 s. The broken file logged `config reload failed; keeping the old config`. SIGHUP applied the fix. |
| 4. `/debugger` | pass | 2026-11-15 | Chrome desktop: decode showed `Signature: valid (kid ..., RS256)` and the expiry. "Run login flow" with Alice Admin and "remember" showed both tokens with a valid signature. "change" returned to `/auth0/debugger` without the "Signed in as" line. The layout renders correctly. |
| 5. `tls` build | pass | 2026-11-15 | Health 200 and `https://` discovery URLs with curl 8.7.1 (LibreSSL 3.3.6). |

## Clean up

Stop the mock. Remove `/tmp/m3.toml` and `/tmp/m3-tls.toml`.
