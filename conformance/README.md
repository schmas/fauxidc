# OpenID Foundation conformance suite

CI runs two plans of the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite)
against fauxidc:

- Basic OP: `oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]`
- Config OP: `oidcc-config-certification-test-plan`

The workflow is `.github/workflows/conformance.yml`. Each run uploads the suite's result export
as the `conformance-results` artifact.

## Run it locally

You need Docker with Compose, git, curl, Python 3 and the Rust toolchain.

Python packages: the script installs the exact versions in `conformance/requirements.txt` into
`target/conformance-venv` on every run. To update them, install `httpx` and `pyparsing` in a new
venv and write its `pip freeze` output to that file.

```sh
scripts/conformance.sh
```

The script does these steps:

1. It clones the suite at `SUITE_TAG` into `target/conformance-suite`.
2. It starts the suite images (Mongo, server, nginx) and a Caddy TLS front with Docker Compose.
3. It builds fauxidc and starts it with `conformance/fauxidc.toml`.
   If `/_mock/health` does not answer within 30 s, the script prints the fauxidc log and exits 1.
4. It waits for the suite API and checks the TLS path from inside the Docker network.
5. It runs both plans with the suite's `scripts/run-test-plan.py`.
6. It stops fauxidc and runs `docker compose down -v`, also when a step fails.

The exit code is the exit code of `run-test-plan.py`. The results go to `target/conformance-results`:
one zip per plan and `fauxidc.log`.

The suite uses the public DNS name `localhost.emobix.co.uk`, which resolves to `127.0.0.1`.
If your DNS does not resolve it, add `127.0.0.1 localhost.emobix.co.uk` to `/etc/hosts`.
The suite UI is at <https://localhost.emobix.co.uk:8443/> while a run is active.

## Why a TLS front

Config OP requires `https` for every endpoint in the discovery document, and it has no override.
fauxidc has no TLS in M2 (spec 12.4). So a Caddy container with `tls internal` listens as
`https://fauxidc` on the suite network and proxies to fauxidc on the host (port 9000).
fauxidc runs with `issuer_url = "https://fauxidc/conformance"` and
`server.public_base_url = "https://fauxidc"`, so every published endpoint is `https`.

The Caddyfile sets `default_sni fauxidc`. The suite runs on Java, and Java sends no SNI for a
host name without a dot. Without `default_sni`, Caddy stops the handshake with `internal_error`.

## Files

| File | Use |
|---|---|
| `fauxidc.toml` | fauxidc config: one Issuer, three static Clients, one User with every OIDC Core 5.1 claim |
| `Caddyfile`, `docker-compose.override.yml` | The TLS front |
| `basic.json`, `config-op.json` | Suite configs: Clients and the scripted browser steps |
| `expected-failures.json` | Expected failures and warnings (see "Known results") |
| `expected-skips.json` | Expected skipped modules |
| `requirements.txt` | Pinned Python packages of the harness (`run-test-plan.py`) |

## Known results

`run-test-plan.py` fails the run on any FAILURE, WARNING or SKIPPED result that these files do
not list. A result with REVIEW needs a manual screenshot check only for a certification; it does not
fail the run.

| Module | Result | Reason | Removed by |
|---|---|---|---|
| `oidcc-scope-email` | warning | The id_token contains `email` for `scope=email`. Spec 8.2 applies the scope rule to the id_token and `/userinfo` alike. OIDC Core 5.4 permits this. | none (spec choice) |
| `oidcc-alternate-happy-flow` | warning | Same as `oidcc-scope-email`. | none (spec choice) |
| `oidcc-ensure-request-with-acr-values-succeeds` | warning | fauxidc does not issue an `acr` claim. The spec does not define `acr_values`. | none (not in the spec) |
| `oidcc-codereuse-30seconds` | warning | Code reuse does not revoke the access token. Access tokens are self-contained JWTs; spec 10 says only `/introspect` sees a revocation. | none (spec choice) |
| `oidcc-claims-essential` | warning | fauxidc does not support the `claims` request parameter (`claims_parameter_supported` is `false`). | none (not in the spec) |
| `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported` | skipped | fauxidc answers `request_not_supported`. Request objects are not supported. | none (not in the spec) |

`oidcc-prompt-none-logged-in` and `oidcc-id-token-hint` pass because a sign-in creates a
Session, and `prompt=none` with a Session returns a code (spec 11).

`oidcc-max-age-1` and `oidcc-max-age-10000` pass because `max_age` is checked against the
Session `auth_time` (spec 11). A Session older than `max_age` gives the login page and a new
`auth_time`. A Session that is not older is reused, so `auth_time` stays the same. A request
with neither `prompt=none` nor `max_age` ignores the Session and works as in M2.

## Update the expected results

An expected failure or skip that does not happen also fails the run. This is intentional: when a
fix makes a listed module pass, the run fails until you remove its entry from
`expected-failures.json` and its row from the table above.

To add an entry, run with `--verbose` (the script does). For each unexpected result, the output
prints a JSON template with `test-name`, `current-block` and `condition`. Copy the template, set
`"variant": "*"` and `"configuration-filename": "*basic.json"`, and add a row with the reason to
the table above.

## Upgrade the suite

1. Find the newest `release-v5.*` tag: `git ls-remote --tags https://gitlab.com/openid/conformance-suite.git 'release-v5.*'`.
2. Set the new default of `SUITE_TAG` in `scripts/conformance.sh`. You can also try a tag first
   with `SUITE_TAG=release-v5.x.y scripts/conformance.sh`.
3. Run the script. A new release can add checks. Fix new failures in fauxidc, or add entries with
   a reason as above.
4. Commit the tag change and the entry changes together.
