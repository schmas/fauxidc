# Configuration

This page has the details of the config sources, the `fauxidc config` command, the examples and the signing keys.
The full key reference is [spec.md](spec.md), section 5. The [JSON Schema](../schema/fauxidc.schema.json) lists every key.

## Sources

fauxidc reads five sources. A later source overrides an earlier one.

| Order | Source | Example |
| --- | --- | --- |
| 1 | Built-in defaults (Zero config if nothing else is set) | |
| 2 | Config files | `--config a.toml --config b.toml`, or `FAUXIDC_CONFIG`, or `./fauxidc.toml` |
| 3 | Inline config | `FAUXIDC_CONFIG_INLINE` (TOML, or JSON if it starts with `{`) |
| 4 | Env var overrides for single keys | `FAUXIDC__SERVER__PORT=9000` |
| 5 | CLI flags | `--port`, `--bind`, `--log-format` |

Every source rejects unknown keys. Invalid config stops the server with exit code 2.

## Zero config

With no config file, no inline config and no `FAUXIDC__*` env var, fauxidc starts in Zero config mode.
It has one Issuer `default` at `http://localhost:9000/default` in Lenient mode, one public Client `test`, and the Users `alice` and `bob`.
The port in the Issuer URL follows `--port`.
A `FAUXIDC__*` env var turns off Zero config, so use it together with a config that has an Issuer.
`--issuer-from-host` and `FAUXIDC_ISSUER_FROM_HOST=true` keep Zero config. See [Issuer URL and endpoint URLs](#issuer-url-and-endpoint-urls).

## The config command

- `fauxidc config` prints the merged config and the source of each value.
- `fauxidc config --check` only validates the config.
- `fauxidc config --schema` prints the JSON Schema of the config file. It reads no config.

The schema is committed as [schema/fauxidc.schema.json](../schema/fauxidc.schema.json).
For completion and key checks in an editor with Taplo or Even Better TOML, add this first line to your config file:

```toml
#:schema https://raw.githubusercontent.com/schmas/fauxidc/main/schema/fauxidc.schema.json
```

## Docker

The image entrypoint is `fauxidc --bind 0.0.0.0`, in the working directory `/config`, so it reads `/config/fauxidc.toml` when you mount one.
With no mount and no env var, it starts in Zero config mode.
Arguments to `docker run` add to the entrypoint. A later `--bind`, `--port` or `--log-format` flag wins.
In the image, change the bind address with a `--bind` argument: the entrypoint flag overrides `server.bind` and `FAUXIDC__SERVER__BIND`.
The image has the example configs in `/examples/`:

```sh
docker run --rm -p 9000:9000 ghcr.io/schmas/fauxidc --config /examples/generic.toml
```

The release archives have the same files in `examples/`.

The image `HEALTHCHECK` runs `fauxidc healthcheck`, which probes the configured port.
To change the port, set it in `/config/fauxidc.toml` (with `FAUXIDC__SERVER__PORT` as an option), not only with a `--port` flag.
The healthcheck reads only `/config/fauxidc.toml` and the env vars, not the `--config` flag.
With `--config` (for example `--config /examples/generic.toml`), `FAUXIDC__SERVER__PORT` alone does not work for the healthcheck: the healthcheck finds no Issuer and probes port 9000.
So with `--config`, keep port 9000, or mount the file at `/config/fauxidc.toml`, or override the `HEALTHCHECK` with `fauxidc healthcheck --url`.

[examples/docker-compose.yml](../examples/docker-compose.yml) runs the published image with `auth0.toml`.

## Examples

To use one of the example configs:

```sh
fauxidc --config examples/auth0.toml
```

Two example configs merge. This command serves both Issuers:

```sh
fauxidc --config examples/auth0.toml --config examples/okta.toml
```

The `examples/` directory has:

- `auth0.toml`: Issuer `auth0` at `http://localhost:9000/auth0/`, with the token path `/oauth/token`,
  the logout path `/v2/logout` and the logout alias `returnTo`.
- `okta.toml`: Issuer `okta` at `http://localhost:9000/oauth2/default`, with `/v1/*` endpoint paths
  (for example `/v1/token` and `/v1/keys`).
- `generic.toml`: Issuer `generic` at `http://localhost:9000/generic` with default paths. Clients `web`
  (confidential), `spa` (public) and `service` (`client_credentials`), and a commented Custom user template.
- `keycloak.toml`: Issuer `keycloak` at `http://localhost:9000/realms/example`, with the
  `/protocol/openid-connect/*` paths, `realm_access.roles` and `preferred_username`.
- `entra.toml`: Issuer `entra` at `http://localhost:9000/00000000-0000-0000-0000-000000000000/v2.0`, with
  `tid`, `oid`, `preferred_username` and `roles` claims.
- `cognito.toml`: Issuer `cognito` at `http://localhost:9000/us-east-1_example`, with `/oauth2/*` paths,
  `cognito:username`, `cognito:groups` and `token_use` claims.
- `docker-compose.yml`: runs the published image with `auth0.toml`.

The comments in each example name the provider behavior that a config cannot copy.

Merge only example files of one provider style. Users `alice` and `bob` are shared across files, so
their claims combine. The `iss` of every example uses `localhost`, so an app that checks a real
provider host fails.

`auth0.toml` and `okta.toml` define the confidential Client `example-app`, the public SPA Client `example-spa`
(redirect URIs `http://localhost:5173/` and `http://localhost:5174/`) and the Users `alice` and `bob`.

With `auth0-spa-js` and `useRefreshTokens`, set `cacheLocation: "localstorage"` against `auth0.toml`.
The default `"memory"` uses a web worker that accepts only `/oauth/token`. See
[testing/m2-exit-test.md](testing/m2-exit-test.md).

## Strict mode and Lenient mode

An Issuer is in Strict mode by default. Set `lenient = true` on the Issuer for Lenient mode.

- Strict mode: an unknown `client_id` fails. The `redirect_uri` must match a Client `redirect_uris` entry exactly.
  One `*` is allowed only as the last path segment. Scheme, host and port always match exactly.
  On a mismatch, fauxidc shows an error page and never redirects. Public Clients need PKCE.
- Lenient mode: the same checks only log a warning. An unknown Client is accepted and registered in memory.
  A refresh token is always issued. `/introspect` and `/revoke` need no client authentication. CORS reflects any origin.

## Issuer URL and endpoint URLs

By default, the `iss` claim is always the exact `issuer_url`. The endpoint URLs in discovery follow the request `Host`,
or `server.public_base_url` when it is set. See [ADR 0001](adr/0001-fixed-iss-host-derived-endpoints.md).
With `server.trust_forwarded_headers = true`, fauxidc reads `X-Forwarded-Host` and `X-Forwarded-Proto`.

With `issuer.<id>.issuer_from_host = true`, `iss` and the discovery `issuer` also follow the request:
they are the base of the endpoint URLs plus the trailing slash of `issuer_url`.
`issuer_url` still sets the Issuer path. Use this when the port is not known before the test starts, for example with Testcontainers.
`--issuer-from-host` or `FAUXIDC_ISSUER_FROM_HOST=true` turns it on for every Issuer and keeps Zero config.

fauxidc then accepts its own tokens only through the host that minted them.
A token minted through `localhost:49153` is inactive at `fauxidc:9000/default/introspect`.
See [ADR 0006](adr/0006-opt-in-host-derived-iss.md).

## Signing keys

Each Issuer signs with `issuer.<id>.signing_alg`: `RS256` (default), `ES256` or `PS256`.
An RS256 Issuer without `issuer.<id>.key_file` shares the server key (`FAUXIDC_KEY_PEM`, else `server.key_file`, else generated).
Any other Issuer has its own key: from its `key_file` if the file exists, else generated and saved to `key_file` when it is set.
A generated key is saved only when generation ends: if the server stops before that, no key file is written and the next start generates a new key.
See [ADR 0003](adr/0003-per-issuer-key-sets.md).

Access tokens have the JWT header `typ` `at+jwt` (RFC 9068). ID tokens have `typ` `JWT`.
