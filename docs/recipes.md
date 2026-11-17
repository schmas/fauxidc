# Recipes

Short recipes for common setups. The [README](../README.md#start-in-60-seconds) shows how to install and start fauxidc.

The recipes use [examples/generic.toml](../examples/generic.toml). Start fauxidc with it:

```sh
# Docker: the image has the examples in /examples/
docker run --rm -p 9000:9000 ghcr.io/schmas/fauxidc --config /examples/generic.toml
# Binary: download the file (the release archive has it in examples/ too)
curl -sO https://raw.githubusercontent.com/schmas/fauxidc/main/examples/generic.toml
fauxidc --config generic.toml
# Checkout
cargo run -- --config examples/generic.toml
```

## SPA with PKCE

`generic.toml` has the public Client `spa` with the redirect URI `http://localhost:5173/`.
Configure your OIDC library with these values:

| Setting | Value |
| --- | --- |
| Authority (Issuer URL) | `http://localhost:9000/generic` |
| Client id | `spa` |
| Redirect URI | `http://localhost:5173/` |
| Scope | `openid profile email` (add `offline_access` for a refresh token) |

A public Client needs PKCE in Strict mode. The library sends `S256` for you.
CORS on `/token`, `/userinfo` and `/revoke` allows the Client `web_origins`, or the origins of its `redirect_uris` when `web_origins` is not set.
With `auth0-spa-js` and `useRefreshTokens`, see the note in [configuration.md](configuration.md#examples).

## Backend with a client secret

`generic.toml` has the confidential Client `web` (secret `local`) with the redirect URI `http://localhost:3000/callback`.
Your backend sends the browser to `/authorize`, the User picks `alice` or `bob`, and the backend exchanges the code:

```sh
curl -s http://localhost:9000/generic/token -u web:local \
  -d grant_type=authorization_code \
  -d code="$CODE" \
  -d redirect_uri=http://localhost:3000/callback
```

The Client can also send the secret in the body (`client_secret_post`) or use `private_key_jwt`.
See [features.md](features.md#private_key_jwt).
A backend that wants the code in a POST body (for example ASP.NET Core) can send `response_mode=form_post`.
See [features.md](features.md#response_modeform_post).

## Machine-to-machine

`generic.toml` has the Client `service` with the `client_credentials` grant, the scope `api`
and the audience `https://api.example.test`:

```sh
curl -s http://localhost:9000/generic/token -u service:local \
  -d grant_type=client_credentials -d scope=api
```

## Mint a token in a test

The Test API issues tokens without a browser. Your test code calls it before it calls your API:

```sh
curl -s http://localhost:9000/_mock/generic/token \
  -H 'content-type: application/json' \
  -d '{"user": "alice", "claims": {"roles": ["viewer"]}, "audience": "https://api.example.test", "expires_in": 300}'
```

Send `"sub"` in place of `"user"` for a Custom user that is not in the config.
A negative `expires_in` gives an expired token, to test that your API rejects it.
Rust tests can also start fauxidc in the same process with `fauxidc::Server::start(config).await`.
The library API is unstable before 1.0.

## Fixed time for reproducible tokens

Set `server.fixed_time = "2020-01-21T00:00:00Z"` (or `FAUXIDC__SERVER__FIXED_TIME`).
Then `iat`, `exp`, `auth_time` and `expires_in` are the same in every run, and fauxidc checks tokens with the same clock.
See [configuration.md](configuration.md#fixed-time).

## Random host port (Testcontainers)

With a mapped port, set `FAUXIDC_ISSUER_FROM_HOST=true`. Then `iss` and the discovery `issuer` use the host and port of the request,
so a client can use `http://localhost:<mapped port>/default` as its issuer. Zero config stays on.
Tokens are then valid only through the host that minted them.
See [configuration.md](configuration.md#issuer-url-and-endpoint-urls).
For JVM tests, [testcontainers.md](testcontainers.md) has the `GenericContainer` setup, the wait strategy,
a Spring Boot example and token minting from Java.

## Simulate a provider outage

Make the next two token requests fail with 503, then remove all Injected failures:

```sh
curl -s -X POST http://localhost:9000/_mock/generic/fail-next \
  -H 'content-type: application/json' -d '{"endpoint": "token", "status": 503, "count": 2}'
curl -s -X DELETE http://localhost:9000/_mock/generic/fail-next
```

Send `"delay_ms": 5000` without `status` to make an endpoint slow, not broken.
To test key rotation, call `POST /_mock/generic/rotate-key`.

## Use with an agent

The repo has an agent skill, [skills/fauxidc](../skills/fauxidc/SKILL.md). It tells a coding agent how to start fauxidc,
write a config, mint tokens, inject failures and avoid the common pitfalls.
Install it: copy or symlink the `skills/fauxidc` directory into `.claude/skills/` (one project),
`~/.claude/skills/` (all projects, Claude Code) or `~/.agents/skills/` (other agents that read it).
A second skill, [skills/fauxidc-setup](../skills/fauxidc-setup/SKILL.md), adds fauxidc to an app project once.
It asks a few questions and writes a config, a compose file, a wrapper script and a README. Install it the same way.

```sh
git clone https://github.com/schmas/fauxidc.git ~/src/fauxidc
mkdir -p .claude/skills && ln -s ~/src/fauxidc/skills/fauxidc .claude/skills/fauxidc
ln -s ~/src/fauxidc/skills/fauxidc-setup .claude/skills/fauxidc-setup
```

[llms.txt](../llms.txt) lists the docs for agents that read it.
The schema of the config file is [schema/fauxidc.schema.json](../schema/fauxidc.schema.json).
