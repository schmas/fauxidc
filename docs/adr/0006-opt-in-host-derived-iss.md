# 6. Opt-in `iss` derived from the request host

Date: 2026-11-15
Status: accepted. Amends [ADR 0001](0001-fixed-iss-host-derived-endpoints.md).

## Context

ADR 0001 fixes `iss` to `issuer_url`. This breaks tests that reach fauxidc on a random host port.
Testcontainers maps the container port 9000 to a port such as 49153.
A client with its issuer set to `http://localhost:49153/default` rejects the discovery `issuer` `http://localhost:9000/default`.

`navikt/mock-oauth2-server` always builds `iss` from the request URL.
Its introspect and userinfo endpoints accept only a token whose `iss` equals the issuer of the current request.

## Decision

- A new per-Issuer key `issuer_from_host`, default `false`. With `false`, ADR 0001 applies unchanged.
- With `true`, `iss` and the discovery `issuer` are the endpoint base of the request: the same order as the
  discovery endpoint URLs (Issuer `public_base_url`, server `public_base_url`, trusted forwarded headers,
  `Host`, the origin of `issuer_url`), plus the Issuer path.
  If `issuer_url` ends with `/`, the value also ends with `/`.
- `issuer_url` stays required. It gives the Issuer path for routing, the trailing slash and the fallback without a `Host` header.
- fauxidc checks its own tokens against the `iss` of the current request only. This applies to introspect, revoke,
  userinfo, refresh, `id_token_hint`, token exchange, the debugger and the `private_key_jwt` audience.
  A token minted through `localhost:49153` fails when it is checked through `fauxidc:9000`. This matches the upstream behavior.
- Forwarded headers still need `server.trust_forwarded_headers = true`. Upstream always trusts them; fauxidc does not.
- Zero config keeps the fixed `iss`. The flag `--issuer-from-host`, or the env var `FAUXIDC_ISSUER_FROM_HOST=true`,
  sets `issuer_from_host` on every Issuer. Unlike a `FAUXIDC__*` env var, it keeps Zero config.

## Consequences

- Testcontainers setups work with the Zero config Client and Users, with one env var.
- The default stays as in ADR 0001, so a browser and a container still share one `iss`.
- With `issuer_from_host`, one token is valid only through the host that minted it. Clients that verify `iss`
  must use the same host for login and for token checks.
