# 1. Fixed `iss`, with discovery endpoint URLs derived from the request `Host`

Date: 2026-11-14
Status: accepted

## Context

A client library compares the discovery `issuer` and the token `iss` with its configured issuer string.
Many libraries (for example Auth.js through oauth4webapi) require an exact match, including a trailing slash.

In a local setup, one mock process is reached under more than one host name.
A browser uses `localhost:9000`. A container on the same compose network uses `fauxidc:9000`.

Some backends also read the `iss` string itself, for example to pick a token parser from a substring of it.
So the issuer path must be free to configure, and `iss` must never change.

## Decision

- Each Issuer has an exact `issuer_url`. `iss` and discovery `issuer` are always this string. They never change with the request host.
- The path of `issuer_url` decides which requests the Issuer gets. Routing ignores a trailing slash.
- Endpoint URLs in discovery use `server.public_base_url` if set (a per-Issuer override is allowed). Otherwise they use `http://` + the request `Host` header.
- `X-Forwarded-Proto` and `X-Forwarded-Host` are used only when `server.trust_forwarded_headers = true`.
- Startup fails if two Issuer paths are equal or one is a prefix of the other. `/_mock` and `/.well-known` are reserved prefixes.

## Consequences

- One process serves the browser and containers with one fixed `iss`. Clients that verify `iss` work in both places.
- Discovery documents differ per request host. Clients must use the endpoint URLs from discovery, not build them from `iss`.
- A root-path Issuer (`/`) is only possible when it is the only Issuer.
- Forwarded headers are off by default, because a mock behind no proxy must not trust them.
