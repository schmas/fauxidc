# 7. One fixed clock for token times and token checks

Date: 2026-11-15
Status: accepted.

## Context

Tests that compare token claims, or that test time logic, need known values of `iat`, `exp`, `auth_time` and `expires_in`.
Before this decision, fauxidc used the system clock everywhere. The only control was a negative `expires_in` on the Test API.

`navikt/mock-oauth2-server` has `tokenProvider.systemTime`: an optional fixed time for the tokens it issues.
Upstream #1102 makes the checks of the server use the same clock as the issued tokens, so that a fixed time in the past
still gives a code and a refresh token that work. Upstream keeps the lifetime check of a client assertion on the real clock.

`jsonwebtoken` reads the system clock in `Validation` for `exp` and `nbf`. It has no way to pass in another time.

## Decision

- A new optional key `server.fixed_time`: an RFC 3339 date-time with an offset, for example `2020-01-21T00:00:00Z`.
  It is global, not per Issuer. Empty (the default) means the system clock, as before.
  Fractions of a second are dropped. A time before 1970 and any other format is a config error at startup and at reload.
  The env var is `FAUXIDC__SERVER__FIXED_TIME`.
- No CLI flag. The CLI flags are the highest config layer and change only at restart. A flag would hide a file change, and the reload must apply a new value.
- No Test API route. Hot reload (ADR 0004) already changes the value at runtime.
- `AppState` holds a `Clock` (system, or fixed seconds). `AppState::next` builds it again from the new config,
  so a reload applies a new, changed or removed value at once. Handlers read `AppState::now()`. There is no global static.
- One clock for everything that is token time:
  - Issued values: `iat`, `exp` and `auth_time` of ID tokens, access tokens and refresh tokens, `expires_in`,
    the code lifetime and the Session `auth_time`. One response reads the clock once, so its tokens share one `iat`.
  - Checks: code expiry, refresh token `exp`, the refresh reuse window, `max_age`, the client assertion `exp` and `nbf`
    (`private_key_jwt`), the jwt-bearer and token exchange `exp`, `/introspect` `active`, `/userinfo`, `/revoke`,
    the revocation list and the used client assertion `jti` list, and the `/debugger` expiry note.
- `exp` and `nbf` are checked by hand. `crate::clock::decode_at` turns off `validate_exp` and `validate_nbf`,
  runs `jsonwebtoken::decode` for the other checks, and then checks `exp` and `nbf` against the server clock.
  It keeps the `jsonwebtoken` rules: the `leeway`, `reject_tokens_expiring_in_less_than` and the error kinds.
  `KeySet::verify` and the client assertion check use it.
- We differ from upstream on purpose: the client assertion `exp` and `nbf` use the fixed clock too.
  A test that fixes the time also signs its assertions for that time, and one clock is easier to reason about.

### Exceptions: the system clock

These times are not token time. They stay on the system clock through `crate::clock::system_now` or `std::time`:

- The Request log entry `time`: when the request arrived.
- The `jwks_uri` cache age (60 s) and the unknown-`kid` refetch cooldown (10 s). With a fixed clock, the cache would never expire.
- The `/debugger` flow lifetime: a pending browser round trip, not a token.
- The config file reload: the poll interval, the file modification times and the debounce.
- `tokio` sleeps and timeouts: the Injected failure `delay_ms`, the `jwks_uri` fetch timeout, the TLS handshake timeout
  and accept retry, and the healthcheck timeout.

## Consequences

- With a fixed time, token claims are the same in every run. Tests can compare exact numbers.
- A fixed time in the past still gives working codes, refresh tokens, Sessions and client assertions inside fauxidc.
  A relying party checks `exp` with its own clock, so it rejects those tokens. The docs say so.
- The clock does not advance. A token never expires inside fauxidc while the time stays fixed.
  To test expiry, give a negative `expires_in` on the Test API, or move the time with a reload.
- An `exp` or `nbf` error now comes after the other `jsonwebtoken` checks. For example, an expired token with a wrong `iss`
  gives an `iss` error. Both are rejected, so only the log text changes.
- Code that needs the time must take it from `AppState::now()`. A new use of `system_now` needs a reason in this list.
