# 3. Per-Issuer key sets

Date: 2026-11-14
Status: accepted

## Context

Up to M2, one RS256 key signs the tokens of every Issuer. M3 adds ES256 and PS256 and key rotation (spec 7).
A real provider has its own keys, and a client of one Issuer must not accept the tokens of another.

Refresh tokens and access tokens are durable across restarts while the signing key stays the same (spec 11).
Existing setups use one server key from `FAUXIDC_KEY_PEM`, `server.key_file` or a generated key.
A change of the default must not make their saved tokens fail.

## Decision

- Each Issuer has a key set: one active key that signs, plus older keys that still verify. JWKS lists the active key first.
- A token is verified with the key that its header `kid` names. Without a `kid`, the active key is used. The header `alg` must equal the key's `alg`.
- `issuer.<id>.signing_alg` selects `RS256` (default), `ES256` or `PS256`. Discovery lists only this algorithm.
- An RS256 Issuer without `issuer.<id>.key_file` uses the server key, with the M1 source order. Several such Issuers share it.
- Any other Issuer has its own key: from its `key_file` if the file exists, else generated after the listener binds and saved to `key_file` when it is set. `FAUXIDC_KEY_PEM` applies only to the server key.
- Issuers with the same `key_file` share one key. A shared file needs one `signing_alg` for all its users; the server key counts as RS256.
- A rotated key (`POST /_mock/{issuer-id}/rotate-key`) lives in memory only. It is never written to a `key_file`.
- A key change in the config needs a restart (spec 11).

## Consequences

- A config with only RS256 Issuers and no `key_file` behaves as in M2: one key, the same `kid`, the same JWKS.
- Issuers with separate keys reject each other's tokens, as real providers do.
- A user who wants a separate key per RS256 Issuer sets `key_file` per Issuer.
- After a restart an Issuer returns to its configured key. Tokens signed with a rotated key stop verifying.
- `/_mock/health` reports `key: ready` only when every Issuer has its first key.
