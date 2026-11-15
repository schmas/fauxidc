# Glossary

**Issuer**: One mock authorization server. It has its own discovery document, endpoints, clients and claim defaults. One process serves many issuers.

**Issuer URL**: The exact string an Issuer puts in `iss` and in discovery `issuer`. It never changes with the request host, unless `issuer_from_host = true` (ADR 0006). Its path decides which requests the Issuer gets.

**Issuer id**: A short name for an Issuer. Config entries and the Test API use it to refer to the Issuer. It is not part of any token.

**Client**: An application allowed to request tokens from an Issuer. It is known by `client_id`, with redirect URIs and an optional secret.

**User**: A test identity declared in config. It is available to every Issuer. An Issuer can shape its `sub` and claims.

**Custom user**: An identity typed on the login page (a `sub` plus claims, or one username filled into the Issuer `custom_user` template). It exists for one login only and is never saved.

**Claim override**: Claims typed on the login page and merged on top of a User for one login. It does not create a new identity.

**Strict mode**: The default. Requests with an unknown Client, a wrong redirect URI, a wrong secret or a wrong PKCE verifier fail with the standard error.

**Lenient mode**: A per-Issuer setting. The same checks only log a warning, and an unknown Client is accepted.

**Test API**: Endpoints under `/_mock` for automated tests. They issue tokens without a browser and show the request log. They are not part of any standard.

**Session**: Proof that a browser already logged in to one Issuer. It lets `prompt=none` succeed without the login page. It also lets a request with `max_age` skip the login page when the Session is younger than `max_age`. It ends at logout or restart.

**Auto-select**: A browser preference to sign in the remembered User and skip the login page next time. It is not a Session: it does not make `prompt=none` succeed. `prompt=login` still shows the page. Logout clears it.

**Zero config**: The setup used when no config source is given: one lenient Issuer, one Client and two Users.

**Request log**: The last requests the mock received, kept for tests to read through the Test API.

**Injected failure**: An error that a test tells the mock to return on the next requests to one endpoint.
