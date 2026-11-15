# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/schmas/fauxidc/compare/v0.1.0...v0.1.1) - 2026-11-15

### Other

- *(release)* publish to crates.io with trusted publishing

## [0.1.0](https://github.com/schmas/fauxidc/releases/tag/v0.1.0) - 2026-11-15

### Added

- *(config)* add fauxidc config --schema and the committed JSON Schema
- *(login)* Custom user template with a username field; template context version 2
- *(config)* add the per-Issuer custom_user template
- *(pages)* redesign the debugger page and document the stylesheet
- *(pages)* redesign the login, error and signed-out pages
- *(tls)* add an optional tls feature with rustls
- *(debugger)* run a code + PKCE flow with the built-in debugger Client
- *(debugger)* decode and check a JWT against the Issuer keys
- *(test-api)* add Injected failures
- *(reload)* reload config on file change and SIGHUP
- *(reload)* swap the router and config at runtime with shared state
- *(authorize)* apply prompt, max_age and id_token_hint rules; require openid at userinfo
- *(authorize)* add Sessions and prompt=none
- *(token)* add actor_token and the act claim to token exchange
- *(token)* add RFC 8693 token exchange
- *(client-auth)* load private_key_jwt keys from a Client jwks_uri
- *(client-auth)* add private_key_jwt with a Client jwks
- *(test-api)* rotate an Issuer's signing key
- *(keys)* give each Issuer its own key set with RS256, ES256 or PS256
- *(keys)* add ES256 and PS256 signing keys
- *(test-api)* add request log
- *(test-api)* issue tokens without a browser
- *(cors)* allow client origins on token, userinfo and revoke
- *(introspect)* add token introspection endpoint
- *(revoke)* add token revocation endpoint
- *(endsession)* add RP-initiated logout with parameter aliases
- *(token)* add client_credentials grant
- *(token)* add refresh_token grant with rotation and reuse check
- *(token)* issue refresh tokens for offline_access
- *(router)* route endpoints from per-issuer paths and publish them in discovery
- *(config)* add endpoint paths, logout aliases and M2 client checks
- add M1 OIDC mock server ([#1](https://github.com/schmas/fauxidc/pull/1))

### Fixed

- *(release)* ship the examples in the image and archives; make the recipes work for every install path
- *(cli)* do not wait for key generation at shutdown
- *(examples)* name token gaps, add Cognito logout_uri alias, and imitate Keycloak aud, Entra scp and Cognito username
- *(pages)* wrap long errors, meet WCAG AA contrast, and fix review minors
- *(reload)* retry a config whose apply failed; tighten the debugger callback and /token body errors
- *(lint)* clear the clippy errors from the part 1 fix wave
- *(server)* https default for forwarded hosts with TLS, cap TLS handshakes
- *(token)* refetch cooldown, sig-only keys, token type, may_act and repeated audience checks
- *(keys)* normalize key file paths and do not share the env server key by file name
- *(sessions)* scope removal to the Issuer and compare id_token_hint per Client
- *(debugger)* exact callback URL, browser-bound state, S256 always, iss note
- *(test-api)* reject cross-origin rotate-key, cap keys, keep failures for the right method
- *(reload)* debounce file changes and compare with the last loaded config
- *(test-api)* DELETE fail-next for an unknown Issuer returns 404
- *(authorize)* prompt=none with max_age=0 returns login_required
- *(reload)* use Lenient-registered Clients only while the Issuer is Lenient
- *(authorize)* reuse a Session that is not older than max_age
- *(client-auth)* check nbf, Content-Length and jwks_uri userinfo
- *(introspect,revoke)* Lenient mode ignores a non-Basic Authorization header
- *(oidc)* reject request objects, accept POST authorization requests and body bearer tokens
- *(cors)* drop default ports from origins and match the /_mock prefix by segment
- *(token)* keep the original scope in a rotated refresh token after a narrowed refresh
- *(config)* name the source of duplicate endpoint paths and reject reserved or unsafe paths

### Other

- *(release)* publish the crate to crates.io with release-plz in registry mode
- *(cli)* start the SIGTERM shutdown clock after kill returns
- *(tls)* test the handshake cap on the listener with a cap of 4, so the test needs few file descriptors
- state the key save on early stop, the image bind and healthcheck limits, and the Test API custom_user rule
- *(spec)* state the M4 rules for rotate-key Origin, debugger flows, audience, jwks_uri refetch, TLS cap and scheme
- add the fauxidc agent skill and llms.txt
- rewrite AGENTS.md in the six-section format
- rewrite the README task-first with recipes and the AI disclaimer
- *(release)* stop publishing to crates.io; keep tags, GitHub releases and the image
- *(examples)* add Entra-style and Cognito-style example configs
- *(examples)* add generic and Keycloak-style example configs
- *(css)* compile page styles with Tailwind CSS v4 and daisyUI v5
- add the Sessions section, the SIGHUP note and the debugger Client note
- use OS-assigned ports in the CLI tests and keep the JWKS test listener
- *(adr)* Lenient registrations apply only while Lenient; server.tls is restart-only
- match the debugger and tls docs to the code and pin them with tests
- add the M3 exit test, runbook and SPA e2e server check
- *(cli)* read the SIGHUP test port from the log and replace the config file in one step
- *(cli)* start the SIGHUP test server on a new port when the bind fails
- say that a Session also lets a max_age request skip the login page
- sync AGENTS.md and README with M2 layout and templates
- exclude CI and test harness files from the crate package
- add M2 exit test runbook
- *(e2e)* add auth0-spa-js and oidc-client-ts exit test with Playwright
- *(examples)* add provider endpoint paths, logout aliases and an SPA client
- run the OIDF conformance suite
- *(conformance)* add OIDF conformance harness for Basic OP and Config OP
- *(token)* extract client authentication and dispatch on grant type
- scaffold fauxidc project
