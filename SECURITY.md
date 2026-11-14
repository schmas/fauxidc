# Security

fauxidc is a mock server for local development and tests.

**Never trust a fauxidc issuer in production.** Anyone who can reach a fauxidc server can sign in as any user and mint tokens. Do not add a fauxidc issuer URL to the trusted issuers of a production system.

## Reporting a vulnerability

A bug that lets fauxidc harm the machine it runs on, or that makes it unsafe to run in a test setup, is in scope.
Report it privately through [GitHub security advisories](https://github.com/schmas/fauxidc/security/advisories/new).
Do not open a public issue for it.
