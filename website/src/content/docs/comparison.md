---
title: Comparison
description: fauxidc and other mock OAuth 2.0 / OpenID Connect servers, from their own docs.
editUrl: https://github.com/schmas/fauxidc/edit/main/website/src/content/docs/comparison.md
tableOfContents: false
---

<!-- Site-only page. Update the date below when you check the sources again. -->

Many mock OAuth 2.0 / OpenID Connect servers exist. They make different choices.
This page puts the facts next to each other, so that you can select the tool that fits your tests.
Each fact comes from the README of the project. "Not in the README" means that the README does not say it.
The feature can still exist. Check the project docs before you decide.

Checked on 2026-11-17.

## The projects

- **fauxidc**: this project. Sources: the [README](https://github.com/schmas/fauxidc#readme) and the docs on this site.
- **mock-oauth2-server**: "Scriptable OAuth2/OpenID Connect server for JVM tests and Docker Compose."
  Source: the [README of navikt/mock-oauth2-server](https://github.com/navikt/mock-oauth2-server#readme).
- **oauth2-mock-server**: a configurable OAuth 2 server for automated tests, for Node.js.
  Source: the [README of axa-group/oauth2-mock-server](https://github.com/axa-group/oauth2-mock-server#readme).
- **mockoidc**: "A Mock OpenID Connect Server for Authentication Unit and Integration Tests", for Go.
  Source: the [README of oauth2-proxy/mockoidc](https://github.com/oauth2-proxy/mockoidc#readme).

All four projects are open source under the MIT license (fauxidc: MIT or Apache-2.0).
All four say that they are for tests only, not for production.

## Table

<div class="fx-compare">

| | fauxidc | mock-oauth2-server | oauth2-mock-server | mockoidc |
| --- | --- | --- | --- | --- |
| Language and runtime | Rust. Native binary, no runtime. | Kotlin, on the JVM. | TypeScript, on Node.js 22.12 or newer. | Go. |
| Distribution | Static binaries for Linux and macOS, a container image (`ghcr.io`), and a crate on crates.io. | A library on Maven Central and a container image (`ghcr.io`). | An npm package, with a library API and a CLI (`npx oauth2-mock-server`). | A Go package. Your test starts the server in the same process. |
| Config style | TOML or JSON files, an inline config, env vars and CLI flags. A JSON Schema covers every key. | A JSON config (`JSON_CONFIG` or `JSON_CONFIG_PATH`) for the standalone server. A Kotlin and Java API in JVM tests. | Options in the JavaScript or TypeScript API. CLI options. | Go code: fields of the server struct before the start. |
| Login UI | Yes. A login page with configured Users and a form for a Custom user. Custom templates are possible. | Yes. An interactive login page, on by default in standalone mode. A custom login page is possible. | No. `/authorize` redirects to the callback with no login page. | No. `/authorize` starts a session for the default User or for a queued User. |
| Test API and token minting | An HTTP Test API under `/_mock/`, for any language. An admin dashboard in the browser. A Rust library API. | In JVM tests: `issueToken` and `enqueueCallback`. In standalone mode: token callbacks in `JSON_CONFIG`. | Event hooks in JavaScript, for example `BeforeTokenSigning`, change tokens and responses. | Go API: `QueueUser` and `QueueCode`. |
| Failure injection | Yes, over HTTP: Injected failures (`fail-next`) for one endpoint. | Not in the README. | Yes, in JavaScript: event hooks can return errors, for example `invalid_grant`. | Yes, in Go: `QueueError`. |
| Conformance testing | The OpenID Foundation conformance suite plans "Basic OP" and "Config OP" run in CI. | Not in the README. | Not in the README. The README says "OIDC-conformant" for its endpoints. | Not in the README. |

</div>

## Notes

- A library that runs in the test process (mock-oauth2-server in JVM tests, oauth2-mock-server, mockoidc) gives fine control from the test code.
  It works best when the tests use the same language as the library.
- A server that runs as a separate process (fauxidc, the mock-oauth2-server image, the oauth2-mock-server CLI) works with tests in any language.
- fauxidc has no in-process library for languages other than Rust.
  Tests in other languages start the binary or the image, for example with [Testcontainers](https://testcontainers.com/).

If a fact on this page is wrong or old, open an issue or a pull request on [GitHub](https://github.com/schmas/fauxidc).
