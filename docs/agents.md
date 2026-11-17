# Use fauxidc with an AI coding agent

A coding agent (Claude Code, Codex and others) can add fauxidc to an app project, write its config,
mint tokens in tests and inject failures. This page shows what the repo gives an agent and has prompts to copy.

## What the repo gives an agent

| File | Use |
| --- | --- |
| [skills/fauxidc/SKILL.md](../skills/fauxidc/SKILL.md) | Reference skill: start fauxidc, write a config, mint tokens, inject failures, read the Request log, use the debugger, common pitfalls. |
| [skills/fauxidc-setup/SKILL.md](../skills/fauxidc-setup/SKILL.md) | Setup skill: adds fauxidc to an app project once. It asks a few questions and writes a config, a compose file, a wrapper script and a README from `templates/`. |
| [llms.txt](../llms.txt) | A list of the docs, for agents that read `llms.txt`. |
| [schema/fauxidc.schema.json](../schema/fauxidc.schema.json) | The JSON Schema of the config file. `fauxidc config --schema` prints it. |

## Install the skills

Copy or symlink the skill directories into the skills directory of your agent:

- `.claude/skills/` for one project (Claude Code).
- `~/.claude/skills/` for all projects (Claude Code).
- `~/.agents/skills/` for other agents that read it.

```sh
git clone https://github.com/schmas/fauxidc.git ~/src/fauxidc
mkdir -p .claude/skills
ln -s ~/src/fauxidc/skills/fauxidc .claude/skills/fauxidc
ln -s ~/src/fauxidc/skills/fauxidc-setup .claude/skills/fauxidc-setup
```

An agent without skills can read the docs directly. Give it the URL of `llms.txt`:
`https://raw.githubusercontent.com/schmas/fauxidc/main/llms.txt`.

## Prompts

Copy a prompt and change the names, ports and paths to match your project.
Each prompt names the fauxidc keys and routes, so the agent does not have to guess them.

### Add fauxidc to a Docker Compose dev stack

```text
Add fauxidc (image ghcr.io/schmas/fauxidc) as a local OpenID Connect provider to our docker-compose.yml.
Write devtools/local-idp/fauxidc.toml with one Issuer "app" at issuer_url "http://localhost:9000/app",
one confidential Client "example-app" (client_secret "local", redirect_uris = ["http://localhost:3000/api/auth/callback/fauxidc"])
and the Users alice and bob with email and name claims. Mount the file read-only at /config/fauxidc.toml,
publish 127.0.0.1:9000:9000, and add a healthcheck with test ["CMD", "/fauxidc", "healthcheck"].
Point the OIDC settings of the app at the issuer http://localhost:9000/app.
If the app container calls fauxidc by its service name, remember that iss stays the issuer_url.
Check the config with "fauxidc config --check" and test the login on the login page.
```

### Configure a SPA for local login with PKCE

```text
Our single-page app uses oidc-client-ts. Make it log in against a local fauxidc in Zero config:
start it with "docker run --rm -p 9000:9000 ghcr.io/schmas/fauxidc".
Use the authority http://localhost:9000/default, the public Client id "test", the code flow with PKCE (S256)
and the scope "openid profile email". Put these values in .env.development, not in the code.
Then open the app, log in as alice on the fauxidc login page and check that the app shows her email.
```

### Write an integration test that mints a token with the Test API

```text
Write an integration test for GET /api/orders of our API. Start fauxidc with examples/generic.toml
(Issuer "generic" at http://localhost:9000/generic). Before the request, mint an access token with the Test API:
POST http://localhost:9000/_mock/generic/token with the JSON body
{"user": "alice", "audience": "https://api.example.test", "claims": {"roles": ["viewer"]}}.
Send the access_token as a Bearer token and expect 200. Add a second test that mints a token with
"expires_in": -60 and expects 401. Configure the API to trust the issuer http://localhost:9000/generic
and to accept the access token header typ "at+jwt".
```

### Add a configured User with custom claims

```text
Add a User "carol" to devtools/local-idp/fauxidc.toml with the label "Carol Editor" and the claims
email "carol@example.com", email_verified true, name "Carol Editor" and roles ["editor"].
Use a [user.carol] table. Run "fauxidc config --check --config devtools/local-idp/fauxidc.toml".
fauxidc reloads the file 1 to 2 s after the save, so do not restart it.
Check with "curl -s http://localhost:9000/_mock/users" that carol is in the list.
Then log in as carol (switch "Choose a configured User" on the login page) and check that the app shows the editor role.
```

### Simulate a token endpoint failure

```text
Test how our app handles an identity provider outage. With fauxidc running on port 9000 and the Issuer "app",
make the next token request fail: POST http://localhost:9000/_mock/app/fail-next with the JSON body
{"endpoint": "token", "status": 503, "count": 1}. Run the login flow and check that the app shows
a clear error message and does not loop on redirects. Then send DELETE http://localhost:9000/_mock/app/fail-next
to remove the failure, and check that the next login works. Write this as an automated test.
```

### Run fauxidc with Testcontainers in a JVM test

```text
Our Spring Boot resource server needs a test identity provider. In the integration tests, start
ghcr.io/schmas/fauxidc with Testcontainers (GenericContainer, withExposedPorts(9000)).
Set the env var FAUXIDC_ISSUER_FROM_HOST=true, so iss uses the mapped host port, and wait with
Wait.forHttp("/_mock/health") until the body has "key":"ready".
Set spring.security.oauth2.resourceserver.jwt.issuer-uri in a @DynamicPropertySource to
http://localhost:<mapped port>/default. Mint tokens with POST /_mock/default/token from java.net.http.HttpClient.
Follow docs/testcontainers.md in the fauxidc repo.
```

## Tips for the agent

- Prefer Strict mode in tests. Zero config is Lenient mode, so it accepts mistakes that a real provider rejects.
- The `iss` claim is always the exact `issuer_url`. An app in Docker that calls `http://fauxidc:9000/...` still gets `iss` `http://localhost:9000/...`.
- `GET /_mock/requests` shows what the app really sent, for example a wrong `redirect_uri`.
- `DELETE /_mock/state` clears codes, Sessions, Injected failures and the Request log between tests.
- The skill [skills/fauxidc/SKILL.md](../skills/fauxidc/SKILL.md) has the full list of pitfalls.
