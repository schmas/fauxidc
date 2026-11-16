---
name: fauxidc-setup
description: Use when adding a local OpenID Connect / OAuth 2.0 login provider (fauxidc) to an app project, for example "add a local IdP", "mock our SSO login for local development", or "set up fauxidc in this repo".
---

# Set up fauxidc in an app project

This skill adds a working local IdP to one app project. Run the steps in order, once.
The result is a directory (default `devtools/local-idp/`) with these files, made from `templates/` in this skill:

| File | From | Content |
| --- | --- | --- |
| `fauxidc.toml` | `templates/fauxidc.toml` | One Issuer, the app Client, the Users, an optional Custom user template |
| `compose.yml` | `templates/compose.yml` | The published image on `127.0.0.1:<port>`, the config read-only, a volume for the signing key, a healthcheck |
| `idp.sh` | `templates/idp.sh` | `up`, `down`, `status`, `logs`, `token <user>`, `check` |
| `README.md` | `templates/README.md` | Issuer URL, Client id and secret, the Users, how to add a User, how to show the login page again |

For config keys, the Test API and the debugger, the `fauxidc` skill is the reference.
Terms: an Issuer is one mock provider with its own URL. A Client is an app registered with an Issuer. A User is a person on the login page.

## 1. Find the app

Read the project to find these values. Ask the person only for the values you cannot find.

- Framework and auth library (`package.json`, `pom.xml`, `build.gradle`, `pyproject.toml`, `Gemfile`, `*.csproj`).
- The app URL in development, for example `http://localhost:3000`.
- The callback path. Common defaults:

| Library | Callback path |
| --- | --- |
| Auth.js / NextAuth | `/api/auth/callback/<provider id>` |
| Spring Security OAuth2 client | `/login/oauth2/code/<registration id>` |
| ASP.NET Core OpenID Connect | `/signin-oidc` |
| OmniAuth OpenID Connect | `/auth/openid_connect/callback` |

- Where the app reads its issuer, client id and secret (env file, `application.yml`, settings module).
- Whether the app runs in Docker or on the host. See step 3 if it runs in Docker.

Done when you have the app URL, the full redirect URI and the settings file of the app.

## 2. Ask for the choices

Ask the person in one message, with a default for each:

1. Issuer id (default `local`; only `a-z`, `0-9` and `_`) and host port (default `9400`).
   Check that the port is free: `lsof -iTCP:<port> -sTCP:LISTEN` and `docker ps --format '{{.Ports}}'`. If it is in use, propose the next free port.
2. Provider style to imitate. Default: none (standard paths). Else one of the fauxidc `examples/`:
   `auth0.toml`, `okta.toml`, `keycloak.toml`, `entra.toml`, `cognito.toml`. Copy its Issuer `paths`, `sub_template`,
   `logout_param_aliases` and `default_claims` into the new Issuer table. Keep `issuer_url` from step 3.
3. The Users and their claims. Default: `alice` (role `admin`) and `bob` (role `viewer`). Use the claim names the app reads,
   for example `roles`, `groups` or a namespaced claim. Use `example.com` or `example.test` email addresses.
4. A Custom user template (a "Custom..." login option where you type any username). Default: no.
5. The target directory. Default `devtools/local-idp/`.

Done when every question has an answer or the person accepts the default.

## 3. Write the files

Copy the four templates into the target directory. Replace every `{{placeholder}}`:

| Placeholder | Value |
| --- | --- |
| `{{issuer_id}}` | The Issuer id |
| `{{port}}` | The host port |
| `{{client_id}}` | The client id the app sends, for example `example-app` |
| `{{client_secret}}` | A local secret, for example `local-secret`. Never a real secret |
| `{{redirect_uri}}` | The full redirect URI from step 1 |
| `{{app_url}}` | The app URL, without a trailing slash |
| `{{project_name}}` | The Compose project name: the app name (from `package.json`, the build file or the directory) plus `-idp` |
| `{{image_tag}}` | The latest release tag without the `v`, for example `0.4.0` |

Get the latest release tag: `gh release view --repo schmas/fauxidc --json tagName -q .tagName`.
`{username}` with single braces in the Custom user template is a fauxidc placeholder. Keep it.

Then change the copies:

- Users: one `[user.<id>]` table per User in `fauxidc.toml`. In `README.md`, list the same Users,
  and rename the `Roles` column and the `roles` claim in the `carol` example to the claim the app reads.
- Custom user: if the person said yes, remove the `#` from the `custom_user` lines.
- Provider style: add the keys from step 2.
- Redirect URI: it must match exactly (scheme, host, port, path). One `*` is allowed only as the last path segment,
  for example `http://localhost:3000/api/auth/callback/*`. If the app has more than one redirect URI, list all of them.
- Make `idp.sh` executable: `chmod +x idp.sh`.

### `issuer_url` when the app runs in Docker

The `iss` claim is always the exact `issuer_url`. The endpoint URLs in discovery follow the request `Host` (ADR 0001).
The template uses `http://localhost:<port>/<issuer id>`. That works when the app and the browser both run on the host.
If the app server runs in a container and the browser runs on the host, the two see fauxidc at different URLs.
Explain the options to the person and let them choose:

- Keep `issuer_url` on `localhost`. The app calls `http://fauxidc:9000/...` for discovery, and expects the issuer
  `http://localhost:<port>/<issuer id>`. Many libraries allow a separate expected issuer; check the auth library.
- Set `issuer_from_host = true` on the Issuer. Then `iss` follows the request host, and a token is valid only through
  the host that minted it. A token from the browser login on `localhost` fails a check through `fauxidc:9000`.
- Give both sides one URL. For example, map `fauxidc` to `127.0.0.1` in `/etc/hosts`, publish host port 9000,
  and set `issuer_url = "http://fauxidc:9000/<issuer id>"`.

Done when no `{{` is left in the four files: `grep -n '{{' <dir>/*`.

## 4. Check the config

```sh
<dir>/idp.sh check
```

It runs `fauxidc config --check` in the image. Exit 0 means the config is valid.
Exit 2 prints each error with its key. Fix the file and run it again.

## 5. Start and test

```sh
<dir>/idp.sh up                 # waits for the healthcheck and the discovery URL
<dir>/idp.sh token alice        # mints tokens with the Test API (/_mock/<issuer id>/token)
```

- Open `http://localhost:<port>/<issuer id>/.well-known/openid-configuration`: `issuer` must equal `issuer_url`.
- Decode the `id_token` from `token alice`: it must have `iss` equal to `issuer_url`, `aud` equal to the client id,
  and the claims the app reads. To check the signature too, paste it into `http://localhost:<port>/<issuer id>/debugger` in a browser.
- `docker compose ps` in the target directory shows the container as `healthy`.

Done when all three checks pass. If `up` fails, read `<dir>/idp.sh logs`.

## 6. Connect the app

Write the app settings with the names the app already reads (step 1). Put them in the local env file of the framework,
for example `.env.local` for Next.js, and check that `.gitignore` covers it. Add the names without values to the example env file if the app has one.

| Setting | Value |
| --- | --- |
| Issuer URL | `http://localhost:<port>/<issuer id>` |
| Discovery URL | `http://localhost:<port>/<issuer id>/.well-known/openid-configuration` |
| Client id | The client id from step 3 |
| Client secret | The client secret from step 3 |

Then print a short summary for the person:

- The settings above and the file you wrote them to.
- The manual next steps. For example: the app must trust the new issuer (an allow list of issuers, or an audience check);
  a resource server must accept the access token header `typ` `at+jwt`; restart the app to read the new settings.
- How to test the login: start the app, click its login button, pick a User on the fauxidc login page.

## Notes

- Strict mode is on (the default). A wrong `client_id`, `redirect_uri` or secret fails like the real provider does.
  Do not set `lenient = true` to hide an app mistake. Read the request in `GET /_mock/requests` and fix the app.
- Signing key: `server.key_file = "/data/server.pem"` is in the named volume. fauxidc writes it at the first start.
  A new container keeps the key, so tokens and the app key cache stay valid. `docker compose down -v` removes it.
- "Remember me and skip this page" sets a browser cookie. The app logout does not clear it if the app does not call
  `/endsession`. Open `http://localhost:<port>/<issuer id>/endsession` in the browser to show the login page again.
- Add a User: edit `fauxidc.toml`. fauxidc reloads it 1 to 2 s after the save. The config mount is read-only,
  so the Users Test API cannot write it. An editor that replaces the file can break a single-file bind mount; then run `idp.sh down` and `idp.sh up`.
- The Test API (`/_mock/`) has no authentication. The compose file binds `127.0.0.1` only. Keep it that way.
