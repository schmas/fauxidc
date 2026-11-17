# Local IdP (fauxidc)

[fauxidc](https://github.com/schmas/fauxidc) is a local OpenID Connect provider for development.
It has no real accounts. Anyone who can reach it can get a token, so it listens on `127.0.0.1` only.

## Start and stop

```sh
./idp.sh up              # start, wait for the healthcheck and discovery
./idp.sh status          # container state and health
./idp.sh logs            # follow the log
./idp.sh token alice     # tokens for a User and the app Client id, without a browser
./idp.sh check           # check fauxidc.toml
./idp.sh down            # stop (the signing key stays in the volume)
```

## App settings

| Setting | Value |
| --- | --- |
| Issuer URL | `http://localhost:{{port}}/{{issuer_id}}` |
| Discovery URL | `http://localhost:{{port}}/{{issuer_id}}/.well-known/openid-configuration` |
| Client id | `{{client_id}}` |
| Client secret | `{{client_secret}}` |
| Redirect URI | `{{redirect_uri}}` |

## Users

The login page opens on a form for any username. Use the switch "Choose a configured User" to pick one of these Users. There are no passwords.

| User | Email | Roles |
| --- | --- | --- |
| `alice` | `alice@example.com` | `admin` |
| `bob` | `bob@example.com` | `viewer` |

To add a User, add a `[user.<id>]` table to `fauxidc.toml`.
Run `./idp.sh check`. fauxidc reloads the file 1 to 2 s after the save.
If the change does not apply (some editors replace the file, and Docker keeps the old one), run `./idp.sh down` and `./idp.sh up`.

```toml
[user.carol]
label = "Carol Example"
claims = { email = "carol@example.com", email_verified = true, name = "Carol Example", roles = ["viewer"] }
```

## Show the login page again

The checkbox "Remember me and skip this page" sets a cookie in the browser.
The app logout does not always clear it. Then the next login signs in the same User with no page.
To show the login page again, open `http://localhost:{{port}}/{{issuer_id}}/endsession` in the browser.

## Debug a token

Open `http://localhost:{{port}}/{{issuer_id}}/debugger` and paste a token.
The page shows the claims and checks the signature, `exp` and `iss`.
