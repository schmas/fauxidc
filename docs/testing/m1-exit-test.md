# M1 exit test

This runbook covers the M1 exit test in `docs/spec.md`, section 14.
It has three parts:

1. An Auth.js app logs in through both example configs.
2. A Spring resource server accepts the access token.
3. The `openidconnect` compatibility test passes.

Part 3 is automated. Parts 1 and 2 are manual.
Record the results in the PR description: tool versions, pass or fail, and any errors.

## Prerequisites

- A fauxidc checkout. Build it with `cargo build`.
- Node.js with npm.
- A JDK. Spring Boot 4 needs Java 17 or later.
- `curl`.

Build the test apps in a temporary directory outside the repo. Do not commit them.

## Part 1: Auth.js

Run the Next.js app on the host with `npm run dev` on port 3000.
Do not run it in a container.
The `iss` is `localhost:9000`, and a container cannot reach the mock under that name.

### Set up the app

Create the app:

```sh
mkdir authjs && cd authjs
npm init -y
npm install next react react-dom next-auth@beta
```

Add the script `"dev": "next dev -p 3000"` to `package.json`.

Create `auth.js`. The variable `EXIT_PROVIDER` selects the provider:

```js
import NextAuth from "next-auth"
import Auth0 from "next-auth/providers/auth0"
import Okta from "next-auth/providers/okta"

const common = {
  clientId: "example-app",
  clientSecret: "local",
  authorization: { params: { scope: "openid profile email" } },
}

const provider =
  process.env.EXIT_PROVIDER === "okta"
    ? Okta({ ...common, issuer: "http://localhost:9000/oauth2/default" })
    : Auth0({ ...common, issuer: "http://localhost:9000/auth0/" })

export const { handlers, auth } = NextAuth({
  providers: [provider],
  secret: "exit-test-secret-not-for-production",
  trustHost: true,
  callbacks: {
    // Expose the access token in the session for part 2.
    jwt({ token, account }) {
      if (account) token.accessToken = account.access_token
      return token
    },
    session({ session, token }) {
      session.accessToken = token.accessToken
      return session
    },
  },
})
```

Create `app/api/auth/[...nextauth]/route.js`:

```js
import { handlers } from "../../../../auth"
export const { GET, POST } = handlers
```

Create `app/layout.js`. The App Router needs a root layout that renders `<html>` and `<body>`:

```js
export default function RootLayout({ children }) {
  return <html><body>{children}</body></html>
}
```

Create `app/page.js`:

```js
export default function Page() {
  return <p>exit test</p>
}
```

The minimal app has these files: `package.json`, `auth.js`, `app/layout.js`, `app/page.js` and `app/api/auth/[...nextauth]/route.js`.
All files are `.js` files with ES module syntax (`import` / `export`) and JSX. Next.js compiles them. The app needs no `next.config.js`.

### Run 1: Auth0 provider

1. In a separate terminal, start the mock: `cargo run -- --config examples/auth0.toml`.
2. Start the app: `EXIT_PROVIDER=auth0 npm run dev`.
3. Open `http://localhost:3000/api/auth/signin` in a browser and select the provider.
4. On the mock login page, select Alice Admin and sign in.
5. Open `http://localhost:3000/api/auth/session`.

Expected: the session shows `alice@example.com`.

Keep the mock and the app running for part 2.
With no `FAUXIDC_KEY_PEM` and no `server.key_file`, the mock generates a new signing key at each start.
A restart then makes the token invalid.

### Run 2: Okta provider

1. Stop the mock and the app.
2. In a separate terminal, start the mock: `cargo run -- --config examples/okta.toml`.
3. Start the app: `EXIT_PROVIDER=okta npm run dev`.
4. Do steps 3 to 5 of run 1 again.

Expected: the session shows `alice@example.com`.

### Run without a browser

You can drive the login with `curl` and a cookie jar.

1. Copy the example config to a temporary directory.
   Add `auto_login = true` to the `[issuer.*]` table. Do not edit `examples/`.
2. In `auth.js`, add `login_hint: "alice"` to `authorization.params` in the `common` object.
3. In a separate terminal, start the mock with the copied config. Then start the app.
4. Run the script below with `auth0` or `okta` as the argument.

```sh
#!/bin/sh
set -eu
P="$1"; JAR=jar.txt; rm -f "$JAR"
APP=http://localhost:3000
CSRF=$(curl -s -c "$JAR" -b "$JAR" "$APP/api/auth/csrf" | sed 's/.*"csrfToken":"\([^"]*\)".*/\1/')
# Auth.js sign-in. It redirects to the mock /authorize.
AUTHZ=$(curl -s -o /dev/null -w '%{redirect_url}' -c "$JAR" -b "$JAR" -X POST \
  --data-urlencode "csrfToken=$CSRF" --data-urlencode "callbackUrl=$APP/" \
  "$APP/api/auth/signin/$P")
# login_hint with auto_login redirects back with a code at once.
CB=$(curl -s -o /dev/null -w '%{redirect_url}' "$AUTHZ")
# The callback exchanges the code and sets the session cookie.
curl -s -o /dev/null -c "$JAR" -b "$JAR" "$CB"
curl -s -b "$JAR" "$APP/api/auth/session"; echo
```

Expected: the session JSON shows `alice@example.com`.
This run skips the login page. Check the login page with a browser at least once.

## Part 2: Spring resource server

### Set up the app

Create a Spring Boot project with Spring Web and OAuth2 Resource Server, for example from start.spring.io.
In Spring Boot 4, the starter is `spring-boot-starter-security-oauth2-resource-server`.
In Spring Boot 3, the starter is `spring-boot-starter-oauth2-resource-server`.

Set `application.properties`:

```properties
server.port=8080
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:9000/auth0/
```

Add one protected endpoint:

```java
@RestController
class MeController {
    @GetMapping("/api/me")
    Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("sub", jwt.getSubject());
    }
}
```

The auto-configuration protects every endpoint. Do not add a custom `JwtDecoder`.
The test checks the default JWT validation.

### Run

1. Keep the mock running with `examples/auth0.toml` from part 1, run 1.
2. Copy the `accessToken` value from `http://localhost:3000/api/auth/session`.
3. Start the app: `./mvnw spring-boot:run`.
4. Call the endpoint:

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me
```

Expected: status 200.

The access token has the header `typ: at+jwt` (RFC 9068).
Check that the default validation accepts it.
If the response is 401, read the `WWW-Authenticate` header.
Record the Spring Boot version, the Spring Security version and the error text.
Do not change `typ` in fauxidc to make the test pass.
A rejection is an interop finding for the spec.

### Known result

Spring Boot 4.1.2 with Spring Security 7.1.2 rejects the token by default:

```
WWW-Authenticate: Bearer error="invalid_token",
  error_description="An error occurred while attempting to decode the Jwt:
  the given typ value needs to be one of [JWT]"
```

An app can accept `at+jwt` with its own `JwtDecoder`:

```java
@Bean
JwtDecoder jwtDecoder() {
    String issuer = "http://localhost:9000/auth0/";
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuer).validateType(false).build();
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(), new JwtIssuerValidator(issuer), new JwtTypeValidator("JWT", "at+jwt")));
    return decoder;
}
```

With this decoder, the same token returns 200.

## Part 3: openidconnect compatibility test

Run:

```sh
cargo test --test compat_openidconnect
```

Expected: the test passes. CI runs it with `cargo nextest run`.

## Clean up

Stop the mock, the Next.js app and the Spring app.
Remove the temporary directory.
