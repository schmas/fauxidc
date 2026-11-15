# Testcontainers

This page shows how to start fauxidc from a JVM test with [Testcontainers](https://testcontainers.com/).
The examples use Java and JUnit 5.
fauxidc has no Java module. Use `GenericContainer` with the published image.

## The image

The image is `ghcr.io/schmas/fauxidc`. Each release has a tag with its version without the `v`, for example `0.2.0`.
`latest` is the newest stable release. Pin a version in tests, so that a new release does not change your build.
The examples use `0.2.0`. Replace it with the newest version from the [releases](https://github.com/schmas/fauxidc/releases).

The image listens on port 9000. Its working directory is `/config`, so it reads `/config/fauxidc.toml` when that file exists.
Without a config file and without a `FAUXIDC__*` env var, it starts in Zero config mode:
the Issuer `default`, the public Client `test`, and the Users `alice` and `bob`.
See [configuration.md](configuration.md#docker).

## Start the container

```java
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
class LoginTest {

    @Container
    static final GenericContainer<?> FAUXIDC =
            new GenericContainer<>(DockerImageName.parse("ghcr.io/schmas/fauxidc:0.2.0"))
                    .withExposedPorts(9000)
                    .withEnv("FAUXIDC_ISSUER_FROM_HOST", "true")
                    .waitingFor(Wait.forHttp("/_mock/health")
                            .forStatusCode(200)
                            .forResponsePredicate(body -> body.contains("\"key\":\"ready\"")));

    static String issuer() {
        return "http://" + FAUXIDC.getHost() + ":" + FAUXIDC.getMappedPort(9000) + "/default";
    }

    @Test
    void issuerIsReachable() {
        // Point your client at issuer(), for example http://localhost:49153/default.
    }
}
```

### Wait for the signing key

The port opens before the signing key exists. A wait for the port only can let the first token request fail.
`GET /_mock/health` returns `{"key":"ready","status":"ok"}` when every Issuer has its first key, and `"pending"` before that.
So the wait strategy checks the body for `"key":"ready"`. See [test-api.md](test-api.md).

### Random host port

Testcontainers maps port 9000 to a random host port, for example 49153.
By default, `iss` is the fixed `issuer_url`, `http://localhost:9000/default`. A client with the mapped issuer URL rejects it.
`FAUXIDC_ISSUER_FROM_HOST=true` makes `iss` and the discovery `issuer` use the host and port of the request.
The issuer is then `http://localhost:49153/default`, and it matches the URL that the test uses.
The env var keeps Zero config, and it also applies to every Issuer of a config file.

A token is then valid only through the host that minted it.
Mint tokens and check them through the same URL.
For example, a token minted through `localhost:49153` is inactive at `http://fauxidc:9000/default/introspect`.
See [configuration.md](configuration.md#issuer-url-and-endpoint-urls) and [ADR 0006](adr/0006-opt-in-host-derived-iss.md).

### Fixed host port

The other option binds the host port 9000. Then you do not need `FAUXIDC_ISSUER_FROM_HOST`, and `iss` stays `http://localhost:9000/default`:

```java
FAUXIDC.setPortBindings(List.of("9000:9000"));   // before the container starts; import java.util.List
```

The trade-off: port 9000 must be free on the host. Two builds on one machine cannot run at the same time.
Use the random port when you can.

## Give a config

Copy a config file to `/config/fauxidc.toml` before the container starts:

```java
import org.testcontainers.utility.MountableFile;

new GenericContainer<>(DockerImageName.parse("ghcr.io/schmas/fauxidc:0.2.0"))
        .withExposedPorts(9000)
        .withCopyFileToContainer(MountableFile.forClasspathResource("fauxidc.toml"), "/config/fauxidc.toml")
        .withEnv("FAUXIDC_ISSUER_FROM_HOST", "true")
        .waitingFor(Wait.forHttp("/_mock/health")
                .forStatusCode(200)
                .forResponsePredicate(body -> body.contains("\"key\":\"ready\"")));
```

`src/test/resources/fauxidc.toml`:

```toml
[issuer.app]
issuer_url = "http://localhost:9000/app"

[client.example_app]
client_id = "example-app"
client_secret = "local"
redirect_uris = ["http://localhost:8080/login/oauth2/code/fauxidc"]

[user.alice]
claims = { email = "alice@example.com", roles = ["admin"] }
```

The issuer is then `http://<host>:<mapped port>/app`.
With `FAUXIDC_ISSUER_FROM_HOST=true`, the port in `issuer_url` does not matter. The path `/app` does.

You can also set single keys with `FAUXIDC__*` env vars. The rest of the name, split on `__`, is the key path:

```java
.withEnv("FAUXIDC__ISSUER__APP__ISSUER_URL", "http://localhost:9000/app")
.withEnv("FAUXIDC__USER__ALICE__CLAIMS", "{ email = \"alice@example.com\" }")
```

A `FAUXIDC__*` env var turns off Zero config, so define an Issuer and Users too.
`FAUXIDC_ISSUER_FROM_HOST` is not a `FAUXIDC__*` env var and does not turn off Zero config.
For more than a few keys, a file is easier to read. See [configuration.md](configuration.md#sources).

## Mint a token from Java

`POST /_mock/{issuer-id}/token` issues tokens without a browser. The body and the fields are in [test-api.md](test-api.md#mint-tokens).
This helper uses `java.net.http.HttpClient` from the JDK, so it needs no extra library:

```java
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class FauxidcTokens {

    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final Pattern ACCESS_TOKEN = Pattern.compile("\"access_token\":\"([^\"]+)\"");

    /** Mints an access token on the Issuer `default`. baseUrl is http://host:mappedPort. */
    static String accessToken(String baseUrl, String body) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/_mock/default/token"))
                .header("content-type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = HTTP.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("fauxidc returned " + response.statusCode() + ": " + response.body());
        }
        Matcher m = ACCESS_TOKEN.matcher(response.body());
        if (!m.find()) {
            throw new IllegalStateException("no access_token in " + response.body());
        }
        return m.group(1);
    }
}
```

Call it with a JSON body:

```java
String base = "http://" + FAUXIDC.getHost() + ":" + FAUXIDC.getMappedPort(9000);
String token = FauxidcTokens.accessToken(base,
        "{\"user\": \"alice\", \"claims\": {\"roles\": [\"viewer\"]}, \"audience\": \"example-app\", \"expires_in\": 300}");
```

The response has the same JSON shape as `/token`, with `access_token`, `id_token` and `expires_in`.
The regex is enough for `access_token`. If your project has a JSON library, such as Jackson, use it.
A negative `expires_in` gives an expired token, to test that your API rejects it.

## Spring Boot resource server

Set the issuer with `@DynamicPropertySource`. Spring reads the property after the container starts:

```java
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MeEndpointTest {

    @Container
    static final GenericContainer<?> FAUXIDC =
            new GenericContainer<>(DockerImageName.parse("ghcr.io/schmas/fauxidc:0.2.0"))
                    .withExposedPorts(9000)
                    .withEnv("FAUXIDC_ISSUER_FROM_HOST", "true")
                    .waitingFor(Wait.forHttp("/_mock/health")
                            .forStatusCode(200)
                            .forResponsePredicate(body -> body.contains("\"key\":\"ready\"")));

    static String base() {
        return "http://" + FAUXIDC.getHost() + ":" + FAUXIDC.getMappedPort(9000);
    }

    @DynamicPropertySource
    static void fauxidc(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> base() + "/default");
    }

    @Value("${local.server.port}")
    int port;

    @Test
    void acceptsATokenFromFauxidc() throws Exception {
        String token = FauxidcTokens.accessToken(base(), "{\"user\": \"alice\"}");
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/me"))
                .header("Authorization", "Bearer " + token)
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
    }
}
```

Access tokens have the JWT header `typ` `at+jwt` (RFC 9068). Spring Security 7.x accepts only `typ` `JWT` by default.
Add a `JwtDecoder` that also allows `at+jwt`:

```java
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Bean
JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuer) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuer).validateType(false).build();
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            new JwtTimestampValidator(), new JwtIssuerValidator(issuer), new JwtTypeValidator("JWT", "at+jwt")));
    return decoder;
}
```

[testing/m1-exit-test.md](testing/m1-exit-test.md#part-2-spring-resource-server) has the same setup and the error without it.

For an app that logs in with `spring-boot-starter-oauth2-client`, also set the provider issuer.
This example uses the Issuer `app` from the config above:

```java
registry.add("spring.security.oauth2.client.provider.fauxidc.issuer-uri", () -> base() + "/app");
```

The Client registration (`spring.security.oauth2.client.registration.fauxidc.*`) then uses the Client of your config,
for example `example-app` with the secret `local`.

## Kotlin

The same calls work in Kotlin. Put the container and the `@DynamicPropertySource` function in a `companion object`.
Mark the container with `@JvmField` and the function with `@JvmStatic`.
