mod common;
use common::*;

#[tokio::test]
async fn all_three_paths_return_the_same_document() {
    let app = app(AUTH0);
    let a = send(&app, get("/auth0/.well-known/openid-configuration")).await;
    let b = send(&app, get("/auth0/.well-known/oauth-authorization-server")).await;
    let c = send(&app, get("/.well-known/oauth-authorization-server/auth0")).await;
    assert_eq!(a.0, 200);
    assert_eq!(a.2, b.2);
    assert_eq!(a.2, c.2);
    let d = json(&a.2);
    assert_eq!(d["issuer"], "http://localhost:9000/auth0/");
    assert_eq!(d["token_endpoint"], "http://localhost:9000/auth0/token");
}

#[tokio::test]
async fn iss_is_fixed_but_endpoints_follow_host() {
    let app = app(AUTH0);
    let d = json(
        &send(
            &app,
            get_with(
                "/auth0/.well-known/openid-configuration",
                &[("host", "fauxidc:9000")],
            ),
        )
        .await
        .2,
    );
    assert_eq!(d["issuer"], "http://localhost:9000/auth0/");
    assert_eq!(d["jwks_uri"], "http://fauxidc:9000/auth0/jwks");
}

#[tokio::test]
async fn cors_star_on_discovery() {
    let (_, h, _) = send(
        &app(AUTH0),
        get_with(
            "/auth0/.well-known/openid-configuration",
            &[("origin", "http://localhost:3000")],
        ),
    )
    .await;
    assert_eq!(h["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn root_issuer() {
    let app = app("[issuer.r]\nissuer_url = \"http://localhost:9000\"\n");
    assert_eq!(
        send(&app, get("/.well-known/openid-configuration")).await.0,
        200
    );
    assert_eq!(
        send(&app, get("/.well-known/oauth-authorization-server"))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn two_issuers_and_unknown_path() {
    let app = app(&format!(
        "{AUTH0}[issuer.okta]\nissuer_url = \"http://localhost:9000/oauth2/default\"\n"
    ));
    let d = json(
        &send(
            &app,
            get("/oauth2/default/.well-known/openid-configuration"),
        )
        .await
        .2,
    );
    assert_eq!(d["issuer"], "http://localhost:9000/oauth2/default");
    assert_eq!(
        send(
            &app,
            get("/.well-known/oauth-authorization-server/oauth2/default")
        )
        .await
        .0,
        200
    );
    assert_eq!(
        send(&app, get("/nope/.well-known/openid-configuration"))
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn discovery_does_not_wait_for_the_key() {
    let (keys, _publisher) = fauxidc::keys::KeyHandle::channel();
    let app = app_with_keys(AUTH0, keys);
    let r = tokio::time::timeout(
        Duration::from_millis(500),
        send(&app, get("/auth0/.well-known/openid-configuration")),
    )
    .await;
    assert_eq!(r.unwrap().0, 200);
}

const OVERRIDES: &str = "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\n\
    paths = { authorize = \"/oauth/authorize\", token = \"/oauth/token\", jwks = \"/.keys\", userinfo = \"/me\" }\n";

#[tokio::test]
async fn discovery_publishes_path_overrides() {
    let app = app(OVERRIDES);
    let d = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        d["token_endpoint"],
        "http://localhost:9000/auth0/oauth/token"
    );
    assert_eq!(
        d["authorization_endpoint"],
        "http://localhost:9000/auth0/oauth/authorize"
    );
    assert_eq!(d["jwks_uri"], "http://localhost:9000/auth0/.keys");
    assert_eq!(d["userinfo_endpoint"], "http://localhost:9000/auth0/me");
    assert_eq!(send(&app, get("/auth0/.keys")).await.0, 200);
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 404);
}

#[tokio::test]
async fn root_issuer_override_has_single_slash() {
    let app = app(
        "[issuer.r]\nissuer_url = \"http://localhost:9000/\"\npaths = { token = \"/oauth/token\" }\n",
    );
    let d = json(&send(&app, get("/.well-known/openid-configuration")).await.2);
    assert_eq!(d["token_endpoint"], "http://localhost:9000/oauth/token");
}

#[tokio::test]
async fn m2_grants_and_offline_access_are_published() {
    let d = json(
        &send(&app(AUTH0), get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        d["grant_types_supported"],
        json!([
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ])
    );
    assert!(
        d["scopes_supported"]
            .as_array()
            .unwrap()
            .contains(&json!("offline_access"))
    );
}

#[tokio::test]
async fn request_and_claims_parameters_unsupported() {
    let (s, _, b) = send(&app(AUTH0), get("/auth0/.well-known/openid-configuration")).await;
    assert_eq!(s, 200);
    let j = json(&b);
    assert_eq!(j["request_parameter_supported"], false);
    assert_eq!(j["request_uri_parameter_supported"], false);
    assert_eq!(j["claims_parameter_supported"], false);
}

#[tokio::test]
async fn private_key_jwt_is_published() {
    let d = json(
        &send(&app(AUTH0), get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        d["token_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none"
        ])
    );
    assert_eq!(
        d["introspection_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ])
    );
    assert_eq!(
        d["revocation_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
            "none"
        ])
    );
    for key in [
        "token_endpoint_auth_signing_alg_values_supported",
        "introspection_endpoint_auth_signing_alg_values_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
    ] {
        assert_eq!(d[key], json!(["RS256", "PS256", "ES256"]), "{key}");
    }
}
