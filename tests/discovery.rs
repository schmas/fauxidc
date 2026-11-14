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
