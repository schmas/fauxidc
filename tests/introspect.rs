mod common;
use common::*;

async fn introspect(app: &Router, issuer: &str, token: &str) -> (StatusCode, HeaderMap, Value) {
    let (s, h, b) = send(
        app,
        post_form(
            &format!("/{issuer}/introspect"),
            &[("token", token)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert!(
        h["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json"),
        "{b}"
    );
    (s, h, json(&b))
}

async fn refresh_token(app: &Router) -> String {
    token_response_for(app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn active_access_token() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[]).await;
    let (s, h, j) = introspect(&app, "auth0", &at).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(h["cache-control"], "no-store");
    assert!(h.get("access-control-allow-origin").is_none());
    assert_eq!(
        (j["active"].as_bool(), j["token_type"].as_str()),
        (Some(true), Some("Bearer"))
    );
    assert_eq!(j["sub"], "auth0|alice");
    assert_eq!(j["client_id"], "example-app");
    assert_eq!(j["iss"], "http://localhost:9000/auth0/");
    assert_eq!(j["scope"], "openid profile email");
    assert!(j["exp"].is_u64() && j["jti"].is_string());
}

#[tokio::test]
async fn active_refresh_token_and_rotated_one_inactive() {
    let app = app(STRICT);
    let rt = refresh_token(&app).await;
    let (_, _, j) = introspect(&app, "auth0", &rt).await;
    assert_eq!(j["active"], true, "{j}");
    assert_eq!(j["token_type"], "refresh_token");
    assert_eq!(j["scope"], "openid offline_access");
    assert_eq!(j["client_id"], "example-app");
    assert_eq!(j["sub"], "auth0|alice");
    assert_eq!(j["aud"], "example-app");
    assert_eq!(j["iss"], "http://localhost:9000/auth0/");
    for name in ["exp", "iat", "jti"] {
        assert!(!j[name].is_null(), "{name}");
    }
    assert!(j.get("subject").is_none(), "{j}");
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let (_, _, j) = introspect(&app, "auth0", &rt).await;
    assert_eq!(j, json!({"active": false}));
    let new_rt = json(&b)["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(introspect(&app, "auth0", &new_rt).await.2["active"], true);
}

#[tokio::test]
async fn used_refresh_token_within_leeway_is_active() {
    let cfg = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\nrefresh_reuse_leeway_secs = 30\n",
    );
    let app = app(&cfg);
    let rt = refresh_token(&app).await;
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(introspect(&app, "auth0", &rt).await.2["active"], true);
}

#[tokio::test]
async fn revoked_token_is_inactive() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[]).await;
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &at)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200);
    let (s, _, j) = introspect(&app, "auth0", &at).await;
    assert_eq!(s, 200);
    assert_eq!(j, json!({"active": false}));
}

#[tokio::test]
async fn garbage_and_id_token_are_inactive() {
    let app = app(STRICT);
    let idt = token_response_for(&app, &[]).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    for token in ["abc", idt.as_str()] {
        let (s, _, j) = introspect(&app, "auth0", token).await;
        assert_eq!(s, 200);
        assert_eq!(j, json!({"active": false}));
    }
}

#[tokio::test]
async fn missing_token_is_invalid_request() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/introspect",
            &[],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn public_client_is_invalid_client_in_strict() {
    let app = app(STRICT);
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[("token", "abc"), ("client_id", "spa")],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 401);
    let j = json(&b);
    assert_eq!(j["error"], "invalid_client");
    assert_eq!(
        j["error_description"],
        "introspection needs a confidential client"
    );
    let (s, _, _) = send(
        &app,
        post_form("/auth0/introspect", &[("token", "abc")], &[]),
    )
    .await;
    assert_eq!(s, 401);
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[("token", "abc")],
            &[("authorization", &basic("example-app", "wrong"))],
        ),
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn lenient_needs_no_client_auth() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&cfg);
    let at = access_token_for(&app, &[]).await;
    let (s, _, b) = send(&app, post_form("/auth0/introspect", &[("token", &at)], &[])).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(json(&b)["active"], true);
}

#[tokio::test]
async fn token_from_other_issuer_is_inactive() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta/\"\n");
    let app = app(&cfg);
    let at = access_token_for(&app, &[]).await;
    assert_eq!(introspect(&app, "auth0", &at).await.2["active"], true);
    let (s, _, j) = introspect(&app, "okta", &at).await;
    assert_eq!(s, 200);
    assert_eq!(j, json!({"active": false}));
}

#[tokio::test]
async fn discovery_lists_introspection_endpoint() {
    let (_, _, b) = send(&app(STRICT), get("/auth0/.well-known/openid-configuration")).await;
    let j = json(&b);
    assert_eq!(
        j["introspection_endpoint"],
        "http://localhost:9000/auth0/introspect"
    );
    assert_eq!(
        j["introspection_endpoint_auth_methods_supported"],
        json!(["client_secret_basic", "client_secret_post"])
    );
}

#[tokio::test]
async fn lenient_ignores_bearer_authorization_header() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&cfg);
    let at = access_token_for(&app, &[]).await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[("token", &at)],
            &[("authorization", &format!("Bearer {at}"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(json(&b)["active"], true);
}
