mod common;
use common::*;

async fn refresh_token(app: &Router) -> String {
    token_response_for(app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn refresh(app: &Router, rt: &str) -> (StatusCode, String) {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    (s, b)
}

#[tokio::test]
async fn revoked_refresh_token_fails_refresh() {
    let app = app(STRICT);
    let rt = refresh_token(&app).await;
    let (s, h, b) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!((s.as_u16(), b.as_str()), (200, ""));
    assert_eq!(h["cache-control"], "no-store");
    let (s, b) = refresh(&app, &rt).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn revoke_with_client_secret_post() {
    let app = app(STRICT);
    let rt = refresh_token(&app).await;
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[
                ("token", &rt),
                ("token_type_hint", "access_token"),
                ("client_id", "example-app"),
                ("client_secret", "local"),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(refresh(&app, &rt).await.0, 400);
}

#[tokio::test]
async fn revoked_access_token_still_works_at_userinfo() {
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
    let (s, _, b) = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &format!("Bearer {at}"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn garbage_token_returns_200() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/revoke",
            &[("token", "abc")],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!((s.as_u16(), b.as_str()), (200, ""));
}

#[tokio::test]
async fn missing_token_is_invalid_request() {
    let app = app(STRICT);
    for form in [vec![], vec![("token", "")]] {
        let (s, _, b) = send(
            &app,
            post_form(
                "/auth0/revoke",
                &form,
                &[("authorization", &basic("example-app", "local"))],
            ),
        )
        .await;
        assert_eq!(
            (s.as_u16(), json(&b)["error"].as_str()),
            (400, Some("invalid_request"))
        );
    }
}

#[tokio::test]
async fn non_form_body_is_invalid_request() {
    let req = Request::builder()
        .method("POST")
        .uri("/auth0/revoke")
        .header("host", "localhost:9000")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (s, _, b) = send(&app(STRICT), req).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn wrong_secret_is_invalid_client() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/revoke",
            &[("token", "abc")],
            &[("authorization", &basic("example-app", "wrong"))],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (401, Some("invalid_client"))
    );
}

#[tokio::test]
async fn no_client_is_invalid_client_in_strict() {
    let (s, _, _) = send(
        &app(STRICT),
        post_form("/auth0/revoke", &[("token", "abc")], &[]),
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn other_clients_token_is_not_revoked_in_strict() {
    let app = app(STRICT);
    let rt = refresh_token(&app).await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &rt), ("client_id", "spa")],
            &[],
        ),
    )
    .await;
    assert_eq!((s.as_u16(), b.as_str()), (200, ""));
    let (s, b) = refresh(&app, &rt).await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn lenient_needs_no_client_auth() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&cfg);
    let rt = refresh_token(&app).await;
    let (s, _, _) = send(&app, post_form("/auth0/revoke", &[("token", &rt)], &[])).await;
    assert_eq!(s, 200);
    let (s, b) = refresh(&app, &rt).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn path_override_is_routed() {
    let cfg = STRICT.replace(
        "sub_template = \"auth0|{user_id}\"\n",
        "sub_template = \"auth0|{user_id}\"\npaths = { revoke = \"/oauth/revoke\" }\n",
    );
    let (s, _, _) = send(
        &app(&cfg),
        post_form(
            "/auth0/oauth/revoke",
            &[("token", "abc")],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn discovery_lists_revocation_endpoint() {
    let (_, _, b) = send(&app(STRICT), get("/auth0/.well-known/openid-configuration")).await;
    let j = json(&b);
    assert_eq!(
        j["revocation_endpoint"],
        "http://localhost:9000/auth0/revoke"
    );
    assert_eq!(
        j["revocation_endpoint_auth_methods_supported"],
        json!(["client_secret_basic", "client_secret_post", "none"])
    );
}

#[tokio::test]
async fn lenient_ignores_bearer_authorization_header() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&cfg);
    let rt = refresh_token(&app).await;
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &rt)],
            &[("authorization", "Bearer some-token")],
        ),
    )
    .await;
    assert_eq!(s, 200);
}
