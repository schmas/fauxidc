mod common;
use common::*;

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("host", "localhost:9000")
        .body(Body::empty())
        .unwrap()
}

async fn reset(app: &Router, uri: &str) -> StatusCode {
    send(app, delete(uri)).await.0
}

const TWO: &str = "\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n";

async fn refresh(app: &Router, rt: &str) -> (StatusCode, Value) {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    (s, json(&b))
}

async fn offline_rt(app: &Router) -> String {
    token_response_for(app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn inject(app: &Router, issuer: &str) {
    let (s, _, b) = send(
        app,
        post_json(
            &format!("/_mock/{issuer}/fail-next"),
            &json!({"endpoint": "jwks"}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

async fn jwks_status(app: &Router, issuer: &str) -> StatusCode {
    send(app, get(&format!("/{issuer}/jwks"))).await.0
}

#[tokio::test]
async fn reset_makes_an_unused_code_invalid() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    assert_eq!(reset(&app, "/_mock/state").await, 204);
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                (
                    "redirect_uri",
                    "http://localhost:3000/api/auth/callback/auth0",
                ),
            ],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn reset_ends_sessions() {
    let app = app(STRICT);
    let (_, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    let prompt_none = || {
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        )
    };
    let (_, h, _) = send(&app, prompt_none()).await;
    assert!(query_param(&location(&h), "code").is_some());
    assert_eq!(reset(&app, "/_mock/state").await, 204);
    let (_, h, _) = send(&app, prompt_none()).await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn reset_forgets_used_refresh_tokens_and_revocations() {
    let app = app(STRICT);
    let rt = offline_rt(&app).await;
    assert_eq!(refresh(&app, &rt).await.0, 200);
    assert_eq!(refresh(&app, &rt).await.0, 400, "reuse is refused");
    assert_eq!(reset(&app, "/_mock/state").await, 204);
    assert_eq!(refresh(&app, &rt).await.0, 200, "the used jti is forgotten");

    let rt = offline_rt(&app).await;
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(refresh(&app, &rt).await.0, 400, "revoked");
    assert_eq!(reset(&app, "/_mock/state").await, 204);
    assert_eq!(
        refresh(&app, &rt).await.0,
        200,
        "the revocation is forgotten"
    );
}

#[tokio::test]
async fn reset_removes_injected_failures_and_the_request_log() {
    let app = app(STRICT);
    inject(&app, "auth0").await;
    send(&app, get("/auth0/.well-known/openid-configuration")).await;
    let (_, _, log) = send(&app, get("/_mock/requests")).await;
    assert_ne!(json(&log).as_array().unwrap().len(), 0);

    assert_eq!(reset(&app, "/_mock/state").await, 204);
    assert_eq!(jwks_status(&app, "auth0").await, 200);
    let (_, _, log) = send(&app, get("/_mock/requests")).await;
    assert_eq!(
        json(&log).as_array().unwrap().len(),
        1,
        "only the jwks request after the reset"
    );
}

#[tokio::test]
async fn reset_of_one_issuer_keeps_the_others() {
    let app = app(&format!("{STRICT}{TWO}"));
    inject(&app, "auth0").await;
    inject(&app, "okta").await;
    send(&app, get("/okta/.well-known/openid-configuration")).await;
    send(&app, get("/auth0/.well-known/openid-configuration")).await;

    assert_eq!(reset(&app, "/_mock/state?issuer=auth0").await, 204);
    assert_eq!(jwks_status(&app, "auth0").await, 200);
    assert_eq!(
        jwks_status(&app, "okta").await,
        500,
        "okta keeps its failure"
    );
    let (_, _, log) = send(
        &app,
        get("/_mock/requests?path=/okta/.well-known/openid-configuration"),
    )
    .await;
    assert_eq!(
        json(&log).as_array().unwrap().len(),
        1,
        "okta keeps its log"
    );
    let (_, _, log) = send(
        &app,
        get("/_mock/requests?path=/auth0/.well-known/openid-configuration"),
    )
    .await;
    assert_eq!(json(&log).as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn reset_keeps_config_and_keys() {
    let app = app(STRICT);
    let (_, _, before) = send(&app, get("/auth0/jwks")).await;
    assert_eq!(reset(&app, "/_mock/state").await, 204);
    let (_, _, after) = send(&app, get("/auth0/jwks")).await;
    assert_eq!(before, after);
    let t = test_token(&app, "auth0", json!({"user": "alice"})).await;
    assert!(t["id_token"].is_string());
}

#[tokio::test]
async fn unknown_issuer_and_bad_query_are_refused() {
    let app = app(STRICT);
    let (s, _, b) = send(&app, delete("/_mock/state?issuer=nope")).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (404, Some("not_found"))
    );
    let (s, _, b) = send(&app, delete("/_mock/state?bad=1")).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_request"))
    );
    assert_eq!(send(&app, get("/_mock/state")).await.0, 405);
}
