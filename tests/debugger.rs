mod common;
use common::*;

#[tokio::test]
async fn debugger_page_renders() {
    let (s, _, b) = send(&app(STRICT), get("/auth0/debugger")).await;
    assert_eq!(s, 200);
    assert!(b.contains("name=\"token\"") && b.contains("/auth0/debugger/start"));
}

#[tokio::test]
async fn decodes_and_verifies_an_own_token() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[]).await;
    let (s, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &at)], &[])).await;
    assert_eq!(s, 200);
    assert!(b.contains("valid (kid"), "{b}");
    assert!(b.contains("expires in"));
    assert!(b.contains("&quot;sub&quot;") || b.contains("\"sub\""));
}

#[tokio::test]
async fn foreign_and_expired_tokens_are_reported() {
    let app = app(STRICT);
    let stranger = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let t = sign_with(&stranger, &json!({"sub":"x","exp":1}));
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &t)], &[])).await;
    assert!(!b.contains("valid (kid"));
    assert!(b.contains("expired"));
    let (s, _, b) = send(
        &app,
        post_form("/auth0/debugger", &[("token", "not-a-jwt")], &[]),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("not a JWT"));
}

#[tokio::test]
async fn decoded_values_are_escaped() {
    let app = app(STRICT);
    let at = test_token(
        &app,
        "auth0",
        json!({"user":"alice","claims":{"name":"<script>alert(1)</script>"}}),
    )
    .await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &at)], &[])).await;
    assert!(!b.contains("<script>alert(1)</script>"));
    assert!(b.contains("&lt;script&gt;"));
}

#[tokio::test]
async fn signed_in_as_and_change_link() {
    let app = app(STRICT);
    let (_, _, b) = send(
        &app,
        get_with("/auth0/debugger", &[("cookie", "fauxidc_user_auth0=alice")]),
    )
    .await;
    assert!(b.contains("Signed in as Alice Admin") && b.contains("/auth0/debugger?forget=1"));
    let (s, h, _) = send(
        &app,
        get_with(
            "/auth0/debugger?forget=1",
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    assert_eq!(s, 303);
    assert_eq!(location(&h), "/auth0/debugger");
    assert_eq!(
        set_cookie(&h, "fauxidc_user_auth0").as_deref(),
        Some("fauxidc_user_auth0=")
    );
}

#[tokio::test]
async fn unknown_auto_select_user_is_not_shown() {
    let (_, _, b) = send(
        &app(STRICT),
        get_with(
            "/auth0/debugger",
            &[("cookie", "fauxidc_user_auth0=mallory")],
        ),
    )
    .await;
    assert!(!b.contains("Signed in as"));
}

#[tokio::test]
async fn debugger_follows_paths_override() {
    let cfg = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\npaths = { debugger = \"/tools/debug\" }\n",
    );
    assert_eq!(send(&app(&cfg), get("/auth0/tools/debug")).await.0, 200);
}
