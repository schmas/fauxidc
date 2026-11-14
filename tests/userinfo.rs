mod common;
use common::*;

#[tokio::test]
async fn userinfo_returns_scoped_claims() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[("scope", "openid email")]).await;
    let (s, _, b) = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &format!("Bearer {at}"))],
        ),
    )
    .await;
    assert_eq!(s, 200);
    let j = json(&b);
    assert_eq!(j["sub"], "auth0|alice");
    assert_eq!(j["email"], "alice@example.com");
    assert!(j.get("name").is_none(), "no profile scope");
    assert!(j.get("aud").is_none() && j.get("scope").is_none());
}

#[tokio::test]
async fn userinfo_errors() {
    let app = app(&format!(
        "{STRICT}[issuer.other]\nissuer_url = \"http://localhost:9000/other\"\n"
    ));
    let (s, h, _) = send(&app, get("/auth0/userinfo")).await;
    assert_eq!(s, 401);
    assert_eq!(
        h["www-authenticate"], "Bearer",
        "RFC 6750 3.1: no error code"
    );
    let (s, h, _) = send(
        &app,
        get_with("/auth0/userinfo", &[("authorization", "Bearer nope")]),
    )
    .await;
    assert_eq!(s, 401);
    assert!(
        h["www-authenticate"]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );
    let at = access_token_for(&app, &[]).await;
    assert_eq!(
        send(
            &app,
            get_with(
                "/other/userinfo",
                &[("authorization", &format!("Bearer {at}"))]
            )
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn userinfo_accepts_post_and_lowercase_scheme() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[]).await;
    let req = Request::builder()
        .method("POST")
        .uri("/auth0/userinfo")
        .header("host", "localhost:9000")
        .header("authorization", format!("bearer {at}"))
        .body(Body::empty())
        .unwrap();
    let (s, _, b) = send(&app, req).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(json(&b)["sub"], "auth0|alice");
}
