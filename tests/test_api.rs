mod common;
use common::*;

#[allow(clippy::needless_pass_by_value)]
fn post_json(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost:9000")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn user_with_claims() {
    let (s, _, b) = send(
        &app(STRICT),
        post_json(
            "/_mock/auth0/token",
            json!({"user": "alice", "claims": {"roles": ["x"]}}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let id = claims_of(json(&b)["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "auth0|alice");
    assert_eq!(id["roles"], json!(["x"]));
    assert_eq!(id["aud"], "test-api");
}

#[tokio::test]
async fn negative_expires_in_gives_expired_token() {
    let app = app(STRICT);
    let j = json(
        &send(
            &app,
            post_json(
                "/_mock/auth0/token",
                json!({"user": "alice", "expires_in": -60}),
            ),
        )
        .await
        .2,
    );
    assert_eq!(j["expires_in"], -60);
    let at = j["access_token"].as_str().unwrap();
    assert!(claims_of(at)["exp"].as_u64().unwrap() < claims_of(at)["iat"].as_u64().unwrap());
    let (s, _, _) = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &format!("Bearer {at}"))],
        ),
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn custom_sub() {
    let (s, _, b) = send(
        &app(STRICT),
        post_json(
            "/_mock/auth0/token",
            json!({"sub": "c-1", "claims": {"email": "carol@example.com"}}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let id = claims_of(json(&b)["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "c-1");
    assert_eq!(id["email"], "carol@example.com");
}

#[tokio::test]
async fn configured_client_audience() {
    let toml = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\naudience = \"https://api.example.com\"\n",
    );
    let (s, _, b) = send(
        &app(&toml),
        post_json(
            "/_mock/auth0/token",
            json!({"user": "alice", "client_id": "example-app"}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let at = json(&b)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims_of(&at)["aud"], "https://api.example.com");
    assert_eq!(claims_of(&at)["client_id"], "example-app");
}

#[tokio::test]
async fn request_audience_wins() {
    let (_, _, b) = send(
        &app(STRICT),
        post_json(
            "/_mock/auth0/token",
            json!({"user": "alice", "audience": "https://other.example.com"}),
        ),
    )
    .await;
    let at = json(&b)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims_of(&at)["aud"], "https://other.example.com");
}

#[tokio::test]
async fn errors() {
    let app = app(STRICT);
    let (s, _, b) = send(
        &app,
        post_json("/_mock/nope/token", json!({"user": "alice"})),
    )
    .await;
    assert_eq!(s, 404);
    assert_eq!(json(&b)["error"], "not_found");
    assert_eq!(json(&b)["error_description"], "unknown issuer: nope");
    for body in [
        json!({"user": "nobody"}),
        json!({}),
        json!({"user": "alice", "sub": "c"}),
        json!({"user": "alice", "bogus": 1}),
    ] {
        let (s, _, b) = send(&app, post_json("/_mock/auth0/token", body.clone())).await;
        assert_eq!(s, 400, "{body}: {b}");
        assert_eq!(json(&b)["error"], "invalid_request");
    }
    let bad = Request::builder()
        .method("POST")
        .uri("/_mock/auth0/token")
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let (s, _, b) = send(&app, bad).await;
    assert_eq!(s, 400);
    assert_eq!(json(&b)["error"], "invalid_request");
}

#[tokio::test]
async fn waits_for_key() {
    let (keys, publisher) = KeyHandle::channel();
    let app = app_with_keys(STRICT, keys);
    let req = tokio::spawn(async move {
        send(
            &app,
            post_json("/_mock/auth0/token", json!({"user": "alice"})),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!req.is_finished());
    publisher.publish(KEY.clone());
    assert_eq!(req.await.unwrap().0, 200);
}

#[tokio::test]
async fn offline_access_with_refresh_client_gives_refresh_token() {
    let (s, _, b) = send(
        &app(STRICT),
        post_json(
            "/_mock/auth0/token",
            json!({"user": "alice", "client_id": "example-app", "scope": "openid offline_access"}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert!(json(&b)["refresh_token"].is_string());
    let (_, _, b) = send(
        &app(STRICT),
        post_json("/_mock/auth0/token", json!({"user": "alice"})),
    )
    .await;
    assert!(json(&b).get("refresh_token").is_none());
}
