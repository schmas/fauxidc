mod common;
use common::*;

#[tokio::test]
async fn offline_access_gives_refresh_token() {
    let app = app(STRICT);
    let j = token_response_for(&app, &[("scope", "openid profile email offline_access")]).await;
    let rt = j["refresh_token"].as_str().unwrap();
    let (h, c) = (header_of(rt), claims_of(rt));
    assert_eq!(h["typ"], "rt+jwt");
    assert_eq!(c["client_id"], "example-app");
    assert_eq!(c["aud"], "example-app");
    assert_eq!(c["iss"], "http://localhost:9000/auth0/");
    assert_eq!(c["sub"], "auth0|alice");
    assert_eq!(c["scope"], "openid profile email offline_access");
    assert_eq!(c["subject"]["kind"], "user");
    assert_eq!(c["subject"]["id"], "alice");
    assert_eq!(
        c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(),
        86400
    );
}

#[tokio::test]
async fn no_refresh_token_without_offline_access_or_grant() {
    assert!(
        token_response_for(&app(STRICT), &[])
            .await
            .get("refresh_token")
            .is_none()
    );
    let cfg = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\ngrant_types = [\"authorization_code\"]\n",
    );
    let j = token_response_for(&app(&cfg), &[("scope", "openid offline_access")]).await;
    assert!(j.get("refresh_token").is_none());
}

#[tokio::test]
async fn lenient_always_issues_refresh_token() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    assert!(token_response_for(&app(&cfg), &[]).await["refresh_token"].is_string());
}

#[tokio::test]
async fn refresh_lifetime_follows_client_override() {
    let cfg = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\nlifetimes = { refresh_token = 120 }\n",
    );
    let j = token_response_for(&app(&cfg), &[("scope", "openid offline_access")]).await;
    let c = claims_of(j["refresh_token"].as_str().unwrap());
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 120);
}

#[tokio::test]
async fn overrides_travel_in_refresh_token() {
    let j = token_response_for(
        &app(STRICT),
        &[
            ("scope", "openid offline_access"),
            ("override_claims", r#"{"roles":["x"]}"#),
        ],
    )
    .await;
    assert_eq!(
        claims_of(j["refresh_token"].as_str().unwrap())["subject"]["overrides"]["roles"],
        json!(["x"])
    );
}

#[tokio::test]
async fn refresh_token_is_not_an_access_token() {
    let app = app(STRICT);
    let j = token_response_for(&app, &[("scope", "openid offline_access")]).await;
    let rt = j["refresh_token"].as_str().unwrap();
    let (s, _, _) = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &format!("Bearer {rt}"))],
        ),
    )
    .await;
    assert_eq!(s, 401);
}
