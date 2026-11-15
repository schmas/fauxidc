mod common;
use common::*;

const CB: &str = "http://localhost:3000/api/auth/callback/auth0";

fn exchange(code: &str, extra: &[(&str, &str)]) -> Request<Body> {
    let mut f = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", CB),
    ];
    f.extend_from_slice(extra);
    post_form(
        "/auth0/token",
        &f,
        &[("authorization", &basic("example-app", "local"))],
    )
}

#[tokio::test]
async fn code_exchange_returns_tokens() {
    let app = app(STRICT);
    let code = login_code(&app, &[("nonce", "n1")]).await;
    let (s, h, b) = send(&app, exchange(&code, &[])).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["pragma"], "no-cache");
    let j = json(&b);
    assert_eq!(j["token_type"], "Bearer");
    assert_eq!(j["expires_in"], 3600);
    let id = claims_of(j["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "auth0|alice");
    assert_eq!(id["nonce"], "n1");
    assert_eq!(id["email"], "alice@example.com");
    assert_eq!(id["roles"], json!(["admin"]));
    let at = claims_of(j["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], "example-app");
}

#[tokio::test]
async fn code_is_single_use() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    assert_eq!(send(&app, exchange(&code, &[])).await.0, 200);
    let (s, _, b) = send(&app, exchange(&code, &[])).await;
    assert_eq!(s, 400);
    assert_eq!(json(&b)["error"], "invalid_grant");
}

#[tokio::test]
async fn client_secret_rules() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    let no_secret = post_form(
        "/auth0/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "example-app"),
        ],
        &[],
    );
    let (s, _, b) = send(&app, no_secret).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (401, Some("invalid_client"))
    );
    let code = login_code(&app, &[]).await;
    let post = post_form(
        "/auth0/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
            ("client_id", "example-app"),
            ("client_secret", "local"),
        ],
        &[],
    );
    assert_eq!(send(&app, post).await.0, 200);
}

#[tokio::test]
async fn wrong_basic_secret_challenges_with_basic() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    let req = post_form(
        "/auth0/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", CB),
        ],
        &[("authorization", &basic("example-app", "wrong"))],
    );
    let (s, h, b) = send(&app, req).await;
    assert_eq!(s, 401);
    assert_eq!(json(&b)["error"], "invalid_client");
    assert!(h["www-authenticate"].to_str().unwrap().starts_with("Basic"));
}

#[tokio::test]
async fn pkce_s256() {
    let app = app(STRICT);
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; // RFC 7636 appendix B
    let code = login_code(
        &app,
        &[
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(
        json(
            &send(&app, exchange(&code, &[("code_verifier", "wrong")]))
                .await
                .2
        )["error"],
        "invalid_grant"
    );
    let code = login_code(
        &app,
        &[
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    assert_eq!(
        send(&app, exchange(&code, &[("code_verifier", verifier)]))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn expired_code() {
    let app = app(&STRICT.replace("sub_template", "lifetimes = { code = 0 }\nsub_template"));
    let code = login_code(&app, &[]).await;
    assert_eq!(
        json(&send(&app, exchange(&code, &[])).await.2)["error_description"],
        "code expired"
    );
}

#[tokio::test]
async fn redirect_uri_must_match() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    let req = post_form(
        "/auth0/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            (
                "redirect_uri",
                "http://localhost:3000/api/auth/callback/other",
            ),
        ],
        &[("authorization", &basic("example-app", "local"))],
    );
    let j = json(&send(&app, req).await.2);
    assert_eq!(j["error"], "invalid_grant");
    assert_eq!(j["error_description"], "redirect_uri does not match");
}

#[tokio::test]
async fn audience_param_sets_aud_and_no_openid_means_no_id_token() {
    let app = app(STRICT);
    let code = login_code(
        &app,
        &[("audience", "https://api.example.com"), ("scope", "email")],
    )
    .await;
    let j = json(&send(&app, exchange(&code, &[])).await.2);
    assert!(j.get("id_token").is_none());
    assert_eq!(
        claims_of(j["access_token"].as_str().unwrap())["aud"],
        "https://api.example.com"
    );
}

#[tokio::test]
async fn unsupported_grant() {
    let (_, _, b) = send(
        &app(STRICT),
        post_form("/auth0/token", &[("grant_type", "password")], &[]),
    )
    .await;
    assert_eq!(json(&b)["error"], "unsupported_grant_type");
}

#[tokio::test]
async fn token_waits_for_key() {
    let (keys, publisher) = fauxidc::keys::KeyHandle::channel();
    let app = app_with_keys(STRICT, keys);
    let code = login_code(&app, &[]).await;
    let req = tokio::spawn(async move { send(&app, exchange(&code, &[])).await.0 });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!req.is_finished());
    publisher.publish(KEY.clone());
    assert_eq!(req.await.unwrap(), 200);
}

#[tokio::test]
async fn short_or_missing_verifier_is_invalid_grant() {
    use base64::Engine as _;
    use sha2::Digest as _;
    let app = app(STRICT);
    // A valid S256 challenge for a verifier that is too short (RFC 7636 4.1: 43 to 128 chars).
    let short = "abc";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(short.as_bytes()));
    let pkce = [
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    let code = login_code(&app, &pkce).await;
    let j = json(
        &send(&app, exchange(&code, &[("code_verifier", short)]))
            .await
            .2,
    );
    assert_eq!(j["error"], "invalid_grant", "{j}");
    let code = login_code(&app, &pkce).await;
    let j = json(&send(&app, exchange(&code, &[])).await.2);
    assert_eq!(j["error"], "invalid_grant", "{j}");
}

#[tokio::test]
async fn code_burned_by_bad_redirect_uri_cannot_be_reused() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    let bad = post_form(
        "/auth0/token",
        &[
            ("grant_type", "authorization_code"),
            ("code", &code),
            (
                "redirect_uri",
                "http://localhost:3000/api/auth/callback/other",
            ),
        ],
        &[("authorization", &basic("example-app", "local"))],
    );
    assert_eq!(json(&send(&app, bad).await.2)["error"], "invalid_grant");
    let (s, _, b) = send(&app, exchange(&code, &[])).await;
    assert_eq!(s, 400);
    assert_eq!(json(&b)["error"], "invalid_grant");
}

#[tokio::test]
async fn form_rejection_is_json_invalid_request() {
    let req = Request::builder()
        .method("POST")
        .uri("/auth0/token")
        .header("host", "localhost:9000")
        .body(Body::from("grant_type=authorization_code"))
        .unwrap();
    let (s, h, b) = send(&app(STRICT), req).await;
    assert_eq!(s, 400, "{b}");
    assert!(
        h["content-type"]
            .to_str()
            .unwrap()
            .starts_with("application/json")
    );
    assert_eq!(json(&b)["error"], "invalid_request");
}

#[tokio::test]
async fn secret_in_basic_and_form_is_invalid_request() {
    let app = app(STRICT);
    let code = login_code(&app, &[]).await;
    let (s, _, b) = send(&app, exchange(&code, &[("client_secret", "local")])).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn unknown_grant_type_is_unsupported() {
    let req = post_form(
        "/auth0/token",
        &[("grant_type", "password")],
        &[("authorization", &basic("example-app", "local"))],
    );
    let (s, _, b) = send(&app(STRICT), req).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("unsupported_grant_type"))
    );
}
