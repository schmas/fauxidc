mod common;
use common::*;

#[tokio::test]
async fn valid_request_shows_login_page() {
    let (s, _, b) = send(&app(STRICT), get(&authorize_url(&[]))).await;
    assert_eq!(s, 200);
    assert!(b.contains("Alice Admin") && b.contains("Bobby Viewer") && b.contains("Custom"));
    assert!(b.contains("example-app") && b.contains("auth0"));
    assert!(b.contains(r#"name="state" value="st""#));
}

#[tokio::test]
async fn unknown_client_and_bad_redirect_never_redirect() {
    let app = app(STRICT);
    let (s, h, b) = send(&app, get(&authorize_url(&[("client_id", "nope")]))).await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none() && b.contains("unknown client_id: nope"));
    let (s, h, b) = send(
        &app,
        get(&authorize_url(&[(
            "redirect_uri",
            "http://localhost:3001/api/auth/callback/x",
        )])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none() && b.contains("redirect_uri not registered"));
}

#[tokio::test]
async fn protocol_errors_redirect_with_state() {
    let app = app(STRICT);
    let (s, h, _) = send(&app, get(&authorize_url(&[("response_type", "token")]))).await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "unsupported_response_type"
    );
    assert_eq!(query_param(&location(&h), "state").unwrap(), "st");
    let (_, h, _) = send(&app, get(&authorize_url(&[("prompt", "none")]))).await;
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "login_required"
    );
    let (_, h, _) = send(
        &app,
        get(&authorize_url(&[
            ("code_challenge_method", "S512"),
            ("code_challenge", "x"),
        ])),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "invalid_request"
    );
}

#[tokio::test]
async fn public_client_needs_pkce_in_strict_mode() {
    let app = app(STRICT);
    let spa = [
        ("client_id", "spa"),
        ("redirect_uri", "http://localhost:5173/cb"),
    ];
    let (_, h, _) = send(&app, get(&authorize_url(&spa))).await;
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "invalid_request"
    );
    let mut with = spa.to_vec();
    with.extend([
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
    ]);
    assert_eq!(send(&app, get(&authorize_url(&with))).await.0, 200);
}

#[tokio::test]
async fn require_nonce() {
    let app = app(&STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nrequire_nonce = true\n"));
    let (_, h, _) = send(&app, get(&authorize_url(&[]))).await;
    assert_eq!(
        query_param(&location(&h), "error_description").unwrap(),
        "nonce required"
    );
    assert_eq!(
        send(&app, get(&authorize_url(&[("nonce", "n1")]))).await.0,
        200
    );
}

#[tokio::test]
async fn lenient_accepts_unknown_client_and_missing_pkce() {
    let app = app(
        "[issuer.dev]\nissuer_url = \"http://localhost:9000/dev\"\nlenient = true\n[user.alice]\n",
    );
    let (s, _, _) = send(
        &app,
        get(
            "/dev/authorize?client_id=anything&redirect_uri=http://localhost:1234/cb&response_type=code&scope=openid",
        ),
    )
    .await;
    assert_eq!(s, 200);
}

fn login_form(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut f = vec![
        ("client_id", "example-app"),
        (
            "redirect_uri",
            "http://localhost:3000/api/auth/callback/auth0",
        ),
        ("response_type", "code"),
        ("scope", "openid profile email"),
        ("state", "st"),
        ("user", "alice"),
    ];
    for &(k, v) in extra {
        f.retain(|&(a, _)| a != k);
        f.push((k, v));
    }
    f
}

#[tokio::test]
async fn login_issues_code_and_redirects() {
    let (s, h, _) = send(
        &app(STRICT),
        post_form("/auth0/authorize", &login_form(&[]), &[]),
    )
    .await;
    assert_eq!(s, 302);
    let loc = location(&h);
    assert!(loc.starts_with("http://localhost:3000/api/auth/callback/auth0?code="));
    assert_eq!(query_param(&loc, "state").unwrap(), "st");
}

#[tokio::test]
async fn tampered_hidden_redirect_is_rejected() {
    let (s, h, _) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_form(&[("redirect_uri", "http://evil.example.com/cb")]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none());
}

#[tokio::test]
async fn bad_json_rerenders_with_input_kept() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_form(&[("override_claims", "{not json")]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("Override claims must be a JSON object"));
    assert!(b.contains("{not json"));
}

#[tokio::test]
async fn custom_user_needs_sub() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_form(&[("user", "__custom__")]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("Custom user needs a sub"));
    let (s, _, _) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_form(&[
                ("user", "__custom__"),
                ("custom_sub", "c-1"),
                ("custom_claims", r#"{"email":"carol@example.com"}"#),
            ]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 302);
}

#[tokio::test]
async fn unknown_user_is_rejected() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form("/auth0/authorize", &login_form(&[("user", "mallory")]), &[]),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("Choose a user"));
}
