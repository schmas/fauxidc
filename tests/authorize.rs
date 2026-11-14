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

#[tokio::test]
async fn remember_sets_cookie_and_next_request_skips_page() {
    let app = app(STRICT);
    let (_, h, _) = send(
        &app,
        post_form("/auth0/authorize", &login_form(&[("remember", "on")]), &[]),
    )
    .await;
    let cookie = h["set-cookie"].to_str().unwrap().to_string();
    assert!(
        cookie.starts_with("fauxidc_user_auth0=alice;")
            && cookie.contains("Path=/auth0")
            && cookie.contains("HttpOnly")
    );
    let (s, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[]),
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    assert_eq!(s, 302);
    assert!(query_param(&location(&h), "code").is_some());
}

#[tokio::test]
async fn prompt_login_ignores_cookie() {
    let (s, _, _) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[("prompt", "login")]),
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn cookie_for_removed_user_shows_page() {
    let (s, _, _) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[]),
            &[("cookie", "fauxidc_user_auth0=ghost")],
        ),
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn login_hint_with_auto_login() {
    let auto = app(&STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nauto_login = true\n"));
    let (s, _, _) = send(&auto, get(&authorize_url(&[("login_hint", "bob")]))).await;
    assert_eq!(s, 302);
    let (s, _, b) = send(&app(STRICT), get(&authorize_url(&[("login_hint", "bob")]))).await;
    assert_eq!(s, 200, "no auto_login: page with bob preselected");
    assert!(b.contains(r#"value="bob" selected"#));
}

#[tokio::test]
async fn custom_user_is_not_remembered() {
    let (_, h, _) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_form(&[
                ("user", "__custom__"),
                ("custom_sub", "c-1"),
                ("remember", "on"),
            ]),
            &[],
        ),
    )
    .await;
    assert!(h.get("set-cookie").is_none());
}

#[tokio::test]
async fn empty_pkce_and_nonce_values_count_as_absent() {
    let app = app(STRICT);
    let spa = [
        ("client_id", "spa"),
        ("redirect_uri", "http://localhost:5173/cb"),
    ];
    let mut empty = spa.to_vec();
    empty.push(("code_challenge", ""));
    let (s, h, _) = send(&app, get(&authorize_url(&empty))).await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error_description").unwrap(),
        "code_challenge required"
    );
    empty.push(("code_challenge_method", ""));
    let (_, h, _) = send(&app, get(&authorize_url(&empty))).await;
    assert_eq!(
        query_param(&location(&h), "error_description").unwrap(),
        "code_challenge required"
    );

    let nonce_app =
        common::app(&STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nrequire_nonce = true\n"));
    let (s, h, _) = send(&nonce_app, get(&authorize_url(&[("nonce", "")]))).await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error_description").unwrap(),
        "nonce required"
    );
}

#[tokio::test]
async fn malformed_code_challenge_is_invalid_request() {
    let app = app(STRICT);
    for challenge in ["short", &"a".repeat(129), &format!("{}!", "a".repeat(42))] {
        let (s, h, _) = send(
            &app,
            get(&authorize_url(&[
                ("code_challenge", challenge),
                ("code_challenge_method", "S256"),
            ])),
        )
        .await;
        assert_eq!(s, 302, "{challenge}");
        assert_eq!(
            query_param(&location(&h), "error").unwrap(),
            "invalid_request",
            "{challenge}"
        );
    }
    let ok = "a".repeat(43) + "-._~";
    let (s, _, _) = send(
        &app,
        get(&authorize_url(&[
            ("code_challenge", &ok),
            ("code_challenge_method", "plain"),
        ])),
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn missing_response_type_is_invalid_request() {
    let app = app(STRICT);
    let url = "/auth0/authorize?client_id=example-app&scope=openid&state=st\
               &redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback%2Fauth0";
    let (s, h, _) = send(&app, get(url)).await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "invalid_request"
    );
    assert_eq!(query_param(&location(&h), "state").unwrap(), "st");
    let (_, h, _) = send(&app, get(&format!("{url}&response_type="))).await;
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "invalid_request"
    );
}
