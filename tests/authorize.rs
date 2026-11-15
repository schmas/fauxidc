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
            &login_form(&[
                ("override_claims", "{not json"),
                ("user", "bob"),
                ("remember", "on"),
            ]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("Override claims must be a JSON object"));
    assert!(b.contains("{not json"));
    assert!(b.contains(r#"value="bob" selected"#), "{b}");
    assert!(!b.contains(r#"value="alice" selected"#));
    assert!(b.contains(r#"name="remember" value="1" checked"#), "{b}");
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
    assert!(b.contains(r#"value="__custom__" selected"#), "{b}");
    assert!(!b.contains("checked"), "remember was not posted");
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
    let cookie = h
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|c| c.starts_with("fauxidc_user_auth0="))
        .unwrap();
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
    assert!(set_cookie(&h, "fauxidc_user_auth0").is_none());
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

#[tokio::test]
async fn login_form_posts_to_overridden_authorize() {
    let cfg = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\npaths = { authorize = \"/oauth/authorize\" }\n",
    );
    let app = app(&cfg);
    let url = authorize_url(&[]).replace("/auth0/authorize", "/auth0/oauth/authorize");
    let (s, _, html) = send(&app, get(&url)).await;
    assert_eq!(s, 200, "{html}");
    // The template engine escapes `/` as `&#x2f;`; a browser decodes it.
    assert!(
        html.contains("action=\"&#x2f;auth0&#x2f;oauth&#x2f;authorize\""),
        "{html}"
    );
}

#[tokio::test]
async fn authorize_post_without_user_is_an_authorization_request() {
    let form = [
        ("client_id", "example-app"),
        ("response_type", "code"),
        ("scope", "openid"),
        (
            "redirect_uri",
            "http://localhost:3000/api/auth/callback/auth0",
        ),
        ("state", "st"),
    ];
    let (s, _, b) = send(&app(STRICT), post_form("/auth0/authorize", &form, &[])).await;
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("Alice Admin") && !b.contains("Choose a user"));
}

#[tokio::test]
async fn request_object_is_not_supported() {
    let (s, h, _) = send(
        &app(STRICT),
        get(&authorize_url(&[("request", "eyJhbGciOiJub25lIn0.e30.")])),
    )
    .await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("request_not_supported")
    );
    assert_eq!(query_param(&location(&h), "state").as_deref(), Some("st"));
    let (s, h, _) = send(
        &app(STRICT),
        get(&authorize_url(&[(
            "request_uri",
            "https://rp.example.com/r",
        )])),
    )
    .await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("request_uri_not_supported")
    );
}

#[tokio::test]
async fn request_object_is_not_supported_in_lenient_mode() {
    let lenient = STRICT.replace(
        "sub_template = \"auth0|{user_id}\"",
        "sub_template = \"auth0|{user_id}\"\nlenient = true",
    );
    let (s, h, _) = send(
        &app(&lenient),
        get(&authorize_url(&[("request", "eyJhbGciOiJub25lIn0.e30.")])),
    )
    .await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("request_not_supported")
    );
}

const TEMPLATE: &str = "[issuer.auth0.custom_user]\nlabel = \"Other…\"\n[issuer.auth0.custom_user.claims]\nemail = \"{username}@example.test\"\nemail_verified = true\nname = \"{username} Example\"\ngroups = [\"{username}-team\"]\norg = { unit = \"{username} st\" }\n";

#[tokio::test]
async fn login_page_shows_the_username_field() {
    let app = app(&format!("{STRICT}{TEMPLATE}"));
    let (s, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert_eq!(s, 200);
    assert!(b.contains("name=\"username\""), "{b}");
    assert!(b.contains(">Other…</option>"), "{b}");
    assert!(!b.contains("name=\"custom_claims\""), "{b}");
    assert!(!b.contains("name=\"custom_sub\""), "{b}");
    assert!(b.contains("name=\"override_claims\""), "{b}");
}

#[tokio::test]
async fn custom_user_template_builds_the_user() {
    let app = app(&format!("{STRICT}{TEMPLATE}"));
    let code = login_code(
        &app,
        &[
            ("user", "__custom__"),
            ("username", "  Carol "),
            ("custom_sub", "ignored"),
            ("custom_claims", r#"{"extra":"ignored"}"#),
            ("override_claims", r#"{"name":"C"}"#),
        ],
    )
    .await;
    let tokens = exchange_code_for(&app, &code).await;
    let id = claims_of(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "carol", "{id}");
    assert_eq!(id["email"], "carol@example.test", "{id}");
    assert_eq!(id["email_verified"], true, "{id}");
    assert_eq!(id["groups"], serde_json::json!(["carol-team"]), "{id}");
    assert_eq!(id["org"], serde_json::json!({"unit": "carol st"}), "{id}");
    assert_eq!(id["name"], "C", "override wins: {id}");
    assert!(id.get("extra").is_none(), "{id}");
}

#[tokio::test]
async fn empty_username_shows_the_page_with_an_error() {
    let app = app(&format!("{STRICT}{TEMPLATE}"));
    let (s, h, b) = send(
        &app,
        post_form(
            "/auth0/authorize",
            &login_form(&[
                ("user", "__custom__"),
                ("username", "   "),
                ("custom_sub", "dave"),
            ]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none());
    assert!(b.contains("Enter a username"), "{b}");
    assert!(b.contains("name=\"username\""), "{b}");
    assert!(b.contains(r#"value="__custom__" selected"#), "{b}");
}

#[tokio::test]
async fn username_is_kept_after_an_error() {
    let app = app(&format!("{STRICT}{TEMPLATE}"));
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/authorize",
            &login_form(&[
                ("user", "__custom__"),
                ("username", "Dave"),
                ("override_claims", "{not json"),
            ]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("Override claims must be a JSON object"), "{b}");
    assert!(b.contains(r#"name="username" value="Dave""#), "{b}");
}

#[tokio::test]
async fn without_template_the_subject_fields_stay() {
    let app = app(STRICT);
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert!(b.contains("name=\"custom_sub\"") && b.contains("name=\"custom_claims\""));
    assert!(!b.contains("name=\"username\""), "{b}");
    assert!(b.contains(">Custom…</option>"), "{b}");
    let code = login_code(
        &app,
        &[
            ("user", "__custom__"),
            ("custom_sub", "dave"),
            ("username", "ignored"),
        ],
    )
    .await;
    let tokens = exchange_code_for(&app, &code).await;
    assert_eq!(
        claims_of(tokens["id_token"].as_str().unwrap())["sub"],
        "dave"
    );
}

#[tokio::test]
async fn custom_user_follows_reload() {
    let (app, handle) = live_app(STRICT);
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert!(!b.contains("name=\"username\""));
    handle
        .apply(
            fauxidc::config::load_str(&format!("{STRICT}{TEMPLATE}"))
                .unwrap()
                .config,
        )
        .unwrap();
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert!(
        b.contains("name=\"username\"") && b.contains(">Other…</option>"),
        "{b}"
    );
    let changed = TEMPLATE.replace("Other…", "Someone else…");
    handle
        .apply(
            fauxidc::config::load_str(&format!("{STRICT}{changed}"))
                .unwrap()
                .config,
        )
        .unwrap();
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert!(b.contains(">Someone else…</option>"), "{b}");
}
