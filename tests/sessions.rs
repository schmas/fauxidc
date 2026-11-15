mod common;
use common::*;

/// Posts the login form for alice and returns the code and the Session cookie `name=value`.
async fn login_with_session(app: &Router) -> (String, String) {
    let (s, h, b) = send(app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    assert_eq!(s, 302, "{b}");
    let code = query_param(&location(&h), "code").unwrap();
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    (code, cookie)
}

#[tokio::test]
async fn login_sets_session_cookie() {
    let app = app(STRICT);
    let (s, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    assert_eq!(s, 302);
    let raw = h
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|c| c.starts_with("fauxidc_session_auth0="))
        .unwrap();
    assert!(
        raw.contains("Path=/auth0")
            && raw.contains("HttpOnly")
            && raw.contains("SameSite=Lax")
            && !raw.contains("Max-Age"),
        "{raw}"
    );
}

#[tokio::test]
async fn prompt_none_with_session_returns_code() {
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    let (s, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(s, 302);
    let loc = location(&h);
    assert!(
        loc.starts_with("http://localhost:3000/api/auth/callback/auth0?"),
        "{loc}"
    );
    assert!(query_param(&loc, "code").is_some());
    assert_eq!(query_param(&loc, "state").as_deref(), Some("st"));
    assert!(
        set_cookie(&h, "fauxidc_session_auth0").is_none(),
        "resume sets no new cookie"
    );
}

#[tokio::test]
async fn prompt_none_without_session_is_login_required() {
    let (_, h, _) = send(&app(STRICT), get(&authorize_url(&[("prompt", "none")]))).await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn unknown_session_cookie_is_login_required() {
    let (_, h, _) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", "fauxidc_session_auth0=not-a-session")],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn prompt_none_ignores_auto_select_and_auto_login() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nauto_login = true\n");
    let app = app(&cfg);
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("login_hint", "alice")]),
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    let loc = location(&h);
    assert!(loc.starts_with("http://localhost:3000/api/auth/callback/auth0?"));
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("login_required")
    );
    assert!(query_param(&loc, "code").is_none());
}

#[tokio::test]
async fn prompt_none_keeps_session_auth_time() {
    let app = app(STRICT);
    let (code1, cookie) = login_with_session(&app).await;
    let first = exchange_code_for(&app, &code1).await;
    let t1 = claims_of(first["id_token"].as_str().unwrap());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    let second = exchange_code_for(&app, &query_param(&location(&h), "code").unwrap()).await;
    let t2 = claims_of(second["id_token"].as_str().unwrap());
    assert_eq!(t1["auth_time"], t2["auth_time"]);
    assert_eq!(t1["sid"], t2["sid"]);
    assert!(t1["sid"].is_string());
    assert!(t2["iat"].as_u64().unwrap() > t2["auth_time"].as_u64().unwrap());
}

#[tokio::test]
async fn session_of_one_issuer_does_not_work_at_another() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    let (_, cookie) = login_with_session(&app).await;
    let value = cookie.split_once('=').unwrap().1;
    let url = authorize_url(&[("prompt", "none")]).replacen("/auth0/", "/okta/", 1);
    let (_, h, _) = send(
        &app,
        get_with(
            &url,
            &[("cookie", &format!("fauxidc_session_okta={value}"))],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn endsession_deletes_the_session() {
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    let (_, h, _) = send(&app, get_with("/auth0/endsession", &[("cookie", &cookie)])).await;
    assert!(set_cookie(&h, "fauxidc_session_auth0").is_some_and(|c| c == "fauxidc_session_auth0="));
    assert!(set_cookie(&h, "fauxidc_user_auth0").is_some());
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn auto_select_sign_in_creates_a_session() {
    let app = app(STRICT);
    let (s, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[]),
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    assert_eq!(s, 302);
    assert!(set_cookie(&h, "fauxidc_session_auth0").is_some());
}

#[tokio::test]
async fn remember_sets_both_cookies() {
    let (_, h, _) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_fields(&[("remember", "on")]),
            &[],
        ),
    )
    .await;
    assert_eq!(
        set_cookie(&h, "fauxidc_user_auth0").as_deref(),
        Some("fauxidc_user_auth0=alice")
    );
    assert!(set_cookie(&h, "fauxidc_session_auth0").is_some());
}

#[tokio::test]
async fn refreshed_and_test_api_id_tokens_have_no_sid() {
    let app = app(STRICT);
    let idt = test_token(&app, "auth0", json!({"user": "alice"})).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(claims_of(&idt).get("sid").is_none());
}

#[tokio::test]
async fn prompt_login_shows_page_with_session() {
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    let (s, _, b) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "login")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("<form"));
}

#[tokio::test]
async fn prompt_select_account_skips_auto_select() {
    let (s, _, b) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[("prompt", "select_account")]),
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("<form"));
}

#[tokio::test]
async fn prompt_none_with_another_value_is_invalid_request() {
    let (_, h, _) = send(
        &app(STRICT),
        get(&authorize_url(&[("prompt", "none login")])),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("invalid_request")
    );
    let lenient = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let (_, h, _) = send(
        &app(&lenient),
        get(&authorize_url(&[("prompt", "none login")])),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("invalid_request")
    );
}

#[tokio::test]
async fn max_age_exceeded_with_prompt_none_is_login_required() {
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("max_age", "1")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("max_age", "3600")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(query_param(&location(&h), "code").is_some());
}

#[tokio::test]
async fn max_age_zero_forces_the_page_over_auto_select() {
    let (s, _, b) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[("max_age", "0")]),
            &[("cookie", "fauxidc_user_auth0=alice")],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("<form"));
    assert!(
        b.contains(r#"name="max_age" value="0""#),
        "max_age is posted back"
    );
}

#[tokio::test]
async fn bad_max_age_is_invalid_request_in_strict_and_ignored_in_lenient() {
    let (_, h, _) = send(&app(STRICT), get(&authorize_url(&[("max_age", "soon")]))).await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("invalid_request")
    );
    let lenient = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    assert_eq!(
        send(&app(&lenient), get(&authorize_url(&[("max_age", "soon")])))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn id_token_hint_must_match_the_session() {
    let app = app(STRICT);
    let (code, cookie) = login_with_session(&app).await;
    let alice_idt = exchange_code_for(&app, &code).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("id_token_hint", &alice_idt)]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(query_param(&location(&h), "code").is_some());
    let bob_idt = test_token(&app, "auth0", json!({"user": "bob"})).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("id_token_hint", &bob_idt)]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn expired_id_token_hint_is_accepted() {
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    let expired =
        test_token(&app, "auth0", json!({"user": "alice", "expires_in": -60})).await["id_token"]
            .as_str()
            .unwrap()
            .to_owned();
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("id_token_hint", &expired)]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(
        query_param(&location(&h), "code").is_some(),
        "{}",
        location(&h)
    );
}

#[tokio::test]
async fn invalid_id_token_hint_is_invalid_request_in_strict_and_ignored_in_lenient() {
    let app_strict = app(STRICT);
    let (_, cookie) = login_with_session(&app_strict).await;
    let (_, h, _) = send(
        &app_strict,
        get_with(
            &authorize_url(&[("prompt", "none"), ("id_token_hint", "not.a.jwt")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("invalid_request")
    );

    let lenient = app(&STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n"));
    let (_, cookie) = login_with_session(&lenient).await;
    let (_, h, _) = send(
        &lenient,
        get_with(
            &authorize_url(&[("prompt", "none"), ("id_token_hint", "not.a.jwt")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(query_param(&location(&h), "code").is_some());
}

#[tokio::test]
async fn custom_user_session_works_with_prompt_none() {
    // The removed-User rule is covered by the `silent_session` unit test in src/authorize.rs.
    let app = app(STRICT);
    let (s, h, _) = send(
        &app,
        post_form(
            "/auth0/authorize",
            &login_fields(&[("user", "__custom__"), ("custom_sub", "c-1")]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 302);
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(query_param(&location(&h), "code").is_some());
}

#[tokio::test]
async fn max_age_with_a_fresh_session_keeps_auth_time() {
    // OIDF oidcc-max-age-10000: a Session younger than max_age is reused, without the page.
    let app = app(STRICT);
    let (code, cookie) = login_with_session(&app).await;
    let t1 = claims_of(
        exchange_code_for(&app, &code).await["id_token"]
            .as_str()
            .unwrap(),
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (s, h, b) = send(
        &app,
        get_with(
            &authorize_url(&[("max_age", "10000")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    let code = query_param(&location(&h), "code").unwrap();
    let t2 = claims_of(
        exchange_code_for(&app, &code).await["id_token"]
            .as_str()
            .unwrap(),
    );
    assert_eq!(t1["auth_time"], t2["auth_time"]);
    assert_eq!(t1["sid"], t2["sid"]);
}

#[tokio::test]
async fn max_age_with_an_old_session_shows_the_page() {
    // OIDF oidcc-max-age-1: a Session older than max_age means a new sign-in.
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (s, _, b) = send(
        &app,
        get_with(&authorize_url(&[("max_age", "1")]), &[("cookie", &cookie)]),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("<form"));
}

#[tokio::test]
async fn request_without_max_age_ignores_the_session() {
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    let (s, _, _) = send(&app, get_with(&authorize_url(&[]), &[("cookie", &cookie)])).await;
    assert_eq!(s, 200, "only prompt=none and max_age use the Session");
}

#[tokio::test]
async fn prompt_none_with_max_age_zero_is_login_required() {
    // Ruling 7: max_age=0 acts as prompt=login, which prompt=none forbids (OIDC Core 3.1.2.1).
    let app = app(STRICT);
    let (_, cookie) = login_with_session(&app).await;
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("max_age", "0")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
    assert!(query_param(&location(&h), "code").is_none());
}

#[tokio::test]
async fn id_token_hint_is_compared_with_the_current_clients_sub() {
    let cfg = format!(
        "{STRICT}\n[client.other]\nclient_secret = \"s\"\nredirect_uris = [\"http://localhost:4000/cb\"]\nid_claims = {{ sub = \"fixed\" }}\n"
    );
    let app = app(&cfg);
    let (_, cookie) = login_with_session(&app).await;
    let other = |extra: &[(&str, &str)]| {
        let mut params = vec![
            ("client_id", "other"),
            ("redirect_uri", "http://localhost:4000/cb"),
            ("prompt", "none"),
        ];
        params.extend_from_slice(extra);
        authorize_url(&params)
    };
    let (_, h, _) = send(&app, get_with(&other(&[]), &[("cookie", &cookie)])).await;
    let code = query_param(&location(&h), "code").expect("a code for other");
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", "http://localhost:4000/cb"),
            ],
            &[("authorization", &basic("other", "s"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let idt = json(&b)["id_token"].as_str().unwrap().to_owned();
    let (_, h, _) = send(
        &app,
        get_with(&other(&[("id_token_hint", &idt)]), &[("cookie", &cookie)]),
    )
    .await;
    let loc = location(&h);
    assert!(query_param(&loc, "code").is_some(), "{loc}");
}
