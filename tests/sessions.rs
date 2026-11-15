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
