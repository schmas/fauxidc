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

/// The `name=value` pair of the debugger state cookie in a `/start` response.
fn state_cookie(h: &HeaderMap) -> String {
    let cookie = set_cookie(h, "fauxidc_debugger_auth0").expect("state cookie");
    assert!(cookie.len() > "fauxidc_debugger_auth0=".len(), "{cookie}");
    cookie
}

/// Runs the debugger flow up to the callback and returns the callback path and the state
/// cookie (`name=value`).
async fn run_to_callback(app: &Router) -> (String, String) {
    let (s, h, _) = send(app, get("/auth0/debugger/start")).await;
    assert_eq!(s, 302);
    let cookie = state_cookie(&h);
    let auth = location(&h);
    let mut form: Vec<(String, String)> =
        serde_urlencoded::from_str(auth.split_once('?').unwrap().1).unwrap();
    form.push(("user".into(), "alice".into()));
    let form: Vec<(&str, &str)> = form.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (s, h, b) = send(app, post_form("/auth0/authorize", &form, &[])).await;
    assert_eq!(s, 302, "{b}");
    let path = location(&h)
        .trim_start_matches("http://localhost:9000")
        .to_owned();
    (path, cookie)
}

#[tokio::test]
async fn debugger_flow_shows_decoded_tokens() {
    let app = app(STRICT);
    let (s, h, _) = send(&app, get("/auth0/debugger/start")).await;
    assert_eq!(s, 302);
    let cookie = state_cookie(&h);
    let auth = location(&h);
    assert_eq!(query_param(&auth, "client_id").as_deref(), Some("debugger"));
    assert_eq!(
        query_param(&auth, "redirect_uri").as_deref(),
        Some("http://localhost:9000/auth0/debugger/callback")
    );
    assert_eq!(
        query_param(&auth, "code_challenge_method").as_deref(),
        Some("S256")
    );
    let path = auth.trim_start_matches("http://localhost:9000");
    let (s, _, b) = send(&app, get(path)).await; // the login page
    assert_eq!(s, 200, "{b}");
    let mut form: Vec<(String, String)> =
        serde_urlencoded::from_str(auth.split_once('?').unwrap().1).unwrap();
    form.push(("user".into(), "alice".into()));
    let form: Vec<(&str, &str)> = form.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (s, h, _) = send(&app, post_form("/auth0/authorize", &form, &[])).await;
    assert_eq!(s, 302);
    let cb = location(&h);
    let (s, _, b) = send(
        &app,
        get_with(
            cb.trim_start_matches("http://localhost:9000"),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("id_token") && b.contains("access_token") && b.contains("valid (kid"));
}

#[tokio::test]
async fn start_takes_a_scope() {
    let (_, h, _) = send(&app(STRICT), get("/auth0/debugger/start?scope=openid")).await;
    assert_eq!(
        query_param(&location(&h), "scope").as_deref(),
        Some("openid")
    );
    let (_, h, _) = send(&app(STRICT), get("/auth0/debugger/start")).await;
    assert_eq!(
        query_param(&location(&h), "scope").as_deref(),
        Some("openid profile email")
    );
}

#[tokio::test]
async fn callback_with_unknown_state_is_an_error_page() {
    let (s, _, b) = send(
        &app(STRICT),
        get("/auth0/debugger/callback?code=x&state=nope"),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("unknown or expired state"));
}

#[tokio::test]
async fn state_is_single_use() {
    let app = app(STRICT);
    let (cb, cookie) = run_to_callback(&app).await;
    let (s, _, b) = send(&app, get_with(&cb, &[("cookie", &cookie)])).await;
    assert_eq!(s, 200, "{b}");
    let (s, _, b) = send(&app, get_with(&cb, &[("cookie", &cookie)])).await;
    assert_eq!(s, 400);
    assert!(b.contains("unknown or expired state"));
}

#[tokio::test]
async fn state_of_another_issuer_is_rejected() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    let (cb, cookie) = run_to_callback(&app).await;
    let other = cb.replace("/auth0/", "/okta/");
    let cookie = cookie.replace("fauxidc_debugger_auth0", "fauxidc_debugger_okta");
    let (s, _, b) = send(&app, get_with(&other, &[("cookie", &cookie)])).await;
    assert_eq!(s, 400);
    assert!(b.contains("unknown or expired state"));
}

#[tokio::test]
async fn debugger_client_rejects_other_redirect_paths() {
    let url = "/auth0/authorize?response_type=code&client_id=debugger&redirect_uri=http%3A%2F%2Fevil.example.com%2Fother&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
    let (s, h, _) = send(&app(STRICT), get(url)).await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none());
    let lenient = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let (s, h, _) = send(&app(&lenient), get(url)).await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none());
}

#[tokio::test]
async fn debugger_client_rejects_another_host() {
    let app = app(STRICT);
    let url = "/auth0/authorize?client_id=debugger&response_type=code&prompt=none&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fevil.example.com%2Fauth0%2Fdebugger%2Fcallback";
    let (s, h, _) = send(&app, get(url)).await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none());
}

#[tokio::test]
async fn debugger_flow_needs_the_state_cookie() {
    let app = app(STRICT);
    let (cb, _cookie) = run_to_callback(&app).await;
    let (s, _, b) = send(&app, get(&cb)).await;
    assert_eq!(s, 400);
    assert!(b.contains("unknown or expired state"), "{b}");
    let (cb, cookie) = run_to_callback(&app).await;
    let (s, _, b) = send(
        &app,
        get_with(&cb, &[("cookie", "fauxidc_debugger_auth0=wrong")]),
    )
    .await;
    assert_eq!(s, 400, "a wrong cookie value: {b}");
    let (s, h, b) = send(&app, get_with(&cb, &[("cookie", &cookie)])).await;
    assert_eq!(s, 200, "{b}");
    assert!(b.contains("valid (kid"), "{b}");
    let cleared = h
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|v| v.starts_with("fauxidc_debugger_auth0="))
        .expect("the callback clears the cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
}

#[tokio::test]
async fn start_sets_the_state_cookie() {
    let (_, h, _) = send(&app(STRICT), get("/auth0/debugger/start")).await;
    let state = query_param(&location(&h), "state").unwrap();
    let raw = h
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|v| v.starts_with("fauxidc_debugger_auth0="))
        .unwrap();
    assert_eq!(
        raw,
        format!(
            "fauxidc_debugger_auth0={state}; Path=/auth0/debugger; HttpOnly; SameSite=Lax; Max-Age=600"
        )
    );
}

#[tokio::test]
async fn builtin_client_needs_s256_in_lenient_mode() {
    let lenient = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&lenient);
    let base = "/auth0/authorize?response_type=code&client_id=debugger&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fauth0%2Fdebugger%2Fcallback";
    let plain = format!(
        "{base}&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=plain"
    );
    for url in [base.to_owned(), plain] {
        let (s, h, b) = send(&app, get(&url)).await;
        assert_eq!(s, 302, "{url}: {b}");
        let loc = location(&h);
        assert_eq!(
            query_param(&loc, "error").as_deref(),
            Some("invalid_request"),
            "{url}"
        );
        assert_eq!(
            query_param(&loc, "error_description").as_deref(),
            Some("the debugger Client needs PKCE with S256"),
            "{url}"
        );
    }
}

#[tokio::test]
async fn missing_token_field_is_an_error_page() {
    let (s, _, b) = send(&app(STRICT), post_form("/auth0/debugger", &[], &[])).await;
    assert_eq!(s, 400);
    assert!(b.contains("paste a JWT"), "{b}");
}

#[tokio::test]
async fn other_issuer_token_shows_the_iss_note() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    let okta = test_token(&app, "okta", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &okta)], &[])).await;
    let b = b.replace("&#x2f;", "/"); // minijinja escapes `/` in HTML
    assert!(b.contains("valid (kid"), "{b}");
    assert!(
        b.contains(
            "iss http://localhost:9000/okta is not this Issuer (http://localhost:9000/auth0/)"
        ),
        "{b}"
    );
    let own = test_token(&app, "auth0", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &own)], &[])).await;
    assert!(b.contains("iss matches this Issuer"), "{b}");
}

#[tokio::test]
async fn debugger_client_requires_pkce() {
    let url = "/auth0/authorize?response_type=code&client_id=debugger&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fauth0%2Fdebugger%2Fcallback";
    let (s, h, _) = send(&app(STRICT), get(url)).await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("invalid_request")
    );
}

#[tokio::test]
async fn configured_debugger_client_wins() {
    let cfg =
        format!("{STRICT}\n[client.debugger]\nredirect_uris = [\"http://localhost:7000/cb\"]\n");
    let url = "/auth0/authorize?response_type=code&client_id=debugger&redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fauth0%2Fdebugger%2Fcallback&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
    assert_eq!(send(&app(&cfg), get(url)).await.0, 400); // the configured Client has another redirect URI
}

#[tokio::test]
async fn authorize_error_is_shown() {
    let app = app(STRICT);
    let (_, h, _) = send(&app, get("/auth0/debugger/start")).await;
    let state = query_param(&location(&h), "state").unwrap();
    let cookie = state_cookie(&h);
    let (s, _, b) = send(
        &app,
        get_with(
            &format!(
                "/auth0/debugger/callback?error=access_denied&error_description=no&state={state}"
            ),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("access_denied"));
}

#[tokio::test]
async fn authorize_error_without_the_state_cookie_is_not_shown() {
    let (s, _, b) = send(
        &app(STRICT),
        get("/auth0/debugger/callback?error=x&error_description=spoofed%20text&state=s"),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("unknown or expired state"), "{b}");
    assert!(!b.contains("spoofed text"), "{b}");
}

#[tokio::test]
async fn stale_callback_keeps_the_cookie_of_the_flow_in_progress() {
    let app = app(STRICT);
    let (cb_a, _cookie_a) = run_to_callback(&app).await;
    let (cb_b, cookie_b) = run_to_callback(&app).await;
    // Tab A's callback with tab B's cookie fails and must not clear the cookie.
    let (s, h, _) = send(&app, get_with(&cb_a, &[("cookie", &cookie_b)])).await;
    assert_eq!(s, 400);
    assert!(
        set_cookie(&h, "fauxidc_debugger_auth0").is_none(),
        "the stale callback cleared the cookie"
    );
    let (s, _, b) = send(&app, get_with(&cb_b, &[("cookie", &cookie_b)])).await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn token_endpoint_accepts_the_debugger_client() {
    let app = app(STRICT);
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let redirect = "http://localhost:9000/auth0/debugger/callback";
    let form = [
        ("client_id", "debugger"),
        ("redirect_uri", redirect),
        ("response_type", "code"),
        ("scope", "openid"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("user", "alice"),
    ];
    let (s, h, b) = send(&app, post_form("/auth0/authorize", &form, &[])).await;
    assert_eq!(s, 302, "{b}");
    let code = query_param(&location(&h), "code").unwrap();
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "debugger"),
                ("code", &code),
                ("redirect_uri", redirect),
                ("code_verifier", verifier),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert!(json(&b)["id_token"].is_string());
}

#[tokio::test]
async fn debugger_shows_badges_and_code_blocks() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[]).await;
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &at)], &[])).await;
    assert!(b.contains("badge-success"), "{b}");
    assert!(b.contains("<pre") && b.contains("<code"));
    assert!(b.contains("/_mock/static/fauxidc.css"));
    assert!(!b.contains("login.css"));
    let stranger = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let t = sign_with(&stranger, &json!({"sub":"x"}));
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &t)], &[])).await;
    assert!(b.contains("badge-error"), "{b}");
}

#[tokio::test]
async fn debugger_badges_for_iss_mismatch_and_expired() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    let okta = test_token(&app, "okta", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &okta)], &[])).await;
    assert!(b.contains(">iss mismatch</span>"), "{b}");
    assert!(!b.contains(">iss ok</span>"), "{b}");
    assert!(!b.contains(">expired</span>"), "{b}");
    let own = test_token(&app, "auth0", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &own)], &[])).await;
    assert!(b.contains(">iss ok</span>"), "{b}");
    let stranger = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let t = sign_with(&stranger, &json!({"sub":"x","exp":1}));
    let (_, _, b) = send(&app, post_form("/auth0/debugger", &[("token", &t)], &[])).await;
    assert!(b.contains(">expired</span>"), "{b}");
}

#[tokio::test]
async fn debugger_error_alert_wraps() {
    let long = "x".repeat(600);
    let (_, _, b) = send(
        &app(STRICT),
        post_form("/auth0/debugger", &[("token", &long)], &[]),
    )
    .await;
    assert!(
        b.contains("<span class=\"min-w-0 wrap-anywhere\">not a JWT"),
        "{b}"
    );
}
