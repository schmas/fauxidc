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

/// Runs the debugger flow up to the callback and returns the callback path.
async fn run_to_callback(app: &Router) -> String {
    let (s, h, _) = send(app, get("/auth0/debugger/start")).await;
    assert_eq!(s, 302);
    let auth = location(&h);
    let mut form: Vec<(String, String)> =
        serde_urlencoded::from_str(auth.split_once('?').unwrap().1).unwrap();
    form.push(("user".into(), "alice".into()));
    let form: Vec<(&str, &str)> = form.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (s, h, b) = send(app, post_form("/auth0/authorize", &form, &[])).await;
    assert_eq!(s, 302, "{b}");
    location(&h)
        .trim_start_matches("http://localhost:9000")
        .to_owned()
}

#[tokio::test]
async fn debugger_flow_shows_decoded_tokens() {
    let app = app(STRICT);
    let (s, h, _) = send(&app, get("/auth0/debugger/start")).await;
    assert_eq!(s, 302);
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
    let (s, _, b) = send(&app, get(cb.trim_start_matches("http://localhost:9000"))).await;
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
    let cb = run_to_callback(&app).await;
    let (s, _, b) = send(&app, get(&cb)).await;
    assert_eq!(s, 200, "{b}");
    let (s, _, b) = send(&app, get(&cb)).await;
    assert_eq!(s, 400);
    assert!(b.contains("unknown or expired state"));
}

#[tokio::test]
async fn state_of_another_issuer_is_rejected() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    let cb = run_to_callback(&app).await;
    let other = cb.replace("/auth0/", "/okta/");
    let (s, _, b) = send(&app, get(&other)).await;
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
    let (s, _, b) = send(
        &app(STRICT),
        get("/auth0/debugger/callback?error=access_denied&error_description=no"),
    )
    .await;
    assert_eq!(s, 200);
    assert!(b.contains("access_denied"));
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
