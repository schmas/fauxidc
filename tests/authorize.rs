mod common;
use common::*;

#[tokio::test]
async fn valid_request_shows_login_page() {
    let (s, _, b) = send(&app(STRICT), get(&authorize_url(&[]))).await;
    assert_eq!(s, 200);
    assert!(b.contains("Alice Admin") && b.contains("Bobby Viewer"));
    assert!(b.contains("Choose a configured User"), "{b}");
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
    assert_form_view(&b);
    assert!(
        !b.contains(r#"value="1" checked"#),
        "remember was not posted"
    );
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
    assert!(!b.contains(">Other…"), "{b}");
    assert!(b.contains("Turn the switch off to type a username."), "{b}");
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

/// Docs (`docs/templates.md`): in username mode a Claim override can still change `sub`,
/// as `custom_claims` can in subject mode.
#[tokio::test]
async fn username_mode_override_can_change_sub() {
    let app = app(&format!("{STRICT}{TEMPLATE}"));
    let code = login_code(
        &app,
        &[
            ("user", "__custom__"),
            ("username", "carol"),
            ("override_claims", r#"{"sub":"other-sub"}"#),
        ],
    )
    .await;
    let tokens = exchange_code_for(&app, &code).await;
    let id = claims_of(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "other-sub", "{id}");
    assert_eq!(id["email"], "carol@example.test", "{id}");
}

/// Docs (`docs/templates.md`): in subject mode the Claim overrides of a Custom user are
/// checked but not applied.
#[tokio::test]
async fn subject_mode_override_is_checked_but_not_applied() {
    let app = app(STRICT);
    let code = login_code(
        &app,
        &[
            ("user", "__custom__"),
            ("custom_sub", "dave"),
            ("custom_claims", r#"{"name":"D"}"#),
            ("override_claims", r#"{"name":"ignored","extra":1}"#),
        ],
    )
    .await;
    let tokens = exchange_code_for(&app, &code).await;
    let id = claims_of(tokens["id_token"].as_str().unwrap());
    assert_eq!(id["name"], "D", "{id}");
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
    assert_form_view(&b);
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
    assert!(!b.contains("Custom…"), "{b}");
    assert!(
        b.contains("Turn the switch off to type a subject and claims."),
        "{b}"
    );
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
        b.contains("name=\"username\"") && b.contains("to type a username."),
        "{b}"
    );
    handle
        .apply(fauxidc::config::load_str(STRICT).unwrap().config)
        .unwrap();
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert!(!b.contains("name=\"username\""), "{b}");
    assert!(b.contains("to type a subject and claims."), "{b}");
}

/// The opening tag of the element with `id`.
fn tag_with_id<'a>(html: &'a str, id: &str) -> &'a str {
    let at = html.find(&format!("id=\"{id}\"")).expect("element present");
    let start = html[..at].rfind('<').unwrap();
    let end = at + html[at..].find('>').unwrap();
    &html[start..=end]
}

/// Asserts the page starts on the User dropdown: the list is shown and enabled, the Custom
/// user fieldset is `hidden disabled`.
fn assert_list_view(b: &str) {
    let list = tag_with_id(b, "user-list");
    let select = tag_with_id(b, "f-user");
    let custom = tag_with_id(b, "custom-user");
    assert!(!list.contains("hidden"), "{list}");
    assert!(!select.contains("disabled"), "{select}");
    assert!(custom.contains(" hidden disabled"), "{custom}");
}

/// Asserts the page starts on the Custom user form: the fieldset is shown and enabled, the
/// list is `hidden` and its select `disabled`.
fn assert_form_view(b: &str) {
    let list = tag_with_id(b, "user-list");
    let select = tag_with_id(b, "f-user");
    let custom = tag_with_id(b, "custom-user");
    assert!(list.contains(" hidden"), "{list}");
    assert!(select.contains(" disabled"), "{select}");
    assert!(
        !custom.contains("hidden") && !custom.contains("disabled"),
        "{custom}"
    );
}

/// `STRICT` with `show_user_list = true` on the Issuer.
fn strict_list() -> String {
    STRICT.replace(
        "sub_template = \"auth0|{user_id}\"\n",
        "sub_template = \"auth0|{user_id}\"\nshow_user_list = true\n",
    )
}

/// The app of a Zero config (Issuer `default`, Users alice and bob).
fn zero_app() -> Router {
    let inputs = fauxidc::config::LoadInputs {
        config_files: vec![],
        env: vec![],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: tmp_dir(),
    };
    app_from_config(fauxidc::config::load(&inputs).unwrap().config)
}

const ZERO_AUTHORIZE: &str = "/default/authorize?client_id=test&response_type=code&scope=openid&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcb&state=st";

fn zero_form(extra: &[(&'static str, &'static str)]) -> Vec<(&'static str, &'static str)> {
    let mut f = vec![
        ("client_id", "test"),
        ("redirect_uri", "http://localhost:3000/cb"),
        ("response_type", "code"),
        ("scope", "openid"),
        ("state", "st"),
    ];
    f.extend_from_slice(extra);
    f
}

#[tokio::test]
async fn login_page_defaults_to_the_custom_user_form() {
    let (s, _, b) = send(&zero_app(), get(ZERO_AUTHORIZE)).await;
    assert_eq!(s, 200, "{b}");
    assert_form_view(&b);
    assert!(b.contains("name=\"custom_sub\""), "{b}");
    assert!(b.contains(r#"<input type="hidden" name="user" value="__custom__">"#));
    assert!(!b.contains(r#"<option value="__custom__""#), "{b}");
    assert!(b.contains("role=\"switch\""), "{b}");
    assert!(!tag_with_id(&b, "f-show-users").contains("checked"));
    assert!(b.contains("2 Users on this Issuer: alice, bob"), "{b}");
}

#[tokio::test]
async fn login_page_links_to_the_dashboard_users() {
    let (s, h, b) = send(&zero_app(), get(ZERO_AUTHORIZE)).await;
    assert_eq!(s, 200, "{b}");
    assert!(
        b.contains(r#"href="/_mock/#issuers" target="_blank" rel="noopener">Admin"#),
        "{b}"
    );
    // The page sets no cookie, so a dashboard tab cannot change the login flow.
    assert!(h.get("set-cookie").is_none());
}

#[tokio::test]
async fn subject_only_sign_in_returns_a_code() {
    let (s, h, b) = send(
        &zero_app(),
        post_form(
            "/default/authorize",
            &zero_form(&[("user", "__custom__"), ("custom_sub", "carol")]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    assert!(query_param(&location(&h), "code").is_some());
}

#[tokio::test]
async fn issuer_setting_opens_the_user_list() {
    let (s, _, b) = send(&app(&strict_list()), get(&authorize_url(&[]))).await;
    assert_eq!(s, 200);
    assert_list_view(&b);
    assert!(tag_with_id(&b, "f-show-users").contains("checked"));
    assert!(!b.contains(">Saved in this browser"), "{b}");
}

#[tokio::test]
async fn cookie_wins_over_the_issuer_setting() {
    let (_, _, b) = send(
        &app(&strict_list()),
        get_with(
            &authorize_url(&[]),
            &[("cookie", "fauxidc_login_view_auth0=form")],
        ),
    )
    .await;
    assert_form_view(&b);
    assert!(
        b.contains(">Saved in this browser · Sign out clears it"),
        "{b}"
    );
    let (_, _, b) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[]),
            &[("cookie", "a=b; fauxidc_login_view_auth0=list")],
        ),
    )
    .await;
    assert_list_view(&b);
    assert!(b.contains(">Saved in this browser"), "{b}");
}

#[tokio::test]
async fn bad_cookie_value_is_ignored() {
    for (toml, list) in [(STRICT.to_owned(), false), (strict_list(), true)] {
        let (s, _, b) = send(
            &app(&toml),
            get_with(
                &authorize_url(&[]),
                &[("cookie", "fauxidc_login_view_auth0=xyz")],
            ),
        )
        .await;
        assert_eq!(s, 200);
        if list {
            assert_list_view(&b);
        } else {
            assert_form_view(&b);
        }
        assert!(!b.contains(">Saved in this browser"), "{b}");
    }
}

#[tokio::test]
async fn memory_setting_applies_at_once() {
    let app = zero_app();
    let (_, _, b) = send(&app, get(ZERO_AUTHORIZE)).await;
    assert_form_view(&b);
    let body = Body::from(r#"{"show_user_list":true}"#);
    let req = Request::builder()
        .method("PUT")
        .uri("/_mock/default/login")
        .header("host", "localhost:9000")
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    let (s, _, b) = send(&app, req).await;
    assert_eq!(s, 200, "{b}");
    let (_, _, b) = send(&app, get(ZERO_AUTHORIZE)).await;
    assert_list_view(&b);
}

#[tokio::test]
async fn user_error_opens_the_user_list() {
    let cookie = [("cookie", "fauxidc_login_view_auth0=form")];
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_form(&[("user", "nobody")]),
            &cookie,
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert_list_view(&b);
    let cookie = [("cookie", "fauxidc_login_view_auth0=list")];
    let (s, _, b) = send(
        &app(&strict_list()),
        post_form(
            "/auth0/authorize",
            &login_form(&[("user", "__custom__"), ("custom_sub", "")]),
            &cookie,
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("Custom user needs a sub"), "{b}");
    assert_form_view(&b);
}

#[tokio::test]
async fn known_login_hint_opens_the_user_list() {
    let (s, _, b) = send(
        &app(STRICT),
        get_with(
            &authorize_url(&[("login_hint", "bob")]),
            &[("cookie", "fauxidc_login_view_auth0=form")],
        ),
    )
    .await;
    assert_eq!(s, 200);
    assert_list_view(&b);
    assert!(b.contains(r#"<option value="bob" selected>"#), "{b}");
    let (_, _, b) = send(
        &app(STRICT),
        get(&authorize_url(&[("login_hint", "nobody")])),
    )
    .await;
    assert_form_view(&b);
}

#[tokio::test]
async fn no_users_means_no_switch() {
    let without_users = STRICT.split("[user.alice]").next().unwrap().replace(
        "sub_template = \"auth0|{user_id}\"\n",
        "sub_template = \"auth0|{user_id}\"\nshow_user_list = true\n",
    );
    let (s, _, b) = send(
        &app(&without_users),
        get_with(
            &authorize_url(&[]),
            &[("cookie", "fauxidc_login_view_auth0=list")],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_form_view(&b);
    assert!(!b.contains("role=\"switch\""), "{b}");
}

#[tokio::test]
async fn custom_user_list_view_posts_the_user() {
    let app = app(&format!("{}{TEMPLATE}", strict_list()));
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert_list_view(&b);
    let start = b.find("id=\"custom-user\"").unwrap();
    let end = start + b[start..].find("</fieldset>").unwrap();
    assert!(b[start..end].contains("name=\"username\""), "{b}");
    let code = login_code(&app, &[("user", "alice")]).await;
    let tokens = exchange_code_for(&app, &code).await;
    assert_eq!(
        claims_of(tokens["id_token"].as_str().unwrap())["sub"],
        "auth0|alice"
    );
}
