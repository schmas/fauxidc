mod common;
use common::*;

#[tokio::test]
async fn embedded_static_is_served() {
    let (s, h, b) = send(&app(AUTH0), get("/_mock/static/login.css")).await;
    assert_eq!(s, 200);
    assert_eq!(h["content-type"], "text/css");
    assert_ne!(b, "");
}

#[tokio::test]
async fn static_traversal_is_rejected() {
    let app = app(AUTH0);
    assert_eq!(send(&app, get("/_mock/static/../Cargo.toml")).await.0, 404);
    assert_eq!(
        send(&app, get("/_mock/static/%2e%2e/Cargo.toml")).await.0,
        404
    );
}

#[tokio::test]
async fn static_dir_traversal_is_rejected() {
    let root = tmp_dir();
    let dir = root.join("static");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(root.join("secret.txt"), "secret").unwrap();
    std::fs::write(dir.join("a.css"), "body{}").unwrap();
    let toml = format!("[server]\nstatic_dir = \"{}\"\n{AUTH0}", dir.display());
    let app = app(&toml);
    let (s, _, b) = send(&app, get("/_mock/static/a.css")).await;
    assert_eq!((s.as_u16(), b.as_str()), (200, "body{}"));
    for path in [
        "/_mock/static/%2e%2e/secret.txt",
        "/_mock/static/%2e%2e%2fsecret.txt",
        "/_mock/static/sub/%2e%2e/secret.txt",
        "/_mock/static/%2e/a.css",
        "/_mock/static/..%5csecret.txt",
        "/_mock/static//a.css",
    ] {
        let (s, _, b) = send(&app, get(path)).await;
        assert_eq!(s, 404, "{path}");
        assert!(!b.contains("secret"), "{path}");
    }
}

#[tokio::test]
async fn static_dir_overrides_embedded() {
    let dir = tmp_dir();
    std::fs::write(dir.join("login.css"), "custom{}").unwrap();
    let toml = format!("[server]\nstatic_dir = \"{}\"\n{AUTH0}", dir.display());
    let (s, _, b) = send(&app(&toml), get("/_mock/static/login.css")).await;
    assert_eq!((s.as_u16(), b.as_str()), (200, "custom{}"));
}

#[tokio::test]
async fn unknown_static_is_404() {
    assert_eq!(
        send(&app(AUTH0), get("/_mock/static/nope.css")).await.0,
        404
    );
}

#[test]
fn bad_template_fails_startup() {
    let dir = tmp_dir();
    std::fs::write(dir.join("login.html"), "{% if %}").unwrap();
    let cfg = fauxidc::config::load_str(&format!(
        "[server]\ntemplates_dir = \"{}\"\n{STRICT}",
        dir.display()
    ))
    .unwrap()
    .config;
    assert!(matches!(
        fauxidc::state::AppState::new(cfg, fauxidc::keys::KeyHandle::ready(KEY.clone()), true),
        Err(fauxidc::error::StartError::Templates(_))
    ));
}

#[test]
fn missing_login_template_file_fails_startup() {
    let cfg = fauxidc::config::load_str(&format!(
        "{STRICT}\n[issuer.other]\nissuer_url = \"http://localhost:9000/other/\"\nlogin_template = \"/nonexistent/login.html\"\n"
    ))
    .unwrap()
    .config;
    assert!(matches!(
        fauxidc::state::AppState::new(cfg, fauxidc::keys::KeyHandle::ready(KEY.clone()), true),
        Err(fauxidc::error::StartError::Templates(_))
    ));
}

#[tokio::test]
async fn templates_dir_replaces_one_file() {
    let dir = tmp_dir();
    std::fs::write(dir.join("login.html"), "CUSTOM {{ issuer_id }}").unwrap();
    let app = app(&format!(
        "[server]\ntemplates_dir = \"{}\"\n{STRICT}",
        dir.display()
    ));
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert_eq!(b, "CUSTOM auth0");
    let (_, _, b) = send(
        &app,
        get("/auth0/authorize?client_id=nope&redirect_uri=http://x/cb&response_type=code"),
    )
    .await;
    assert!(
        b.contains("unknown client_id"),
        "embedded error.html still used"
    );
}

#[tokio::test]
async fn per_issuer_login_template() {
    let dir = tmp_dir();
    let f = dir.join("a.html");
    std::fs::write(&f, "ISSUER PAGE").unwrap();
    let app = app(&STRICT.replace(
        "[issuer.auth0]\n",
        &format!("[issuer.auth0]\nlogin_template = \"{}\"\n", f.display()),
    ));
    assert_eq!(send(&app, get(&authorize_url(&[]))).await.2, "ISSUER PAGE");
}

#[tokio::test]
async fn templates_dir_replaces_signed_out_page() {
    let dir = tmp_dir();
    std::fs::write(dir.join("signed_out.html"), "BYE {{ issuer_id }}").unwrap();
    let app = app(&format!(
        "[server]\ntemplates_dir = \"{}\"\n{STRICT}",
        dir.display()
    ));
    let (s, _, b) = send(&app, get("/auth0/endsession")).await;
    assert_eq!((s.as_u16(), b.as_str()), (200, "BYE auth0"));
}

/// The halo base of every page: plain CSS, small, both themes, no network.
#[tokio::test]
async fn halo_css_is_served_small_and_offline() {
    let (s, h, css) = send(&app(AUTH0), get("/_mock/static/halo.css")).await;
    assert_eq!(s, 200);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/css"));
    assert!(css.contains("@media (prefers-color-scheme: dark)"));
    assert!(css.len() < 24 * 1024, "{} bytes", css.len());
    for bad in ["http://", "https://", "url(//", "@import"] {
        assert!(!css.contains(bad), "{bad}");
    }
}

/// The Tailwind stylesheet of the old built-in pages stays served, so a custom template
/// that links it keeps its style.
#[tokio::test]
async fn fauxidc_css_is_served() {
    let (s, h, b) = send(&app(AUTH0), get("/_mock/static/fauxidc.css")).await;
    assert_eq!(s, 200);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/css"));
    assert!(
        b.contains("prefers-color-scheme: dark") || b.contains("prefers-color-scheme:dark"),
        "dark theme rule"
    );
}

#[test]
fn fauxidc_css_is_under_60_kb_and_has_no_external_urls() {
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/fauxidc.css"
    ))
    .unwrap();
    assert!(css.len() < 60 * 1024, "{} bytes", css.len());
    for bad in ["http://", "https://", "url(//"] {
        assert!(!css.contains(bad), "{bad}");
    }
}

#[tokio::test]
async fn login_form_keeps_its_field_names() {
    let (_, _, b) = send(&app(STRICT), get(&authorize_url(&[]))).await;
    for needle in [
        "<h1",
        ">Sign in</h1>",
        "name=\"user\"",
        "value=\"__custom__\"",
        "name=\"custom_sub\"",
        "name=\"custom_claims\"",
        "name=\"override_claims\"",
        "name=\"remember\"",
        "value=\"1\"",
        "id=\"custom-user\"",
        "/_mock/static/halo.css",
    ] {
        assert!(b.contains(needle), "{needle}");
    }
    assert!(!b.contains("login.css"));
}

/// The opening tag of the element with `id`.
fn tag_with_id<'a>(html: &'a str, id: &str) -> &'a str {
    let at = html.find(&format!("id=\"{id}\"")).expect("element present");
    let start = html[..at].rfind('<').unwrap();
    let end = at + html[at..].find('>').unwrap();
    &html[start..=end]
}

#[tokio::test]
async fn custom_fields_are_not_hidden_in_the_html() {
    // Without JS nothing hides them: the served HTML has no `hidden` attribute on #custom-user,
    // and no CSS rule hides it by default.
    let (_, _, b) = send(&app(STRICT), get(&authorize_url(&[]))).await;
    let tag = tag_with_id(&b, "custom-user");
    assert!(!tag.contains("hidden"), "{tag}");
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/halo.css"
    ))
    .unwrap();
    assert!(!css.contains("#custom-user"));
    // The form view posts `user=__custom__` from a hidden input; the User list is hidden and
    // disabled, so only one `user` value posts. The switch needs the page script.
    assert!(b.contains("<input type=\"hidden\" name=\"user\" value=\"__custom__\">"));
    assert!(tag_with_id(&b, "f-user").contains(" disabled"));
    assert!(b.contains("class=\"switch-row switch-tile js-only\""));
    assert!(css.contains("html:not(.js) .js-only { display: none; }"));
}

#[tokio::test]
async fn legacy_login_css_is_still_served() {
    assert_eq!(
        send(&app(AUTH0), get("/_mock/static/login.css")).await.0,
        200
    );
}

fn template_files() -> Vec<(String, String)> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/templates");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        out.push((
            path.display().to_string(),
            std::fs::read_to_string(&path).unwrap(),
        ));
    }
    assert_eq!(out.len(), 6);
    out
}

#[test]
fn templates_have_no_external_urls() {
    for (name, text) in template_files() {
        for bad in ["http://", "https://", "src=\"//", "href=\"//"] {
            assert!(!text.contains(bad), "{name}: {bad}");
        }
    }
}

#[test]
fn templates_link_the_halo_css() {
    for (name, text) in template_files() {
        // Every page links the halo base; the dashboard adds its shell (the halo design).
        assert!(text.contains("{{ static_base|href }}/halo.css"), "{name}");
        assert_eq!(
            text.contains("{{ static_base|href }}/dashboard.css"),
            name.ends_with("dashboard.html"),
            "{name}"
        );
        assert!(!text.contains("fauxidc.css"), "{name}");
        assert!(!text.contains("login.css"), "{name}");
    }
}

#[test]
fn halo_css_has_the_used_components() {
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/halo.css"
    ))
    .unwrap();
    for class in [
        ".card",
        ".btn",
        ".select",
        ".input",
        ".textarea",
        ".checkbox",
        ".alert",
        ".label",
        ".table-wrap",
        ".details",
        ".input-error",
        ".select-error",
        ".textarea-error",
    ] {
        assert!(css.contains(class), "{class}");
    }
}

#[test]
fn debugger_code_blocks_wrap() {
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/halo.css"
    ))
    .unwrap();
    assert!(css.contains("white-space: pre-wrap"), "wrap rule");
    assert!(css.contains("overflow-wrap: anywhere"), "break rule");
}

#[test]
fn templates_doc_names_the_stylesheet() {
    let doc =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/templates.md")).unwrap();
    assert!(doc.contains("/_mock/static/halo.css"));
    // The old Tailwind file is still named, for old custom templates.
    assert!(doc.contains("/_mock/static/fauxidc.css"));
}

#[tokio::test]
async fn error_page_wraps_a_long_message() {
    let long = format!("http://x/{}", "a".repeat(600));
    let (s, _, b) = send(
        &app(STRICT),
        get(&format!(
            "/auth0/authorize?client_id=example-app&redirect_uri={long}&response_type=code"
        )),
    )
    .await;
    assert_eq!(s, 400);
    assert!(
        b.contains("<span class=\"wrap\">redirect_uri not registered"),
        "{b}"
    );
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/halo.css"
    ))
    .unwrap();
    assert!(css.contains(".wrap { min-width: 0; overflow-wrap: anywhere; }"));
}

/// The opening tags in `html` that carry `class` (an error class).
fn tags_with<'a>(html: &'a str, class: &str) -> Vec<&'a str> {
    html.match_indices(class)
        .map(|(at, _)| {
            let start = html[..at].rfind('<').unwrap();
            let end = at + html[at..].find('>').unwrap();
            &html[start..=end]
        })
        .collect()
}

/// Posts the login form with `extra` to an app from `toml`, asserts 400, returns the body.
async fn login_error(toml: &str, extra: &[(&str, &str)]) -> String {
    let (s, _, b) = send(
        &app(toml),
        post_form("/auth0/authorize", &login_fields(extra), &[]),
    )
    .await;
    assert_eq!(s, 400, "{b}");
    b
}

/// A config, the extra login fields, and the id of the field that must be marked.
type Case<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);

#[tokio::test]
async fn login_error_marks_only_the_failed_field() {
    const TEMPLATE: &str =
        "[issuer.auth0.custom_user.claims]\nemail = \"{username}@example.test\"\n";
    let with_template = format!("{STRICT}{TEMPLATE}");
    let cases: [Case<'_>; 5] = [
        (STRICT, &[("user", "__custom__")], "f-custom-sub"),
        (
            STRICT,
            &[
                ("user", "__custom__"),
                ("custom_sub", "c"),
                ("custom_claims", "[1]"),
            ],
            "f-custom-claims",
        ),
        (STRICT, &[("override_claims", "{x")], "f-override"),
        (&with_template, &[("user", "__custom__")], "f-username"),
        (STRICT, &[("user", "mallory")], "f-user"),
    ];
    for (toml, extra, id) in cases {
        let b = login_error(toml, extra).await;
        let invalid = tags_with(&b, "aria-invalid=\"true\"");
        assert_eq!(invalid.len(), 1, "{id}: {invalid:?}");
        assert!(
            invalid[0].contains(&format!("id=\"{id}\"")),
            "{id}: {invalid:?}"
        );
        let error_class = tags_with(&b, "-error");
        assert!(
            error_class
                .iter()
                .filter(|t| !t.contains("alert-error"))
                .all(|t| t.contains(&format!("id=\"{id}\""))),
            "{id}: {error_class:?}"
        );
    }
}

#[tokio::test]
async fn login_page_without_error_marks_no_field() {
    let (_, _, b) = send(&app(STRICT), get(&authorize_url(&[]))).await;
    for bad in [
        "input-error",
        "textarea-error",
        "select-error",
        "aria-invalid",
    ] {
        assert!(!b.contains(bad), "{bad}");
    }
}

#[tokio::test]
async fn context_version_is_3() {
    let dir = tmp_dir();
    std::fs::write(
        dir.join("login.html"),
        "v{{ context_version }} {{ custom_label }} {{ custom_username }} [{{ username }}] {{ error_field }} {{ show_user_list }} {{ user_list_saved }} {{ view_cookie }} {{ view_cookie_path }}",
    )
    .unwrap();
    std::fs::write(dir.join("error.html"), "v{{ context_version }}").unwrap();
    let toml = format!("[server]\ntemplates_dir = \"{}\"\n{STRICT}", dir.display());
    let app = app(&toml);
    let (_, _, b) = send(&app, get(&authorize_url(&[]))).await;
    assert_eq!(
        b,
        "v3 Custom… False [] None False False fauxidc_login_view_auth0 &#x2f;auth0"
    );
    let (_, _, b) = send(
        &app,
        post_form(
            "/auth0/authorize",
            &login_fields(&[("override_claims", "{x")]),
            &[],
        ),
    )
    .await;
    assert_eq!(
        b,
        "v3 Custom… False [] override_claims True False fauxidc_login_view_auth0 &#x2f;auth0"
    );
    let (_, _, b) = send(
        &app,
        get("/auth0/authorize?client_id=nope&redirect_uri=http://x/cb&response_type=code"),
    )
    .await;
    assert_eq!(b, "v3");
}

#[tokio::test]
async fn context_has_the_username_fields() {
    let dir = tmp_dir();
    std::fs::write(
        dir.join("login.html"),
        "{{ custom_label }} {{ custom_username }} [{{ username }}] {{ error_field }}",
    )
    .unwrap();
    let toml = format!(
        "[server]\ntemplates_dir = \"{}\"\n{STRICT}[issuer.auth0.custom_user]\nlabel = \"Other…\"\n",
        dir.display()
    );
    let (_, _, b) = send(
        &app(&toml),
        post_form(
            "/auth0/authorize",
            &login_fields(&[("user", "__custom__"), ("username", " ")]),
            &[],
        ),
    )
    .await;
    assert_eq!(b, "Other… True [ ] username");
}
