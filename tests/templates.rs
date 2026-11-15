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
        "/_mock/static/fauxidc.css",
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
        "/assets/static/fauxidc.css"
    ))
    .unwrap();
    assert!(!css.contains("#custom-user"));
    // The custom option carries the data-custom hook.
    assert!(
        b.contains("value=\"__custom__\" data-custom"),
        "data-custom hook"
    );
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
    assert_eq!(out.len(), 4);
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
fn templates_link_only_fauxidc_css() {
    for (name, text) in template_files() {
        assert!(
            text.contains("{{ static_base|href }}/fauxidc.css"),
            "{name}"
        );
        assert!(!text.contains("login.css"), "{name}");
    }
}

#[test]
fn compiled_css_has_the_used_components() {
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/fauxidc.css"
    ))
    .unwrap();
    for class in [".card", ".btn", ".select", ".alert", ".collapse"] {
        assert!(css.contains(class), "{class}");
    }
}

#[test]
fn debugger_code_blocks_wrap() {
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/fauxidc.css"
    ))
    .unwrap();
    assert!(css.contains("white-space:pre-wrap"), "wrap rule");
    assert!(css.contains("overflow-wrap:anywhere"), "break rule");
}

#[test]
fn templates_doc_names_the_stylesheet() {
    let doc =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/templates.md")).unwrap();
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
        b.contains("<span class=\"min-w-0 wrap-anywhere\">redirect_uri not registered"),
        "{b}"
    );
    let css = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/static/fauxidc.css"
    ))
    .unwrap();
    assert!(css.contains(".min-w-0{min-width:0"));
}

#[tokio::test]
async fn login_error_marks_no_field() {
    let (s, _, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_fields(&[("user", "__custom__")]),
            &[],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert!(
        b.contains("<span class=\"min-w-0 wrap-anywhere\">Custom user needs a sub"),
        "{b}"
    );
    for bad in ["input-error", "textarea-error", "aria-invalid"] {
        assert!(!b.contains(bad), "{bad}");
    }
}
