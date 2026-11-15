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
