mod common;
use common::*;

use fauxidc::config::load_str;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use fauxidc::config::LoadInputs;
use fauxidc::reload::{ReloadError, watch_files};

#[tokio::test]
async fn reload_changes_routes_and_discovery() {
    let (app, handle) = live_app(STRICT);
    assert_eq!(
        send(&app, post_form("/auth0/oauth/token", &[], &[]))
            .await
            .0,
        404
    );
    let next = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\npaths = { token = \"/oauth/token\" }\n",
    );
    let warnings = handle.apply(load_str(&next).unwrap().config).unwrap();
    assert_eq!(warnings, Vec::<String>::new());
    let d = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        d["token_endpoint"],
        "http://localhost:9000/auth0/oauth/token"
    );
    assert_eq!(send(&app, post_form("/auth0/token", &[], &[])).await.0, 404);
}

#[tokio::test]
async fn code_and_session_survive_reload() {
    let (app, handle) = live_app(STRICT);
    let (s, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    assert_eq!(s, 302);
    let code = query_param(&location(&h), "code").unwrap();
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    handle
        .apply(
            load_str(&format!("{STRICT}\n[user.carol]\nlabel = \"Carol\"\n"))
                .unwrap()
                .config,
        )
        .unwrap();
    assert!(exchange_code_for(&app, &code).await["id_token"].is_string());
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
async fn session_for_removed_user_fails() {
    let (app, handle) = live_app(STRICT);
    let (_, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    let without_alice = STRICT.replace("[user.alice]", "[user.alice_old]");
    handle
        .apply(load_str(&without_alice).unwrap().config)
        .unwrap();
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
async fn refresh_token_survives_reload() {
    let (app, handle) = live_app(STRICT);
    let rt = token_response_for(&app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    handle.apply(load_str(STRICT).unwrap().config).unwrap();
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn failed_reload_keeps_old_config() {
    let (app, handle) = live_app(STRICT);
    let mut bad = load_str(STRICT).unwrap().config;
    bad.issuer.get_mut("auth0").unwrap().login_template = "/nonexistent/login.html".into();
    assert!(matches!(handle.apply(bad), Err(ReloadError::Templates(_))));
    assert_eq!(send(&app, get(&authorize_url(&[]))).await.0, 200);
}

#[tokio::test]
async fn invalid_config_is_rejected_by_apply() {
    let (app, handle) = live_app(STRICT);
    let mut bad = load_str(STRICT).unwrap().config;
    bad.issuer.get_mut("auth0").unwrap().issuer_url = "not a url".into();
    assert!(matches!(handle.apply(bad), Err(ReloadError::Config(_))));
    assert_eq!(send(&app, get(&authorize_url(&[]))).await.0, 200);
}

#[tokio::test]
async fn key_change_warns_and_keeps_keys() {
    let (app, handle) = live_app(STRICT);
    let before = json(&send(&app, get("/auth0/jwks")).await.2);
    let next = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\nsigning_alg = \"ES256\"\n",
    );
    let warnings = handle.apply(load_str(&next).unwrap().config).unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("issuer.auth0.signing_alg") && w.contains("needs a restart")),
        "{warnings:?}"
    );
    assert_eq!(json(&send(&app, get("/auth0/jwks")).await.2), before);
    // Discovery keeps the running algorithm too.
    let d = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(d["id_token_signing_alg_values_supported"], json!(["RS256"]));
}

#[tokio::test]
async fn new_issuer_gets_a_key_on_reload() {
    let (app, handle) = live_app(STRICT);
    handle
        .apply(
            load_str(&format!(
                "{STRICT}\n[issuer.es]\nissuer_url = \"http://localhost:9000/es\"\nsigning_alg = \"ES256\"\n"
            ))
            .unwrap()
            .config,
        )
        .unwrap();
    assert_eq!(
        json(&send(&app, get("/es/jwks")).await.2)["keys"][0]["alg"],
        "ES256"
    );
}

#[tokio::test]
async fn cors_origins_follow_reload() {
    let (app, handle) = live_app(STRICT);
    let preflight = || {
        Request::builder()
            .method("OPTIONS")
            .uri("/auth0/token")
            .header("host", "localhost:9000")
            .header("origin", "http://localhost:4200")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap()
    };
    let (_, h, _) = send(&app, preflight()).await;
    assert!(h.get("access-control-allow-origin").is_none());
    let next = STRICT.replace(
        "redirect_uris = [\"http://localhost:5173/cb\"]",
        "redirect_uris = [\"http://localhost:5173/cb\"]\nweb_origins = [\"http://localhost:4200\"]",
    );
    handle.apply(load_str(&next).unwrap().config).unwrap();
    let (_, h, _) = send(&app, preflight()).await;
    assert_eq!(h["access-control-allow-origin"], "http://localhost:4200");
}

struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A temp config file with `text`, its load inputs and the loaded config.
fn config_file(text: &str) -> (PathBuf, LoadInputs, fauxidc::config::Loaded) {
    let dir = tmp_dir();
    let file = dir.join("fauxidc.toml");
    std::fs::write(&file, text).unwrap();
    let inputs = LoadInputs {
        config_files: vec![file.clone()],
        env: vec![],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: dir,
    };
    let loaded = fauxidc::config::load(&inputs).unwrap();
    (file, inputs, loaded)
}

async fn test_api_status(app: &Router, user: &str) -> StatusCode {
    send(
        app,
        post_json("/_mock/auth0/token", &json!({ "user": user })),
    )
    .await
    .0
}

#[tokio::test]
async fn file_change_is_applied() {
    let (file, inputs, loaded) = config_file(STRICT);
    let (app, handle) = live_app_from(loaded.config.clone());
    let _w = watch_files(
        handle,
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
        SystemTime::now(),
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    std::fs::write(
        &file,
        format!("{STRICT}\n[user.carol]\nlabel = \"Carol\"\n"),
    )
    .unwrap();
    wait_until(Duration::from_secs(3), || async {
        test_api_status(&app, "carol").await == 200
    })
    .await;
}

#[tokio::test]
async fn invalid_file_keeps_old_config_and_logs() {
    let logs = Arc::new(Mutex::new(Vec::<u8>::new()));
    let w = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || CaptureWriter(w.clone()))
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let (file, inputs, loaded) = config_file(STRICT);
    let (app, handle) = live_app_from(loaded.config.clone());
    let _w = watch_files(
        handle,
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
        SystemTime::now(),
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    std::fs::write(&file, "[server]\nprot = 1").unwrap();
    let text = || String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
    wait_until(Duration::from_secs(3), || async {
        text().contains("config reload failed")
    })
    .await;
    assert!(text().contains("prot"), "{}", text());
    assert_eq!(test_api_status(&app, "alice").await, 200);
}

#[tokio::test]
async fn same_mtime_different_length_reloads() {
    let (file, inputs, loaded) = config_file(STRICT);
    let first_mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    let (app, handle) = live_app_from(loaded.config.clone());
    let _w = watch_files(
        handle,
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
        SystemTime::now(),
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    std::fs::write(
        &file,
        format!("{STRICT}\n[user.carol]\nlabel = \"Carol\"\n"),
    )
    .unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(first_mtime)
        .unwrap();
    wait_until(Duration::from_secs(3), || async {
        test_api_status(&app, "carol").await == 200
    })
    .await;
}

#[tokio::test]
async fn touched_file_logs_no_error() {
    let logs = Arc::new(Mutex::new(Vec::<u8>::new()));
    let w = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || CaptureWriter(w.clone()))
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let (file, inputs, loaded) = config_file(STRICT);
    let (app, handle) = live_app_from(loaded.config.clone());
    let _w = watch_files(
        handle,
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
        SystemTime::now(),
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(std::time::SystemTime::now() + Duration::from_secs(5))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let text = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
    assert!(!text.contains("ERROR"), "{text}");
    assert_eq!(test_api_status(&app, "alice").await, 200);
}

#[tokio::test]
async fn lenient_client_is_unknown_after_reload_to_strict() {
    let lenient = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let (app, handle) = live_app(&lenient);
    let url = authorize_url(&[
        ("client_id", "new-app"),
        ("redirect_uri", "http://localhost:1/cb"),
    ]);
    assert_eq!(send(&app, get(&url)).await.0, 200);
    handle.apply(load_str(STRICT).unwrap().config).unwrap();
    let (s, _, b) = send(&app, get(&url)).await;
    assert_eq!(s, 400, "{b}");
    assert!(b.contains("client_id"), "{b}");
    // Back to Lenient: the registration is still there.
    handle.apply(load_str(&lenient).unwrap().config).unwrap();
    assert_eq!(send(&app, get(&url)).await.0, 200);
}

/// Installs a log capture for this thread and returns the captured text reader.
fn capture_logs() -> (
    tracing::subscriber::DefaultGuard,
    impl Fn() -> String + Clone,
) {
    let logs = Arc::new(Mutex::new(Vec::<u8>::new()));
    let w = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || CaptureWriter(w.clone()))
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(sub);
    (guard, move || {
        String::from_utf8_lossy(&logs.lock().unwrap()).into_owned()
    })
}

#[tokio::test]
async fn half_written_file_is_not_applied() {
    // Poll every 200 ms. Write a valid prefix of the file that lacks [user.carol] and keep it
    // for less than one poll interval, then write the full file. At most one poll sees the
    // cut file, so the debounce never applies it: carol stays valid the whole time.
    // (STRICT already has bob, so the plan's [user.bob] is carol here.)
    let full = format!("{STRICT}\n[user.carol]\nlabel = \"Carol\"\n");
    let (file, inputs, loaded) = config_file(&full);
    let (app, handle) = live_app_from(loaded.config.clone());
    let _w = watch_files(
        handle.clone(),
        inputs,
        loaded.files.clone(),
        Duration::from_millis(200),
        SystemTime::now() - Duration::from_secs(5),
    );
    tokio::time::sleep(Duration::from_millis(450)).await;
    std::fs::write(&file, STRICT).unwrap(); // cut: no carol
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(100) {
        assert_eq!(
            test_api_status(&app, "carol").await,
            200,
            "cut file applied"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    std::fs::write(&file, format!("{full}\n# saved\n")).unwrap(); // full again, new length
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_millis(700) {
        assert_eq!(
            test_api_status(&app, "carol").await,
            200,
            "cut file applied"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn touch_after_restart_key_change_warns_once() {
    let (_guard, text) = capture_logs();
    let (file, inputs, loaded) = config_file(STRICT);
    let (_app, handle) = live_app_from(loaded.config.clone());
    let _w = watch_files(
        handle,
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
        SystemTime::now(),
    );
    tokio::time::sleep(Duration::from_millis(120)).await;
    let warning = "server.port changed; it needs a restart";
    std::fs::write(&file, format!("[server]\nport = 9100\n{STRICT}")).unwrap();
    wait_until(Duration::from_secs(3), || {
        let text = text.clone();
        async move { text().contains(warning) }
    })
    .await;
    let reloaded = text().matches("config reloaded").count();
    for offset in [5, 10] {
        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_modified(SystemTime::now() + Duration::from_secs(offset))
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let logs = text();
    assert_eq!(logs.matches(warning).count(), 1, "{logs}");
    assert_eq!(logs.matches("config reloaded").count(), reloaded, "{logs}");
}

#[tokio::test]
async fn change_before_first_poll_is_applied() {
    let loaded_at = SystemTime::now() - Duration::from_secs(1);
    let (file, inputs, loaded) = config_file(STRICT);
    let (app, handle) = live_app_from(loaded.config.clone());
    std::fs::write(
        &file,
        format!("{STRICT}\n[user.carol]\nlabel = \"Carol\"\n"),
    )
    .unwrap();
    let _w = watch_files(
        handle,
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
        loaded_at,
    );
    wait_until(Duration::from_secs(3), || async {
        test_api_status(&app, "carol").await == 200
    })
    .await;
}

#[tokio::test]
async fn failed_apply_is_retried_after_the_cause_is_fixed() {
    // The apply fails because the login template file is missing. After the file is created,
    // the same config applies on the next reload (for example SIGHUP).
    let (file, inputs, loaded) = config_file(STRICT);
    let (_app, handle) = live_app_from(loaded.config.clone());
    let template = file.with_file_name("login.html");
    let next = STRICT.replace(
        "[issuer.auth0]\n",
        &format!(
            "[issuer.auth0]\nlogin_template = \"{}\"\n",
            template.display()
        ),
    );
    std::fs::write(&file, next).unwrap();
    assert!(
        !fauxidc::reload::reload_from(&handle, &inputs),
        "the template is missing"
    );
    std::fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/assets/templates/login.html"),
        &template,
    )
    .unwrap();
    assert!(
        fauxidc::reload::reload_from(&handle, &inputs),
        "the same config applies once the template exists"
    );
    assert_eq!(
        handle.current().config.issuer["auth0"].login_template,
        template.display().to_string()
    );
}
