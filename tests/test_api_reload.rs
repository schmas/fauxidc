//! `POST /_mock/reload`: reloads the config files at once and returns the result.

mod common;
use common::*;

use std::sync::Arc;

use fauxidc::config::{CliOverrides, LoadInputs, load};
use fauxidc::reload::{ConfigWriter, live_router};
use fauxidc::state::AppState;

/// The live app with the Test API writer. `file` is the config file text, or `None` for a
/// directory without a config file (Zero config).
fn app_with_inputs(file: Option<&str>) -> (Router, PathBuf) {
    let dir = tmp_dir();
    let path = dir.join("fauxidc.toml");
    let mut config_files = Vec::new();
    if let Some(text) = file {
        std::fs::write(&path, text).unwrap();
        config_files.push(path.clone());
    }
    let inputs = LoadInputs {
        config_files,
        env: Vec::new(),
        flags: CliOverrides::default(),
        cwd: dir,
    };
    let config = load(&inputs).unwrap().config;
    let state = Arc::new(AppState::new(config, KeyHandle::ready(KEY.clone()), true).unwrap());
    let writer = state.config_writer.clone();
    let (app, handle) = live_router(state);
    assert!(
        writer
            .set(ConfigWriter::new(inputs, handle.downgrade()))
            .is_ok()
    );
    (app, path)
}

fn reload_request(headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/_mock/reload")
        .header("host", "localhost:9000");
    for (name, value) in headers {
        b = b.header(*name, *value);
    }
    b.body(Body::empty()).unwrap()
}

async fn reload(app: &Router) -> (StatusCode, Value) {
    let (s, h, b) = send(app, reload_request(&[])).await;
    assert_eq!(h["cache-control"], "no-store");
    (s, json(&b))
}

const CAROL: &str =
    "\n[user.carol]\nlabel = \"Carol\"\nclaims = { email = \"carol@example.com\" }\n";

#[tokio::test]
async fn a_changed_file_applies_at_once() {
    let (app, file) = app_with_inputs(Some(STRICT));
    std::fs::write(&file, format!("{STRICT}{CAROL}")).unwrap();
    let (s, body) = reload(&app).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body, json!({"changed": true, "warnings": []}));
    // No wait for the file poller: the next request sees the new User.
    let t = test_token(&app, "auth0", json!({"user": "carol"})).await;
    let claims = claims_of(t["id_token"].as_str().unwrap());
    assert_eq!(claims["email"], "carol@example.com");
}

#[tokio::test]
async fn an_unchanged_file_reports_no_change() {
    let (app, _) = app_with_inputs(Some(STRICT));
    let (s, body) = reload(&app).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body, json!({"changed": false, "warnings": []}));
}

#[tokio::test]
async fn a_restart_only_change_returns_its_warning() {
    let (app, file) = app_with_inputs(Some(STRICT));
    let next = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\nsigning_alg = \"ES256\"\n",
    );
    std::fs::write(&file, next).unwrap();
    let (s, body) = reload(&app).await;
    assert_eq!(s, 200, "{body}");
    assert_eq!(body["changed"], true);
    let warnings: Vec<&str> = body["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect();
    assert!(
        warnings.contains(&"issuer.auth0.signing_alg changed; it needs a restart"),
        "{body}"
    );
}

#[tokio::test]
async fn an_invalid_file_returns_the_errors_and_keeps_the_old_config() {
    let (app, file) = app_with_inputs(Some(STRICT));
    std::fs::write(
        &file,
        format!("{STRICT}{CAROL}\n[issuer.extra]\nissuer_url = \"not a url\"\n"),
    )
    .unwrap();
    let (s, body) = reload(&app).await;
    assert_eq!(s, 422, "{body}");
    assert_eq!(body["error"], "invalid_config");
    let errors = body["errors"].as_array().unwrap();
    assert!(!errors.is_empty(), "{body}");
    assert!(
        errors
            .iter()
            .any(|e| e.as_str().unwrap().contains("issuer_url")),
        "{body}"
    );
    // The old config stays: carol is unknown, alice still works.
    let (s, _, b) = send(
        &app,
        post_json("/_mock/auth0/token", &json!({"user": "carol"})),
    )
    .await;
    assert_eq!(s, 400, "{b}");
    assert!(test_token(&app, "auth0", json!({"user": "alice"})).await["id_token"].is_string());
}

#[tokio::test]
async fn a_toml_syntax_error_returns_422() {
    let (app, file) = app_with_inputs(Some(STRICT));
    std::fs::write(&file, "[issuer.auth0\n").unwrap();
    let (s, body) = reload(&app).await;
    assert_eq!(s, 422, "{body}");
    let errors = body["errors"].as_array().unwrap();
    assert!(
        errors[0]
            .as_str()
            .unwrap()
            .contains(&file.display().to_string()),
        "{body}"
    );
}

#[tokio::test]
async fn without_a_config_file_it_answers_409() {
    let (app, _) = app_with_inputs(None);
    let (s, body) = reload(&app).await;
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "conflict");
}

#[tokio::test]
async fn without_load_inputs_it_answers_409() {
    let (app, _) = live_app(STRICT);
    let (s, body) = reload(&app).await;
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"], "conflict");
}

#[tokio::test]
async fn a_cross_origin_request_is_refused() {
    let (app, file) = app_with_inputs(Some(STRICT));
    std::fs::write(&file, format!("{STRICT}{CAROL}")).unwrap();
    let (s, _, b) = send(
        &app,
        reload_request(&[("origin", "http://evil.example.test")]),
    )
    .await;
    assert_eq!(s, 403, "{b}");
    assert_eq!(json(&b)["error"], "access_denied");
    // Nothing applied.
    let (s, _, _) = send(
        &app,
        post_json("/_mock/auth0/token", &json!({"user": "carol"})),
    )
    .await;
    assert_eq!(s, 400);
    // The server's own origin is allowed.
    let (s, _, b) = send(&app, reload_request(&[("origin", "http://localhost:9000")])).await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn reload_works_on_a_started_server() {
    let dir = tmp_dir();
    let file = dir.join("fauxidc.toml");
    let base = format!("[server]\nbind = \"127.0.0.1\"\nport = 0\n\n{STRICT}");
    std::fs::write(&file, &base).unwrap();
    let inputs = LoadInputs {
        config_files: vec![file.clone()],
        env: Vec::new(),
        flags: CliOverrides::default(),
        cwd: dir,
    };
    let config = load(&inputs).unwrap().config;
    let mut opts = fauxidc::StartOptions::with_key_pem(KEY.to_pem().to_string());
    opts.load_inputs = Some(inputs);
    let srv = fauxidc::Server::start_with(config, opts).await.unwrap();
    std::fs::write(&file, format!("{base}{CAROL}")).unwrap();
    let res = reqwest::Client::new()
        .post(format!("http://{}/_mock/reload", srv.local_addr()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["changed"], true);
    let users = &srv.reload_handle().current().config.user;
    assert!(users.contains_key("carol"));
    srv.shutdown().await.unwrap();
}
