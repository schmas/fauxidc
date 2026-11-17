//! `GET` and `PUT /_mock/{issuer_id}/login`: the `show_user_list` setting of an Issuer.

mod common;
use common::*;

use std::sync::Arc;

use fauxidc::config::{CliOverrides, LoadInputs, load};
use fauxidc::reload::{ConfigWriter, ReloadHandle, live_router};
use fauxidc::state::AppState;

const FILE: &str = "# Login setting tests.\n";

/// The live app from a config file with `STRICT` and a comment, with the Test API writer.
fn file_app(env: &[(&str, &str)]) -> (Router, ReloadHandle, PathBuf) {
    let file = tmp_dir().join("fauxidc.toml");
    std::fs::write(&file, format!("{FILE}{STRICT}")).unwrap();
    let inputs = LoadInputs {
        config_files: vec![file.clone()],
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        flags: CliOverrides::default(),
        cwd: tmp_dir(),
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
    (app, handle, file)
}

/// The app of a Zero config (Issuer `default`), without a config file or writer.
fn zero_app() -> Router {
    let inputs = LoadInputs {
        config_files: vec![],
        env: vec![],
        flags: CliOverrides::default(),
        cwd: tmp_dir(),
    };
    app_from_config(load(&inputs).unwrap().config)
}

fn request(method: &str, uri: &str, body: Option<&str>, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:9000");
    for (name, value) in headers {
        b = b.header(*name, *value);
    }
    match body {
        Some(body) => b
            .header("content-type", "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let (s, _, b) = send(app, request(method, uri, body, headers)).await;
    let v = if b.is_empty() { Value::Null } else { json(&b) };
    (s, v)
}

async fn put(app: &Router, issuer: &str, body: &str) -> (StatusCode, Value) {
    call(
        app,
        "PUT",
        &format!("/_mock/{issuer}/login"),
        Some(body),
        &[],
    )
    .await
}

async fn read(app: &Router, issuer: &str) -> (StatusCode, Value) {
    call(app, "GET", &format!("/_mock/{issuer}/login"), None, &[]).await
}

#[tokio::test]
async fn get_is_default_false() {
    let app = zero_app();
    let (s, v) = read(&app, "default").await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v,
        json!({"show_user_list": false, "source": "default", "origin": null})
    );
}

#[tokio::test]
async fn put_without_file_stays_in_memory() {
    let app = zero_app();
    let (s, v) = put(&app, "default", r#"{"show_user_list": true}"#).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        v,
        json!({"show_user_list": true, "source": "memory", "origin": null})
    );
    let (_, v) = read(&app, "default").await;
    assert_eq!(
        v,
        json!({"show_user_list": true, "source": "memory", "origin": null})
    );
}

#[tokio::test]
async fn reset_state_clears_the_memory_value() {
    let app = app(&format!(
        "{AUTH0}[issuer.other]\nissuer_url = \"http://localhost:9000/other/\"\n"
    ));
    let (s, v) = put(&app, "auth0", r#"{"show_user_list": true}"#).await;
    assert_eq!(s, 200, "{v}");
    let (s, _) = call(&app, "DELETE", "/_mock/state?issuer=other", None, &[]).await;
    assert!(s.is_success(), "{s}");
    let (_, v) = read(&app, "auth0").await;
    assert_eq!(v["show_user_list"], true);
    let (s, _) = call(&app, "DELETE", "/_mock/state", None, &[]).await;
    assert!(s.is_success(), "{s}");
    let (_, v) = read(&app, "auth0").await;
    assert_eq!(v["show_user_list"], false);
    assert_eq!(v["source"], "default");
}

#[tokio::test]
async fn put_with_file_writes_the_key() {
    let (app, _, file) = file_app(&[]);
    let (s, v) = put(&app, "auth0", r#"{"show_user_list": true}"#).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["show_user_list"], true);
    assert_eq!(v["source"], "file");
    let origin = v["origin"].as_str().unwrap();
    assert!(origin.contains("fauxidc.toml"), "{origin}");
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains("show_user_list = true"), "{text}");
    assert!(text.starts_with(FILE), "{text}");
    let (_, v) = read(&app, "auth0").await;
    assert_eq!(v["show_user_list"], true);
    assert_eq!(v["source"], "file");
}

#[tokio::test]
async fn put_refuses_env_source() {
    let (app, _, _) = file_app(&[("FAUXIDC__ISSUER__AUTH0__SHOW_USER_LIST", "false")]);
    let (s, v) = put(&app, "auth0", r#"{"show_user_list": true}"#).await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["error"], "conflict");
    let (_, v) = read(&app, "auth0").await;
    assert_eq!(v["source"], "env");
}

#[tokio::test]
async fn put_checks_origin_issuer_and_body() {
    let app = zero_app();
    let (s, v) = call(
        &app,
        "PUT",
        "/_mock/default/login",
        Some(r#"{"show_user_list": true}"#),
        &[("origin", "http://evil.example.test")],
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("access_denied"))
    );
    let (s, _) = put(&app, "nope", r#"{"show_user_list": true}"#).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = put(&app, "default", r#"{"show_user_list": "yes"}"#).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
    let (s, _) = put(&app, "default", r#"{"show_user_list": true, "x": 1}"#).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}
