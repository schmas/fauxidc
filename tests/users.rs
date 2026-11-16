mod common;
use common::*;

use std::sync::Arc;

use fauxidc::config::{CliOverrides, LoadInputs, load};
use fauxidc::reload::{ConfigWriter, ReloadHandle, live_router};
use fauxidc::state::AppState;

const FILE: &str = "# Users for the tests.\n";

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

fn request(
    method: &str,
    uri: &str,
    body: Option<&Value>,
    headers: &[(&str, &str)],
) -> Request<Body> {
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
            .body(Body::from(body.to_string()))
            .unwrap(),
        None => b.body(Body::empty()).unwrap(),
    }
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<&Value>,
) -> (StatusCode, HeaderMap, Value) {
    let (s, h, b) = send(app, request(method, uri, body, &[])).await;
    let v = if b.is_empty() { Value::Null } else { json(&b) };
    (s, h, v)
}

#[tokio::test]
async fn list_and_get_show_the_running_users() {
    let (app, _, _) = file_app(&[]);
    let (s, _, all) = call(&app, "GET", "/_mock/users", None).await;
    assert_eq!(s, 200);
    let ids: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["alice", "bob"]);
    let (s, _, alice) = call(&app, "GET", "/_mock/users/alice", None).await;
    assert_eq!(s, 200);
    assert_eq!(alice["label"], "Alice Admin");
    assert_eq!(alice["claims"]["roles"], json!(["admin"]));
    assert_eq!(alice["issuer"], json!({}));
    let (s, _, e) = call(&app, "GET", "/_mock/users/zed", None).await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found"))
    );
}

#[tokio::test]
async fn create_writes_the_file_and_applies_at_once() {
    let (app, _, file) = file_app(&[]);
    let body = json!({
        "id": "carol",
        "label": "Carol",
        "claims": {"email": "carol@example.com"},
        "issuer": {"auth0": {"claims": {"org": "o-1"}}}
    });
    let (s, h, carol) = call(&app, "POST", "/_mock/users", Some(&body)).await;
    assert_eq!(s, 201, "{carol}");
    assert_eq!(h["location"], "/_mock/users/carol");
    assert_eq!(carol["claims"]["email"], "carol@example.com");

    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with(FILE), "{text}");
    assert!(text.contains("[user.carol]\nlabel = \"Carol\""), "{text}");

    // No wait for the file poller: the next request sees the new User.
    let t = test_token(&app, "auth0", json!({"user": "carol"})).await;
    let claims = claims_of(t["id_token"].as_str().unwrap());
    assert_eq!(claims["email"], "carol@example.com");
    assert_eq!(claims["org"], "o-1");
    let (_, _, page) = send(&app, get(&authorize_url(&[]))).await;
    assert!(page.contains("Carol"), "login page lists the new User");

    let (s, _, e) = call(&app, "POST", "/_mock/users", Some(&body)).await;
    assert_eq!(s, 409);
    assert_eq!(e["error"], "conflict");
}

#[tokio::test]
async fn replace_merge_and_remove() {
    let (app, _, file) = file_app(&[]);
    let (s, _, bob) = call(
        &app,
        "PUT",
        "/_mock/users/bob",
        Some(&json!({"label": "Bob", "claims": {"email": "b2@example.com"}})),
    )
    .await;
    assert_eq!(s, 200, "{bob}");
    assert_eq!(bob["claims"], json!({"email": "b2@example.com"}));

    let (s, _, alice) = call(
        &app,
        "PATCH",
        "/_mock/users/alice",
        Some(&json!({"claims": {"roles": null, "nickname": "al"}})),
    )
    .await;
    assert_eq!(s, 200, "{alice}");
    assert_eq!(alice["label"], "Alice Admin");
    assert!(alice["claims"].get("roles").is_none());
    assert_eq!(alice["claims"]["nickname"], "al");
    assert_eq!(alice["claims"]["email"], "alice@example.com");

    let (s, _, _) = call(&app, "DELETE", "/_mock/users/bob", None).await;
    assert_eq!(s, 204);
    assert!(
        !std::fs::read_to_string(&file)
            .unwrap()
            .contains("[user.bob]")
    );
    let (s, _, _) = send(
        &app,
        post_json("/_mock/auth0/token", &json!({"user": "bob"})),
    )
    .await;
    assert_eq!(s, 400, "bob is gone from the running config");

    for (method, body) in [
        ("PUT", Some(json!({"label": "Z"}))),
        ("PATCH", Some(json!({"label": "Z"}))),
        ("DELETE", None),
    ] {
        let (s, _, e) = call(&app, method, "/_mock/users/zed", body.as_ref()).await;
        assert_eq!(s, 404, "{method} {e}");
    }
}

#[tokio::test]
async fn bad_input_is_refused_and_the_file_does_not_change() {
    let (app, _, file) = file_app(&[]);
    let before = std::fs::read_to_string(&file).unwrap();
    for (method, uri, body) in [
        ("POST", "/_mock/users", json!({"id": "carol", "nope": 1})),
        ("POST", "/_mock/users", json!({"id": "Bad-Id"})),
        (
            "POST",
            "/_mock/users",
            json!({"id": "carol", "claims": {"x": null}}),
        ),
        ("PUT", "/_mock/users/alice", json!({"claims": 1})),
        ("PATCH", "/_mock/users/alice", json!({"nope": 1})),
    ] {
        let (s, _, e) = call(&app, method, uri, Some(&body)).await;
        assert_eq!(s, 400, "{method} {body}: {e}");
        assert_eq!(e["error"], "invalid_request");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
}

#[tokio::test]
async fn a_user_set_by_env_cannot_change() {
    let (app, _, file) = file_app(&[("FAUXIDC__USER__BOB__LABEL", "Bob from env")]);
    let before = std::fs::read_to_string(&file).unwrap();
    let (s, _, e) = call(&app, "DELETE", "/_mock/users/bob", None).await;
    assert_eq!(s, 409);
    let message = e["error_description"].as_str().unwrap();
    assert!(
        message.contains("env FAUXIDC__USER__BOB__LABEL"),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    // Other Users still change.
    let (s, _, _) = call(&app, "DELETE", "/_mock/users/alice", None).await;
    assert_eq!(s, 204);
}

#[tokio::test]
async fn cross_origin_writes_are_refused() {
    let (app, _, file) = file_app(&[]);
    let before = std::fs::read_to_string(&file).unwrap();
    let req = request(
        "DELETE",
        "/_mock/users/bob",
        None,
        &[("origin", "http://evil.example.test")],
    );
    let (s, _, b) = send(&app, req).await;
    assert_eq!(s, 403, "{b}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    let req = request(
        "DELETE",
        "/_mock/users/bob",
        None,
        &[("origin", "http://localhost:9000")],
    );
    assert_eq!(send(&app, req).await.0, 204);
}

#[tokio::test]
async fn without_a_config_file_writes_answer_409() {
    let app = app(STRICT);
    let (s, _, e) = call(&app, "POST", "/_mock/users", Some(&json!({"id": "carol"}))).await;
    assert_eq!(s, 409);
    assert!(
        e["error_description"]
            .as_str()
            .unwrap()
            .contains("no config file is loaded"),
        "{e}"
    );
    let (s, _, _) = call(&app, "GET", "/_mock/users/alice", None).await;
    assert_eq!(s, 200, "reads work without a file");
}
