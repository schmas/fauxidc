mod common;
use common::*;

use std::sync::Arc;

use fauxidc::config::{CliOverrides, LoadInputs, load};
use fauxidc::reload::{ConfigWriter, ReloadHandle, live_router};
use fauxidc::state::AppState;

const FILE: &str = "# Clients for the tests.\n";

/// The live app from a config file with `text` after a comment, with the Test API writer.
fn file_app_with(text: &str, env: &[(&str, &str)]) -> (Router, ReloadHandle, PathBuf) {
    let file = tmp_dir().join("fauxidc.toml");
    std::fs::write(&file, format!("{FILE}{text}")).unwrap();
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

fn file_app(env: &[(&str, &str)]) -> (Router, ReloadHandle, PathBuf) {
    file_app_with(STRICT, env)
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

/// `POST /auth0/token` with `grant_type=client_credentials` and Basic auth.
fn client_credentials(id: &str, secret: &str) -> Request<Body> {
    post_form(
        "/auth0/token",
        &[("grant_type", "client_credentials")],
        &[("authorization", &basic(id, secret))],
    )
}

#[tokio::test]
async fn list_and_get_show_the_running_clients_with_masked_secrets() {
    let (app, _, _) = file_app(&[]);
    let (s, _, all) = call(&app, "GET", "/_mock/clients", None).await;
    assert_eq!(s, 200);
    let keys: Vec<&str> = all
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["key"].as_str().unwrap())
        .collect();
    assert_eq!(keys, ["example_app", "spa"]);
    assert!(!all.to_string().contains("\"local\""), "{all}");

    let (s, _, app_client) = call(&app, "GET", "/_mock/clients/example_app", None).await;
    assert_eq!(s, 200);
    assert_eq!(app_client["client_id"], "example-app");
    assert_eq!(app_client["client_secret"], "***");
    assert_eq!(app_client["lenient"], false);
    let (_, _, spa) = call(&app, "GET", "/_mock/clients/spa", None).await;
    assert_eq!(spa["client_id"], "spa", "client_id defaults to the key");
    assert_eq!(spa["client_secret"], Value::Null);

    let (s, _, e) = call(&app, "GET", "/_mock/clients/example-app", None).await;
    assert_eq!(
        (s, e["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("not_found")),
        "the path uses the key, not the client_id"
    );
}

#[tokio::test]
async fn create_writes_the_file_and_applies_at_once() {
    let (app, _, file) = file_app(&[]);
    let body = json!({
        "key": "backend",
        "client_secret": "s3",
        "grant_types": ["client_credentials"],
        "scopes": ["api"],
        "audience": "https://api.example.test"
    });
    let (s, _, _) = send(&app, client_credentials("backend", "s3")).await;
    assert_eq!(s, 401, "backend is not known yet");

    let (s, h, backend) = call(&app, "POST", "/_mock/clients", Some(&body)).await;
    assert_eq!(s, 201, "{backend}");
    assert_eq!(h["location"], "/_mock/clients/backend");
    assert_eq!(backend["client_secret"], "***");
    assert_eq!(backend["grant_types"], json!(["client_credentials"]));

    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.starts_with(FILE), "{text}");
    assert!(
        text.contains(
            "[client.spa]\nredirect_uris = [\"http://localhost:5173/cb\"]\n\n[client.backend]\nclient_secret = \"s3\"\ngrant_types = [\"client_credentials\"]\n\
             scopes = [\"api\"]\naudience = \"https://api.example.test\"\n"
        ),
        "{text}"
    );

    // No wait for the file poller: the next request sees the new Client.
    let (s, _, b) = send(&app, client_credentials("backend", "s3")).await;
    assert_eq!(s, 200, "{b}");
    let claims = claims_of(json(&b)["access_token"].as_str().unwrap());
    assert_eq!(claims["aud"], "https://api.example.test");

    let (s, _, e) = call(&app, "POST", "/_mock/clients", Some(&body)).await;
    assert_eq!(s, 409);
    assert_eq!(e["error"], "conflict");
}

#[tokio::test]
async fn replace_merge_and_remove() {
    let (app, _, file) = file_app(&[]);
    let (s, _, spa) = call(
        &app,
        "PUT",
        "/_mock/clients/spa",
        Some(&json!({"redirect_uris": ["http://localhost:5174/cb"]})),
    )
    .await;
    assert_eq!(s, 200, "{spa}");
    assert_eq!(spa["redirect_uris"], json!(["http://localhost:5174/cb"]));

    let (s, _, client) = call(
        &app,
        "PATCH",
        "/_mock/clients/example_app",
        Some(&json!({"redirect_uris": ["http://localhost:3001/cb"]})),
    )
    .await;
    assert_eq!(s, 200, "{client}");
    assert_eq!(client["redirect_uris"], json!(["http://localhost:3001/cb"]));
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(
        text.contains("client_secret = \"local\""),
        "PATCH keeps the secret: {text}"
    );

    let (s, _, _) = call(&app, "DELETE", "/_mock/clients/spa", None).await;
    assert_eq!(s, 204);
    assert!(
        !std::fs::read_to_string(&file)
            .unwrap()
            .contains("[client.spa]")
    );
    let url = authorize_url(&[
        ("client_id", "spa"),
        ("redirect_uri", "http://localhost:5174/cb"),
    ]);
    let (s, _, page) = send(&app, get(&url)).await;
    assert_eq!(s, 400, "spa is gone from the running config: {page}");

    for (method, body) in [
        ("PUT", Some(json!({}))),
        ("PATCH", Some(json!({}))),
        ("DELETE", None),
    ] {
        let (s, _, e) = call(&app, method, "/_mock/clients/zed", body.as_ref()).await;
        assert_eq!(s, 404, "{method} {e}");
    }
}

#[tokio::test]
async fn bad_input_is_refused_and_the_file_does_not_change() {
    let (app, _, file) = file_app(&[]);
    let before = std::fs::read_to_string(&file).unwrap();
    for (method, uri, body) in [
        ("POST", "/_mock/clients", json!({"key": "svc", "nope": 1})),
        ("POST", "/_mock/clients", json!({"key": "Bad-Key"})),
        ("POST", "/_mock/clients", json!({"client_secret": "s"})),
        (
            "POST",
            "/_mock/clients",
            json!({"key": "svc", "id_claims": {"x": null}}),
        ),
        (
            "POST",
            "/_mock/clients",
            json!({"key": "svc", "issuer": "nope"}),
        ),
        ("PUT", "/_mock/clients/spa", json!({"grant_types": 1})),
        ("PATCH", "/_mock/clients/spa", json!({"nope": 1})),
    ] {
        let (s, _, e) = call(&app, method, uri, Some(&body)).await;
        assert_eq!(s, 400, "{method} {body}: {e}");
        assert_eq!(e["error"], "invalid_request");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
}

#[tokio::test]
async fn a_client_set_by_env_cannot_change() {
    let (app, _, file) = file_app(&[("FAUXIDC__CLIENT__SPA__REQUIRE_PKCE", "true")]);
    let before = std::fs::read_to_string(&file).unwrap();
    let (s, _, e) = call(&app, "DELETE", "/_mock/clients/spa", None).await;
    assert_eq!(s, 409);
    let message = e["error_description"].as_str().unwrap();
    assert!(
        message.contains("env FAUXIDC__CLIENT__SPA__REQUIRE_PKCE"),
        "{message}"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    // Other Clients still change.
    let (s, _, _) = call(&app, "DELETE", "/_mock/clients/example_app", None).await;
    assert_eq!(s, 204);
}

#[tokio::test]
async fn cross_origin_writes_are_refused() {
    let (app, _, file) = file_app(&[]);
    let before = std::fs::read_to_string(&file).unwrap();
    let req = request(
        "DELETE",
        "/_mock/clients/spa",
        None,
        &[("origin", "http://evil.example.test")],
    );
    let (s, _, b) = send(&app, req).await;
    assert_eq!(s, 403, "{b}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    let req = request(
        "DELETE",
        "/_mock/clients/spa",
        None,
        &[("origin", "http://localhost:9000")],
    );
    assert_eq!(send(&app, req).await.0, 204);
}

#[tokio::test]
async fn without_a_config_file_writes_answer_409() {
    let app = app(STRICT);
    let (s, _, e) = call(&app, "POST", "/_mock/clients", Some(&json!({"key": "svc"}))).await;
    assert_eq!(s, 409);
    assert!(
        e["error_description"]
            .as_str()
            .unwrap()
            .contains("no config file is loaded"),
        "{e}"
    );
    let (s, _, _) = call(&app, "GET", "/_mock/clients/spa", None).await;
    assert_eq!(s, 200, "reads work without a file");
}

#[tokio::test]
async fn lenient_registered_clients_are_listed_and_read_only() {
    let lenient = "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\nlenient = true\n\n\
                   [client.spa]\nredirect_uris = [\"http://localhost:5173/cb\"]\n";
    let (app, _, file) = file_app_with(lenient, &[]);
    let url = authorize_url(&[
        ("client_id", "new_app"),
        ("redirect_uri", "http://localhost:4000/cb"),
    ]);
    let (s, _, page) = send(&app, get(&url)).await;
    assert_eq!(s, 200, "Lenient mode registers new_app: {page}");

    let (_, _, all) = call(&app, "GET", "/_mock/clients", None).await;
    assert_eq!(all[0]["key"], "spa");
    assert_eq!(all[0]["lenient"], false);
    assert_eq!(all[1]["key"], "new_app");
    assert_eq!(all[1]["lenient"], true);
    assert_eq!(all[1]["issuer"], "auth0");
    assert_eq!(all[1]["redirect_uris"], json!(["http://localhost:4000/cb"]));
    let (s, _, one) = call(&app, "GET", "/_mock/clients/new_app", None).await;
    assert_eq!((s, &one["lenient"]), (StatusCode::OK, &json!(true)));

    let before = std::fs::read_to_string(&file).unwrap();
    for (method, body) in [
        ("PUT", Some(json!({}))),
        ("PATCH", Some(json!({}))),
        ("DELETE", None),
    ] {
        let (s, _, e) = call(&app, method, "/_mock/clients/new_app", body.as_ref()).await;
        assert_eq!(s, 409, "{method} {e}");
        assert!(
            e["error_description"]
                .as_str()
                .unwrap()
                .contains("Lenient-registered"),
            "{e}"
        );
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), before);

    // A POST with the same key adds it to the config file; the configured Client wins.
    let body = json!({"key": "new_app", "redirect_uris": ["http://localhost:4000/cb"]});
    let (s, _, created) = call(&app, "POST", "/_mock/clients", Some(&body)).await;
    assert_eq!(s, 201, "{created}");
    assert_eq!(created["lenient"], false);
    let (_, _, one) = call(&app, "GET", "/_mock/clients/new_app", None).await;
    assert_eq!(one["lenient"], false);
    let (s, _, _) = call(&app, "DELETE", "/_mock/clients/new_app", None).await;
    assert_eq!(s, 204);
}
