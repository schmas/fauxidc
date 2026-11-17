//! `GET /_mock/config`: the running config with the source of each value, secrets masked.

mod common;
use common::*;

use std::sync::Arc;

use fauxidc::config::{CliOverrides, LoadInputs, SigningAlg, load, render};
use fauxidc::reload::{ConfigWriter, ReloadHandle, live_router, reload_from};
use fauxidc::state::AppState;

static CLIENT_KEY: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::generate_for(SigningAlg::ES256).unwrap());

/// A file config with a confidential Client and a Client `jwks` that has a private member.
fn file_text() -> String {
    let mut jwk = CLIENT_KEY.jwk.clone();
    jwk["d"] = json!("private-key-d");
    let fields: Vec<String> = jwk
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect();
    format!(
        "{STRICT}\n[client.backend]\nclient_id = \"backend\"\nclient_secret = \"file-secret-1\"\n\
         grant_types = [\"client_credentials\"]\nscopes = [\"api\"]\njwks = {{ keys = [ {{ {} }} ] }}\n",
        fields.join(", ")
    )
}

fn inputs(file: &std::path::Path, env: &[(&str, &str)]) -> LoadInputs {
    LoadInputs {
        config_files: vec![file.to_path_buf()],
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        flags: CliOverrides::default(),
        cwd: tmp_dir(),
    }
}

/// The live app from `text` in a config file, with its load inputs.
fn file_app(text: &str, env: &[(&str, &str)]) -> (Router, ReloadHandle, LoadInputs) {
    let file = tmp_dir().join("fauxidc.toml");
    std::fs::write(&file, text).unwrap();
    let inputs = inputs(&file, env);
    let config = load(&inputs).unwrap().config;
    let state = Arc::new(AppState::new(config, KeyHandle::ready(KEY.clone()), true).unwrap());
    let writer = state.config_writer.clone();
    let (app, handle) = live_router(state);
    let set = writer.set(ConfigWriter::new(inputs.clone(), handle.downgrade()));
    assert!(set.is_ok());
    (app, handle, inputs)
}

async fn view(app: &Router, uri: &str) -> (StatusCode, HeaderMap, String) {
    send(app, get(uri)).await
}

async fn view_json(app: &Router) -> Value {
    let (s, h, b) = view(app, "/_mock/config").await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(h["cache-control"], "no-store");
    json(&b)
}

/// The value at a dotted path of the JSON config.
fn at<'a>(config: &'a Value, path: &str) -> &'a Value {
    path.split('.').fold(config, |v, k| &v[k])
}

#[tokio::test]
async fn masks_every_secret() {
    let env = [(
        "FAUXIDC__CLIENT__EXAMPLE_APP__CLIENT_SECRET",
        "env-secret-2",
    )];
    let (app, _, _) = file_app(&file_text(), &env);
    let (s, _, body) = view(&app, "/_mock/config").await;
    assert_eq!(s, 200, "{body}");
    for secret in ["file-secret-1", "env-secret-2", "private-key-d", "local"] {
        assert!(!body.contains(&format!("\"{secret}\"")), "{secret}: {body}");
    }
    let v = json(&body);
    assert_eq!(at(&v["config"], "client.backend.client_secret"), "***");
    assert_eq!(at(&v["config"], "client.example_app.client_secret"), "***");
    assert_eq!(
        v["config"]["client"]["backend"]["jwks"]["keys"][0]["d"],
        "***"
    );
    assert_eq!(
        v["config"]["client"]["backend"]["jwks"]["keys"][0]["x"],
        CLIENT_KEY.jwk["x"]
    );
    assert_eq!(
        v["sources"]["client.example_app.client_secret"],
        "env FAUXIDC__CLIENT__EXAMPLE_APP__CLIENT_SECRET"
    );
    let (_, _, text) = view(&app, "/_mock/config?format=toml").await;
    for secret in ["file-secret-1", "env-secret-2", "private-key-d"] {
        assert!(!text.contains(secret), "{secret}: {text}");
    }
}

#[tokio::test]
async fn matches_fauxidc_config_for_the_same_input() {
    let env = [("FAUXIDC__SERVER__REQUEST_LOG_SIZE", "42")];
    let (app, _, inputs) = file_app(&file_text(), &env);
    let v = view_json(&app).await;
    let printed = render(&load(&inputs).unwrap());
    let lines: Vec<&str> = printed.lines().collect();
    assert!(lines.len() > 20, "{printed}");
    assert_eq!(v["sources"].as_object().unwrap().len(), lines.len());
    for line in lines {
        let (leaf, source) = line.rsplit_once("  # ").unwrap();
        let (path, value) = leaf.split_once(" = ").unwrap();
        assert_eq!(v["sources"][path], source, "{line}");
        let expected: toml::Table = toml::from_str(&format!("v = {value}")).unwrap();
        let expected = serde_json::to_value(&expected["v"]).unwrap();
        assert_eq!(at(&v["config"], path), &expected, "{line}");
    }
    assert_eq!(
        v["sources"]["server.request_log_size"],
        "env FAUXIDC__SERVER__REQUEST_LOG_SIZE"
    );
    assert_eq!(v["sources"]["server.bind"], "default");
}

#[tokio::test]
async fn follows_hot_reload() {
    let (app, handle, inputs) = file_app(&file_text(), &[]);
    let file = &inputs.config_files[0];
    let text = format!("{}\n[user.carol]\nlabel = \"Carol\"\n", file_text());
    std::fs::write(file, &text).unwrap();
    assert!(reload_from(&handle, &inputs));
    let v = view_json(&app).await;
    assert_eq!(at(&v["config"], "user.carol.label"), "Carol");
    let line = text
        .lines()
        .position(|l| l.starts_with("label = \"Carol\""))
        .unwrap()
        + 1;
    assert_eq!(
        v["sources"]["user.carol.label"],
        format!("{}:{line}", file.display())
    );
}

#[tokio::test]
async fn a_value_the_files_no_longer_give_has_an_unknown_source() {
    let (app, handle, inputs) = file_app(&file_text(), &[]);
    // `server.port` needs a restart: the running config keeps 9000.
    let text = format!("[server]\nport = 9555\n{}\n[user.carol]\n", file_text());
    std::fs::write(&inputs.config_files[0], text).unwrap();
    assert!(reload_from(&handle, &inputs));
    let v = view_json(&app).await;
    assert_eq!(at(&v["config"], "server.port"), 9000);
    assert_eq!(v["sources"]["server.port"], "unknown");
    assert_ne!(v["sources"]["server.bind"], "unknown");
}

#[tokio::test]
async fn without_load_inputs_every_source_is_unknown() {
    let app = app(STRICT);
    let v = view_json(&app).await;
    assert_eq!(at(&v["config"], "client.example_app.client_secret"), "***");
    let sources = v["sources"].as_object().unwrap();
    assert!(!sources.is_empty());
    assert!(sources.values().all(|s| s == "unknown"), "{sources:?}");
}

#[tokio::test]
async fn format_toml_gives_the_masked_config_without_sources() {
    let (app, _, inputs) = file_app(&file_text(), &[]);
    let (s, h, text) = view(&app, "/_mock/config?format=toml").await;
    assert_eq!(s, 200, "{text}");
    assert_eq!(h["content-type"], "application/toml");
    let parsed: toml::Table = toml::from_str(&text).unwrap();
    let expected = fauxidc::config::masked(&load(&inputs).unwrap().config);
    assert_eq!(toml::Value::Table(parsed), expected);
    assert!(!text.contains(" # "), "{text}");
    let (s, h, _) = view(&app, "/_mock/config?format=json").await;
    assert_eq!(s, 200);
    assert_eq!(h["content-type"], "application/json");
}

#[tokio::test]
async fn bad_query_is_invalid_request() {
    let app = app(STRICT);
    for uri in ["/_mock/config?format=yaml", "/_mock/config?issuer=auth0"] {
        let (s, _, b) = view(&app, uri).await;
        assert_eq!(
            (s.as_u16(), json(&b)["error"].as_str()),
            (400, Some("invalid_request")),
            "{uri}: {b}"
        );
    }
}

async fn put_login(app: &Router, issuer: &str, value: bool) {
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/_mock/{issuer}/login"))
        .header("host", "localhost:9000")
        .header("content-type", "application/json")
        .body(Body::from(json!({ "show_user_list": value }).to_string()))
        .unwrap();
    let (s, _, b) = send(app, req).await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn config_view_shows_the_memory_login_setting() {
    let app = app(AUTH0);
    put_login(&app, "auth0", true).await;
    let v = view_json(&app).await;
    assert_eq!(at(&v["config"], "issuer.auth0.show_user_list"), true);
    assert_eq!(v["sources"]["issuer.auth0.show_user_list"], "memory");
    let (_, _, text) = view(&app, "/_mock/config?format=toml").await;
    assert!(text.contains("show_user_list = true"), "{text}");
}

#[tokio::test]
async fn config_view_shows_the_file_login_setting() {
    let (app, _, _) = file_app(&file_text(), &[]);
    put_login(&app, "auth0", true).await;
    let v = view_json(&app).await;
    assert_eq!(at(&v["config"], "issuer.auth0.show_user_list"), true);
    let source = v["sources"]["issuer.auth0.show_user_list"]
        .as_str()
        .unwrap();
    assert!(source.contains("fauxidc.toml"), "{source}");
}
