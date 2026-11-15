mod common;
use common::*;

use axum::Router;
use serde_json::Value;

const EXAMPLES: [&str; 6] = ["auth0", "okta", "generic", "keycloak", "entra", "cognito"];
const PKCE_VERIFIER: &str = "example-verifier-0123456789-0123456789-0123456789";

fn load_inputs(file: &str) -> fauxidc::config::LoadInputs {
    fauxidc::config::LoadInputs {
        config_files: vec![file.into()],
        env: vec![],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: ".".into(),
    }
}

fn load_example(name: &str) -> fauxidc::config::Config {
    let f = format!("examples/{name}.toml");
    fauxidc::config::load(&load_inputs(&f))
        .unwrap_or_else(|e| panic!("{f}: {e}"))
        .config
}

fn router_path(url: &str) -> String {
    url.strip_prefix("http://localhost:9000")
        .unwrap_or_else(|| panic!("not a localhost:9000 URL: {url}"))
        .to_owned()
}

fn pkce_challenge() -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(PKCE_VERIFIER.as_bytes()))
}

/// Reads discovery at `{issuer_path}/.well-known/openid-configuration`, runs the login form for
/// `user` with `client_id` + PKCE S256 + `redirect_uri`, and exchanges the code at the published
/// token endpoint (Basic auth when `secret` is Some). Returns the token response JSON.
async fn login_and_token(
    app: &Router,
    issuer_path: &str,
    client_id: &str,
    secret: Option<&str>,
    redirect_uri: &str,
    user: &str,
    scope: &str,
) -> Value {
    let (s, _, b) = send(
        app,
        get(&format!("{issuer_path}/.well-known/openid-configuration")),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let d = json(&b);
    let authorize = router_path(d["authorization_endpoint"].as_str().unwrap());
    let token = router_path(d["token_endpoint"].as_str().unwrap());
    let challenge = pkce_challenge();
    let (s, h, b) = send(
        app,
        post_form(
            &authorize,
            &[
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("response_type", "code"),
                ("scope", scope),
                ("state", "st"),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
                ("user", user),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    let code = query_param(&location(&h), "code").unwrap();
    let auth = secret.map(|s| basic(client_id, s));
    let mut headers: Vec<(&str, &str)> = vec![];
    if let Some(a) = &auth {
        headers.push(("authorization", a));
    }
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri),
        ("code_verifier", PKCE_VERIFIER),
    ];
    if auth.is_none() {
        form.push(("client_id", client_id));
    }
    let (s, _, b) = send(app, post_form(&token, &form, &headers)).await;
    assert_eq!(s, 200, "{b}");
    json(&b)
}

#[test]
fn example_configs_are_valid() {
    for f in EXAMPLES.map(|n| format!("examples/{n}.toml")) {
        let f = f.as_str();
        let i = fauxidc::config::LoadInputs {
            config_files: vec![f.into()],
            env: vec![],
            flags: fauxidc::config::CliOverrides::default(),
            cwd: ".".into(),
        };
        let l = fauxidc::config::load(&i).unwrap_or_else(|e| panic!("{f}: {e}"));
        assert!(!l.zero_config);
    }
}

#[tokio::test]
async fn examples_merge_and_publish_paths() {
    let i = fauxidc::config::LoadInputs {
        config_files: vec!["examples/auth0.toml".into(), "examples/okta.toml".into()],
        env: vec![],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: ".".into(),
    };
    let app = app_from_config(fauxidc::config::load(&i).unwrap().config);
    let a = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        a["token_endpoint"],
        "http://localhost:9000/auth0/oauth/token"
    );
    assert_eq!(
        a["end_session_endpoint"],
        "http://localhost:9000/auth0/v2/logout"
    );
    let o = json(
        &send(
            &app,
            get("/oauth2/default/.well-known/openid-configuration"),
        )
        .await
        .2,
    );
    assert_eq!(
        o["jwks_uri"],
        "http://localhost:9000/oauth2/default/v1/keys"
    );
    assert_eq!(
        o["revocation_endpoint"],
        "http://localhost:9000/oauth2/default/v1/revoke"
    );
}

#[tokio::test]
async fn generic_example_logs_in_and_issues_client_credentials() {
    let app = app_from_config(load_example("generic"));
    let t = login_and_token(
        &app,
        "/generic",
        "web",
        Some("local"),
        "http://localhost:3000/callback",
        "alice",
        "openid profile email",
    )
    .await;
    assert_eq!(
        claims_of(t["id_token"].as_str().unwrap())["email"],
        "alice@example.com"
    );
    let t = login_and_token(
        &app,
        "/generic",
        "spa",
        None,
        "http://localhost:5173/",
        "bob",
        "openid email",
    )
    .await;
    assert_eq!(
        claims_of(t["id_token"].as_str().unwrap())["email"],
        "bob@example.com"
    );
    let (s, _, b) = send(
        &app,
        post_form(
            "/generic/token",
            &[("grant_type", "client_credentials"), ("scope", "api")],
            &[("authorization", &basic("service", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let at = claims_of(json(&b)["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], "https://api.example.test");
}

#[tokio::test]
async fn keycloak_example_logs_in() {
    let app = app_from_config(load_example("keycloak"));
    let t = login_and_token(
        &app,
        "/realms/example",
        "example-app",
        Some("local"),
        "http://localhost:3000/callback",
        "alice",
        "openid profile email",
    )
    .await;
    let at = claims_of(t["access_token"].as_str().unwrap());
    assert_eq!(at["iss"], "http://localhost:9000/realms/example");
    assert_eq!(at["typ"], "Bearer");
    assert_eq!(at["realm_access"]["roles"][0], "admin");
    assert_eq!(at["aud"], "account");
    assert_eq!(
        claims_of(t["id_token"].as_str().unwrap())["preferred_username"],
        "alice"
    );
}

#[tokio::test]
async fn entra_example_logs_in() {
    let app = app_from_config(load_example("entra"));
    let t = login_and_token(
        &app,
        "/00000000-0000-0000-0000-000000000000/v2.0",
        "example-app",
        Some("local"),
        "http://localhost:3000/callback",
        "alice",
        "openid profile email",
    )
    .await;
    let id = claims_of(t["id_token"].as_str().unwrap());
    assert_eq!(id["tid"], "00000000-0000-0000-0000-000000000000");
    assert!(id["oid"].as_str().unwrap().starts_with("00000000-"));
    assert_eq!(id["preferred_username"], "alice@example.test");
    assert_eq!(id["ver"], "2.0");
    assert_eq!(id["roles"][0], "Admin");
    let at = claims_of(t["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], "api://example-app");
    assert_eq!(at["tid"], "00000000-0000-0000-0000-000000000000");
    assert_eq!(at["ver"], "2.0");
    assert_eq!(at["scp"], "openid profile email");
    assert_eq!(at["roles"][0], "Admin");
}

#[tokio::test]
async fn cognito_example_logs_in() {
    let app = app_from_config(load_example("cognito"));
    let t = login_and_token(
        &app,
        "/us-east-1_example",
        "example-app",
        Some("local"),
        "http://localhost:3000/callback",
        "alice",
        "openid profile email",
    )
    .await;
    let id = claims_of(t["id_token"].as_str().unwrap());
    assert_eq!(id["cognito:username"], "alice");
    assert_eq!(id["token_use"], "id");
    let at = claims_of(t["access_token"].as_str().unwrap());
    assert_eq!(at["token_use"], "access");
    assert_eq!(at["client_id"], "example-app");
    assert_eq!(at["cognito:groups"][0], "admin");
    assert_eq!(at["username"], "alice");
    // Cognito signs out with `logout_uri`.
    let (s, h, b) = send(
        &app,
        get("/us-east-1_example/logout?client_id=example-app&logout_uri=http%3A%2F%2Flocalhost%3A3000%2F"),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    assert_eq!(location(&h), "http://localhost:3000/");
}

fn example_files() -> Vec<std::path::PathBuf> {
    let mut files: Vec<_> = std::fs::read_dir("examples")
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    files.sort();
    assert!(files.len() >= EXAMPLES.len(), "{files:?}");
    files
}

#[test]
fn examples_point_at_the_schema() {
    let want = format!("#:schema {}", fauxidc::config::SCHEMA_URL);
    for f in example_files() {
        let text = std::fs::read_to_string(&f).unwrap();
        assert_eq!(text.lines().next(), Some(want.as_str()), "{}", f.display());
    }
}

/// A small JSON Schema validator for the keywords the config schema uses. It panics on a
/// keyword it does not know, so a new keyword in the schema cannot pass unchecked.
#[allow(clippy::too_many_lines)] // one flat match over the schema keywords
fn validate(root: &Value, schema: &Value, v: &Value, at: &str, errs: &mut Vec<String>) {
    let Some(obj) = schema.as_object() else {
        if schema == &Value::Bool(false) {
            errs.push(format!("{at}: not allowed"));
        }
        return;
    };
    for (key, val) in obj {
        match key.as_str() {
            "$schema" | "$id" | "title" | "description" | "default" | "$defs" | "examples"
            | "format" => {}
            "$ref" => {
                let name = val.as_str().unwrap().strip_prefix("#/$defs/").unwrap();
                validate(root, &root["$defs"][name], v, at, errs);
            }
            "type" => {
                let ok = |t: &str| match t {
                    "object" => v.is_object(),
                    "array" => v.is_array(),
                    "string" => v.is_string(),
                    "boolean" => v.is_boolean(),
                    "null" => v.is_null(),
                    "integer" => v.is_i64() || v.is_u64(),
                    "number" => v.is_number(),
                    other => panic!("unknown type {other}"),
                };
                let types: Vec<&str> = match val {
                    Value::String(t) => vec![t],
                    Value::Array(a) => a.iter().map(|t| t.as_str().unwrap()).collect(),
                    _ => panic!("bad type"),
                };
                if !types.iter().any(|t| ok(t)) {
                    errs.push(format!("{at}: expected {types:?}, got {v}"));
                }
            }
            "enum" => {
                if !val.as_array().unwrap().contains(v) {
                    errs.push(format!("{at}: {v} not in {val}"));
                }
            }
            "const" => {
                if val != v {
                    errs.push(format!("{at}: expected {val}"));
                }
            }
            "minimum" => {
                if v.as_f64().is_some_and(|n| n < val.as_f64().unwrap()) {
                    errs.push(format!("{at}: below {val}"));
                }
            }
            "maximum" => {
                if v.as_f64().is_some_and(|n| n > val.as_f64().unwrap()) {
                    errs.push(format!("{at}: above {val}"));
                }
            }
            "anyOf" | "oneOf" => {
                let passes = val
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|s| {
                        let mut e = Vec::new();
                        validate(root, s, v, at, &mut e);
                        e.is_empty()
                    })
                    .count();
                if passes == 0 || (key == "oneOf" && passes != 1) {
                    errs.push(format!("{at}: {key} matched {passes} branches for {v}"));
                }
            }
            "properties" | "additionalProperties" | "propertyNames" => {
                let Some(map) = v.as_object() else { continue };
                for (k, child) in map {
                    let sub = format!("{at}/{k}");
                    match key.as_str() {
                        "properties" => {
                            if let Some(s) = val.get(k) {
                                validate(root, s, child, &sub, errs);
                            }
                        }
                        "additionalProperties" => {
                            if obj.get("properties").and_then(|p| p.get(k)).is_none() {
                                validate(root, val, child, &sub, errs);
                            }
                        }
                        _ => {
                            assert_eq!(val["pattern"], "^[a-z0-9_]+$", "unknown key pattern");
                            if k.is_empty()
                                || !k.chars().all(|c| {
                                    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
                                })
                            {
                                errs.push(format!("{sub}: key does not match the pattern"));
                            }
                        }
                    }
                }
            }
            "items" => {
                for (i, child) in v.as_array().into_iter().flatten().enumerate() {
                    validate(root, val, child, &format!("{at}/{i}"), errs);
                }
            }
            "required" => {
                for name in val.as_array().unwrap() {
                    if v.as_object()
                        .is_some_and(|m| !m.contains_key(name.as_str().unwrap()))
                    {
                        errs.push(format!("{at}: missing {name}"));
                    }
                }
            }
            other => panic!("the test validator does not know the keyword {other}"),
        }
    }
}

fn check(schema: &Value, doc: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    validate(schema, schema, doc, "", &mut errs);
    errs
}

#[test]
fn examples_validate_against_the_schema() {
    let schema: Value = serde_json::from_str(&fauxidc::config::schema_json()).unwrap();
    for f in example_files() {
        let doc: toml::Value = toml::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        let doc = serde_json::to_value(doc).unwrap();
        let errs = check(&schema, &doc);
        assert!(errs.is_empty(), "{}: {errs:#?}", f.display());
    }
}

#[test]
fn the_schema_validator_flags_bad_configs() {
    let schema: Value = serde_json::from_str(&fauxidc::config::schema_json()).unwrap();
    for bad in [
        "[server]\nprot = 1",
        "[issuer.Bad-Id]\nlenient = true",
        "[issuer.a]\nsigning_alg = \"HS256\"",
        "[client.a]\nredirect_uris = \"x\"",
        "[issuer.a.custom_user]\nlabl = \"x\"",
    ] {
        let doc: toml::Value = toml::from_str(bad).unwrap();
        let doc = serde_json::to_value(doc).unwrap();
        assert!(!check(&schema, &doc).is_empty(), "{bad}");
    }
}
