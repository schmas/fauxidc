#![allow(dead_code, unused_imports)] // each test binary uses only some helpers
#![allow(clippy::unwrap_used, clippy::expect_used)] // helpers are not #[test] fns

pub use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
pub use fauxidc::keys::{KeyHandle, SigningKey};
pub use serde_json::{Value, json};
pub use std::{path::PathBuf, sync::LazyLock, time::Duration};

use std::sync::Arc;

use fauxidc::router::build_router;
use fauxidc::state::AppState;
use tower::ServiceExt;

pub static KEY: LazyLock<SigningKey> = LazyLock::new(|| SigningKey::generate().unwrap());

pub const AUTH0: &str = "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\n";

/// Builds the router from an inline TOML config and a ready shared key.
pub fn app(toml: &str) -> Router {
    app_with_keys(toml, KeyHandle::ready(KEY.clone()))
}

/// Builds the router from an inline TOML config and the given key handle.
pub fn app_with_keys(toml: &str, keys: KeyHandle) -> Router {
    let loaded = fauxidc::config::load_str(toml).unwrap();
    app_from_parts(loaded.config, keys)
}

/// Builds the router from a loaded config and a ready shared key.
pub fn app_from_config(config: fauxidc::config::Config) -> Router {
    app_from_parts(config, KeyHandle::ready(KEY.clone()))
}

fn app_from_parts(config: fauxidc::config::Config, keys: KeyHandle) -> Router {
    let state = AppState::new(config, keys, true).unwrap();
    build_router(Arc::new(state))
}

/// Sends one request and returns status, headers and body text.
pub async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
    let res = app.clone().oneshot(req).await.unwrap();
    let (parts, body) = res.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (
        parts.status,
        parts.headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// A GET request with `Host: localhost:9000`.
pub fn get(uri: &str) -> Request<Body> {
    get_with(uri, &[])
}

/// A GET request with `Host: localhost:9000` and extra headers; a given `host` replaces the default.
pub fn get_with(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        b = b.header("host", "localhost:9000");
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

/// A form POST with `Host: localhost:9000` and extra headers.
pub fn post_form(uri: &str, form: &[(&str, &str)], headers: &[(&str, &str)]) -> Request<Body> {
    let body = serde_urlencoded::to_string(form).unwrap();
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded");
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        b = b.header("host", "localhost:9000");
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::from(body)).unwrap()
}

/// Parses a JSON string.
pub fn json(body: &str) -> Value {
    serde_json::from_str(body).unwrap()
}

pub const STRICT: &str = r#"[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"
sub_template = "auth0|{user_id}"

[client.example_app]
client_id = "example-app"
client_secret = "local"
redirect_uris = ["http://localhost:3000/api/auth/callback/*"]

[client.spa]
redirect_uris = ["http://localhost:5173/cb"]

[user.alice]
label = "Alice Admin"
claims = { email = "alice@example.com", email_verified = true, given_name = "Alice", family_name = "Admin", name = "Alice Admin", roles = ["admin"] }

[user.bob]
label = "Bobby Viewer"
claims = { email = "bob@example.com", name = "Bobby Viewer" }
"#;

/// `/auth0/authorize` for example-app with `response_type=code`, `scope="openid profile email"`,
/// `redirect_uri=http://localhost:3000/api/auth/callback/auth0`, `state=st`.
/// `extra` adds or replaces params.
pub fn authorize_url(extra: &[(&str, &str)]) -> String {
    let mut params: Vec<(String, String)> = [
        ("client_id", "example-app"),
        ("response_type", "code"),
        ("scope", "openid profile email"),
        (
            "redirect_uri",
            "http://localhost:3000/api/auth/callback/auth0",
        ),
        ("state", "st"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    for (k, v) in extra {
        match params.iter_mut().find(|(name, _)| name == k) {
            Some(pair) => pair.1 = (*v).to_owned(),
            None => params.push(((*k).to_owned(), (*v).to_owned())),
        }
    }
    format!(
        "/auth0/authorize?{}",
        serde_urlencoded::to_string(&params).unwrap()
    )
}

/// A fresh empty directory under the system temp dir.
pub fn tmp_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("fauxidc-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The `Location` header as a string.
pub fn location(h: &HeaderMap) -> String {
    h["location"].to_str().unwrap().to_owned()
}

/// The value of query parameter `name` in `url`.
pub fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    let query = query.split('#').next().unwrap_or(query);
    serde_urlencoded::from_str::<Vec<(String, String)>>(query)
        .ok()?
        .into_iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v)
}

/// `Basic base64(id:secret)` for an `Authorization` header.
pub fn basic(id: &str, secret: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"))
    )
}

/// Decodes the payload of a JWT without verifying it.
pub fn claims_of(jwt: &str) -> Value {
    use base64::Engine as _;
    let payload = jwt.split('.').nth(1).unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Decodes the header of a JWT without verifying it.
pub fn header_of(jwt: &str) -> Value {
    use base64::Engine as _;
    let header = jwt.split('.').next().unwrap();
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The login form for alice as example-app. `extra` adds or replaces form fields.
pub fn login_fields<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut form: Vec<(&str, &str)> = vec![
        ("client_id", "example-app"),
        (
            "redirect_uri",
            "http://localhost:3000/api/auth/callback/auth0",
        ),
        ("response_type", "code"),
        ("scope", "openid profile email"),
        ("state", "st"),
        ("user", "alice"),
    ];
    for &(k, v) in extra {
        form.retain(|&(a, _)| a != k);
        form.push((k, v));
    }
    form
}

/// Posts the login form for alice and returns the `code` from the `Location` header.
/// `extra` adds or replaces form fields.
pub async fn login_code(app: &Router, extra: &[(&str, &str)]) -> String {
    let (s, h, b) = send(
        app,
        post_form("/auth0/authorize", &login_fields(extra), &[]),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    query_param(&location(&h), "code").unwrap()
}

/// Exchanges `code` at `/auth0/token` as example-app, asserts 200 and returns the JSON body.
pub async fn exchange_code_for(app: &Router, code: &str) -> Value {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                (
                    "redirect_uri",
                    "http://localhost:3000/api/auth/callback/auth0",
                ),
            ],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    json(&b)
}

/// Logs alice in with `extra` login fields, exchanges the code as example-app, returns the JSON body.
pub async fn token_response_for(app: &Router, extra: &[(&str, &str)]) -> Value {
    let code = login_code(app, extra).await;
    exchange_code_for(app, &code).await
}

/// The `name=value` part of the `Set-Cookie` header for cookie `name`, if any.
pub fn set_cookie(h: &HeaderMap, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    h.get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with(&prefix))
        .map(|c| c.split(';').next().unwrap_or(c).to_owned())
}

/// Logs alice in, exchanges the code at `/auth0/token` as example-app and returns the access token.
/// `extra` adds or replaces login form fields.
pub async fn access_token_for(app: &Router, extra: &[(&str, &str)]) -> String {
    token_response_for(app, extra).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A JSON POST with `Host: localhost:9000`.
pub fn post_json(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("host", "localhost:9000")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// Posts `body` to the Test API of `issuer`, asserts 200 and returns the JSON response.
pub async fn test_token(app: &Router, issuer: &str, body: Value) -> Value {
    let (s, _, b) = send(app, post_json(&format!("/_mock/{issuer}/token"), &body)).await;
    assert_eq!(s, 200, "{b}");
    json(&b)
}

/// A JWT with `header` and `claims` and an empty signature.
pub fn unsigned_jwt(header: &Value, claims: &Value) -> String {
    use base64::Engine as _;
    let enc = |v: &Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap())
    };
    format!("{}.{}.", enc(header), enc(claims))
}

/// The current time in seconds since the Unix epoch.
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub use fauxidc::config::SigningAlg;

/// Base64url without padding.
pub fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// A JWT signed by `key`: header `alg` = the key's algorithm, `kid` = the key's `kid`.
pub fn sign_with(key: &SigningKey, claims: &Value) -> String {
    let mut header = jsonwebtoken::Header::new(key.alg.jwt());
    header.kid = Some(key.kid.clone());
    jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
}

/// The live router and its reload handle, from an inline TOML config and a ready shared key.
pub fn live_app(toml: &str) -> (Router, fauxidc::reload::ReloadHandle) {
    live_app_from(fauxidc::config::load_str(toml).unwrap().config)
}

/// The live router and its reload handle, from a loaded config and a ready shared key.
pub fn live_app_from(config: fauxidc::config::Config) -> (Router, fauxidc::reload::ReloadHandle) {
    let state = AppState::new(config, KeyHandle::ready(KEY.clone()), true).unwrap();
    fauxidc::reload::live_router(Arc::new(state))
}

/// Polls `f` every 20 ms until it returns true. Panics after `limit`.
pub async fn wait_until<F, Fut>(limit: Duration, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = std::time::Instant::now();
    loop {
        if f().await {
            return;
        }
        assert!(
            start.elapsed() < limit,
            "condition not met within {limit:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
