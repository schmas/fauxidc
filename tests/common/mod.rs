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
    let state = AppState::new(loaded.config, keys).unwrap();
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
