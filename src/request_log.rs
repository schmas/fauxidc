//! The Request log: an in-memory ring buffer of the raw requests the mock received.
//!
//! Headers and bodies are stored raw, secrets included. The `tracing` spans stay free of them.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use axum::{
    Json,
    body::Body,
    extract::{Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::clock::system_now;
use crate::issuer::{issuer_for_path, under};
use crate::state::AppState;

/// The largest request body the log buffers. A larger body gets 413 while the log is on.
pub const MAX_LOGGED_BODY: usize = 1024 * 1024;

/// One logged request and its response status.
#[derive(Debug, Clone, Serialize)]
pub struct LoggedRequest {
    /// Starts at 1, never reused (also not after `DELETE`).
    pub id: u64,
    /// Unix seconds.
    pub time: u64,
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    /// Issuer id from `issuer_for_path`.
    pub issuer: Option<String>,
    /// Lowercase names; repeated values joined with ", ".
    pub headers: BTreeMap<String, String>,
    /// Raw body, UTF-8 lossy.
    pub body: String,
    pub status: u16,
}

#[derive(Default)]
struct Inner {
    entries: VecDeque<LoggedRequest>,
    next_id: u64,
}

/// A ring buffer of [`LoggedRequest`]. Capacity 0 turns the log off.
pub struct RequestLog {
    capacity: usize,
    inner: Mutex<Inner>,
}

impl RequestLog {
    pub fn new(capacity: usize) -> RequestLog {
        RequestLog {
            capacity,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// `false` when the capacity is 0.
    pub fn enabled(&self) -> bool {
        self.capacity > 0
    }

    /// Assigns `id`; drops the oldest entry at capacity.
    pub fn push(&self, mut entry: LoggedRequest) {
        if self.capacity == 0 {
            return;
        }
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.next_id += 1;
        entry.id = inner.next_id;
        if inner.entries.len() >= self.capacity {
            inner.entries.pop_front();
        }
        inner.entries.push_back(entry);
    }

    /// Oldest first. Both filters are exact matches.
    pub fn list(&self, issuer: Option<&str>, path: Option<&str>) -> Vec<LoggedRequest> {
        let inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner
            .entries
            .iter()
            .filter(|e| issuer.is_none_or(|i| e.issuer.as_deref() == Some(i)))
            .filter(|e| path.is_none_or(|p| e.path == p))
            .cloned()
            .collect()
    }

    /// Removes all entries. The id counter keeps going.
    pub fn clear(&self) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .clear();
    }
}

/// Query parameters of `GET /_mock/requests`.
#[derive(Deserialize)]
pub struct ListQuery {
    pub issuer: Option<String>,
    pub path: Option<String>,
}

/// Middleware: buffers the body, runs the request and logs it with the response status.
/// `/_mock/*` requests and a disabled log pass through untouched.
pub async fn record(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let log = &state.request_log;
    if !log.enabled() || under(req.uri().path(), "/_mock") {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_LOGGED_BODY).await else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({
                "error": "invalid_request",
                "error_description": "request body too large",
            })),
        )
            .into_response();
    };
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in &parts.headers {
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        headers
            .entry(name.as_str().to_owned())
            .and_modify(|v| {
                v.push_str(", ");
                v.push_str(&value);
            })
            .or_insert(value);
    }
    let path = parts.uri.path().to_owned();
    let entry = LoggedRequest {
        id: 0,
        // When the request arrived: the system clock, not token time (ADR 0007).
        time: system_now(),
        method: parts.method.to_string(),
        issuer: issuer_for_path(&state.config, &path),
        path,
        query: parts.uri.query().map(str::to_owned),
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
        status: 0,
    };
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    log.push(LoggedRequest {
        status: response.status().as_u16(),
        ..entry
    });
    response
}

/// `GET /_mock/requests?issuer=&path=`.
pub async fn list(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Json<Vec<LoggedRequest>> {
    Json(
        state
            .request_log
            .list(q.issuer.as_deref(), q.path.as_deref()),
    )
}

/// `DELETE /_mock/requests`.
pub async fn clear(State(state): State<Arc<AppState>>) -> StatusCode {
    state.request_log.clear();
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, issuer: Option<&str>) -> LoggedRequest {
        LoggedRequest {
            id: 0,
            time: 0,
            method: "GET".into(),
            path: path.into(),
            query: None,
            issuer: issuer.map(str::to_owned),
            headers: BTreeMap::new(),
            body: String::new(),
            status: 200,
        }
    }

    #[test]
    fn capacity_and_id_order() {
        let log = RequestLog::new(2);
        for p in ["/a", "/b", "/c"] {
            log.push(entry(p, None));
        }
        let ids: Vec<u64> = log.list(None, None).iter().map(|e| e.id).collect();
        assert_eq!(ids, vec![2, 3]);
        log.clear();
        log.push(entry("/d", None));
        assert_eq!(log.list(None, None)[0].id, 4);
    }

    #[test]
    fn filters_are_exact() {
        let log = RequestLog::new(10);
        log.push(entry("/x/token", Some("x")));
        log.push(entry("/y/token", Some("y")));
        assert_eq!(log.list(Some("x"), None).len(), 1);
        assert_eq!(log.list(None, Some("/y/token")).len(), 1);
        assert_eq!(log.list(Some("x"), Some("/y/token")).len(), 0);
        assert_eq!(log.list(Some("x"), Some("/x")).len(), 0);
    }

    #[test]
    fn size_zero_stores_nothing() {
        let log = RequestLog::new(0);
        log.push(entry("/a", None));
        assert!(log.list(None, None).is_empty());
    }
}
