//! Injected failures: the Test API `POST /_mock/{issuer_id}/fail-next` makes the next N
//! requests to one endpoint of an Issuer fail or slow down.
//!
//! The entries live in the shared [`Store`], so they survive a hot reload. Every Issuer route
//! has the [`inject`] middleware with its endpoint key.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    extract::{Path, Request, State, rejection::JsonRejection},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::error::OAuthError;
use crate::logging::record_endpoint;
use crate::state::{AppState, Store};
use crate::test_api::unknown_issuer;

/// The endpoint keys an Injected failure can target: the eight `paths` keys and `discovery`.
pub const ENDPOINTS: [&str; 9] = [
    "authorize",
    "token",
    "userinfo",
    "jwks",
    "endsession",
    "introspect",
    "revoke",
    "debugger",
    "discovery",
];

/// The largest allowed `delay_ms`.
pub const MAX_DELAY_MS: u64 = 60_000;

const DEFAULT_STATUS: u16 = 500;
const DEFAULT_ERROR: &str = "server_error";

/// The JSON body of `POST /_mock/{issuer_id}/fail-next`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailNextRequest {
    pub endpoint: String,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub count: Option<u32>,
    pub delay_ms: Option<u64>,
}

/// A stored Injected failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Injected {
    /// The response status; `None` for a delay-only entry.
    pub status: Option<u16>,
    pub error: String,
    pub remaining: u32,
    pub delay_ms: u64,
}

/// Checks the body and returns the normalized entry, with `remaining` possibly 0.
fn normalize(req: FailNextRequest) -> Result<(String, Injected), String> {
    if !ENDPOINTS.contains(&req.endpoint.as_str()) {
        return Err(format!(
            "unknown endpoint \"{}\"; expected one of: {}",
            req.endpoint,
            ENDPOINTS.join(", ")
        ));
    }
    if let Some(status) = req.status
        && !(400..=599).contains(&status)
    {
        return Err(format!("status must be 400 to 599, got {status}"));
    }
    let delay_ms = req.delay_ms.unwrap_or(0);
    if delay_ms > MAX_DELAY_MS {
        return Err(format!("delay_ms must be at most {MAX_DELAY_MS}"));
    }
    let error = match req.error {
        Some(e) if e.is_empty() => return Err("error must not be empty".into()),
        Some(e) => e,
        None => DEFAULT_ERROR.to_owned(),
    };
    let status = match req.status {
        Some(s) => Some(s),
        None if delay_ms > 0 => None,
        None => Some(DEFAULT_STATUS),
    };
    Ok((
        req.endpoint,
        Injected {
            status,
            error,
            remaining: req.count.unwrap_or(1),
            delay_ms,
        },
    ))
}

/// Checks the body (Ruling 12) and returns the entry to store; `count: 0` gives `Ok(None)`
/// (remove the entry).
pub fn injected_from(req: FailNextRequest) -> Result<Option<Injected>, String> {
    normalize(req).map(|(_, f)| (f.remaining > 0).then_some(f))
}

/// `POST /_mock/{issuer_id}/fail-next`: 200 `{"endpoint","status","error","remaining","delay_ms"}`;
/// 400 `invalid_request`; 404 for an unknown Issuer id.
pub async fn fail_next(
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
    body: Result<Json<FailNextRequest>, JsonRejection>,
) -> Response {
    if !state.config.issuer.contains_key(&issuer_id) {
        return unknown_issuer(&issuer_id);
    }
    let req = match body {
        Ok(Json(req)) => req,
        Err(rejection) => {
            return OAuthError::json("invalid_request", format!("invalid body: {rejection}"))
                .into_response();
        }
    };
    let (endpoint, f) = match normalize(req) {
        Ok(v) => v,
        Err(e) => return OAuthError::json("invalid_request", e).into_response(),
    };
    let body = json!({
        "endpoint": endpoint,
        "status": f.status,
        "error": f.error,
        "remaining": f.remaining,
        "delay_ms": f.delay_ms,
    });
    tracing::info!(issuer = %issuer_id, endpoint = %endpoint, remaining = f.remaining, "injected failure set");
    state.store.inject(&issuer_id, &endpoint, Some(f));
    Json(body).into_response()
}

/// `DELETE /_mock/{issuer_id}/fail-next`: removes every Injected failure of the Issuer. 204; 404 for an unknown Issuer id.
pub async fn clear(State(state): State<Arc<AppState>>, Path(issuer_id): Path<String>) -> Response {
    if !state.config.issuer.contains_key(&issuer_id) {
        return unknown_issuer(&issuer_id);
    }
    state.store.clear_failures(&issuer_id);
    StatusCode::NO_CONTENT.into_response()
}

/// What the route middleware needs: the shared store and the endpoint it guards.
#[derive(Clone)]
pub struct FailureTarget {
    pub store: Arc<Store>,
    pub issuer_id: String,
    pub endpoint: &'static str,
}

/// Takes one use of the Injected failure of `endpoint`, sleeps its delay, and returns the
/// failure response. `None` when there is no entry or the entry only delays.
pub async fn apply(store: &Store, issuer_id: &str, endpoint: &str) -> Option<Response> {
    let f = store.take_failure(issuer_id, endpoint)?;
    if f.delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(f.delay_ms)).await;
    }
    let status = StatusCode::from_u16(f.status?).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    tracing::info!(issuer = %issuer_id, endpoint, status = status.as_u16(), "injected failure");
    Some(
        (
            status,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(json!({"error": f.error, "error_description": "injected failure"})),
        )
            .into_response(),
    )
}

/// The route middleware: records the Issuer and endpoint on the request span, takes one use,
/// sleeps `delay_ms`, then answers `status` with
/// `{"error": error, "error_description": "injected failure"}` (Cache-Control: no-store), or
/// calls `next` for a delay-only entry. `OPTIONS` requests (CORS preflights) pass through.
pub async fn inject(State(target): State<FailureTarget>, req: Request, next: Next) -> Response {
    if req.method() == Method::OPTIONS {
        return next.run(req).await;
    }
    record_endpoint(&target.issuer_id, target.endpoint);
    match apply(&target.store, &target.issuer_id, target.endpoint).await {
        Some(res) => res,
        None => next.run(req).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(v: serde_json::Value) -> FailNextRequest {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn defaults() {
        let f = injected_from(req(json!({"endpoint":"token"})))
            .unwrap()
            .unwrap();
        assert_eq!(
            f,
            Injected {
                status: Some(500),
                error: "server_error".into(),
                remaining: 1,
                delay_ms: 0
            }
        );
    }

    #[test]
    fn delay_only() {
        let f = injected_from(req(json!({"endpoint":"token","delay_ms":10})))
            .unwrap()
            .unwrap();
        assert_eq!(f.status, None);
        assert_eq!(f.delay_ms, 10);
    }

    #[test]
    fn count_zero_removes() {
        assert_eq!(
            injected_from(req(json!({"endpoint":"token","count":0}))),
            Ok(None)
        );
    }

    #[test]
    fn bad_values() {
        for v in [
            json!({"endpoint":"nope"}),
            json!({"endpoint":"token","status":399}),
            json!({"endpoint":"token","status":600}),
            json!({"endpoint":"token","delay_ms":60_001}),
            json!({"endpoint":"token","error":""}),
        ] {
            assert!(injected_from(req(v.clone())).is_err(), "{v}");
        }
        assert!(injected_from(req(json!({"endpoint":"token","delay_ms":60_000}))).is_ok());
    }
}
