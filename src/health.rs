//! `GET /_mock/health`: liveness plus signing key readiness. It never waits for the key.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::state::AppState;

/// Reports `key: ready` once the signing key exists and `key: pending` before that.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let key = if state.keys.try_get().is_some() {
        "ready"
    } else {
        "pending"
    };
    Json(json!({ "status": "ok", "key": key }))
}
