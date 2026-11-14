//! The JWKS endpoint: serves the public signing key.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::state::IssuerCtx;

/// `GET /jwks`: waits for the signing key, then serves it as a JWK set.
pub async fn jwks(State(ctx): State<IssuerCtx>) -> Response {
    match ctx.app.keys.get().await {
        Ok(key) => Json(json!({ "keys": [key.jwk] })).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "server_error",
                "error_description": "signing key not available",
            })),
        )
            .into_response(),
    }
}
