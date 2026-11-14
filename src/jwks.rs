//! The JWKS endpoint: serves the public signing key.

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::{error::OAuthError, logging::record_endpoint, state::IssuerCtx};

/// `GET /jwks`: waits for the signing key, then serves it as a JWK set.
pub async fn jwks(State(ctx): State<IssuerCtx>) -> Response {
    record_endpoint(&ctx.id, "jwks");
    match ctx.app.keys.get().await {
        Ok(key) => Json(json!({ "keys": [key.jwk] })).into_response(),
        Err(_) => OAuthError::Unavailable.into_response(),
    }
}
