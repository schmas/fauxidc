//! The JWKS endpoint: serves the public keys of the Issuer's key set.

use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};

use crate::{logging::record_endpoint, state::IssuerCtx};

/// `GET /jwks`: waits for the Issuer's first key, then serves its key set, the active key first.
pub async fn jwks(State(ctx): State<IssuerCtx>) -> Response {
    record_endpoint(&ctx.id, "jwks");
    match ctx.keys().await {
        Ok(set) => Json(set.jwks()).into_response(),
        Err(e) => e.into_response(),
    }
}
