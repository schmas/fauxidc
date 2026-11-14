//! The userinfo endpoint: scope-filtered claims for a bearer access token.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::claims::PROTOCOL_CLAIMS;
use crate::error::OAuthError;
use crate::logging::record_endpoint;
use crate::state::IssuerCtx;
use crate::tokens::verify_access_token;

/// The token from an `Authorization: Bearer <token>` header. The scheme is case-insensitive.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let (scheme, token) = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
}

/// `GET` or `POST /userinfo`: the token claims without protocol claims and `nbf`.
pub async fn userinfo(State(ctx): State<IssuerCtx>, headers: HeaderMap) -> Response {
    record_endpoint(&ctx.id, "userinfo");
    match respond(&ctx, &headers).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn respond(ctx: &IssuerCtx, headers: &HeaderMap) -> Result<Response, OAuthError> {
    let token = bearer_token(headers).ok_or(OAuthError::BearerMissing)?;
    let key = ctx
        .app
        .keys
        .get()
        .await
        .map_err(|_| OAuthError::Unavailable)?;
    let mut claims = verify_access_token(&key, &ctx.issuer().issuer_url, token)?;
    for name in PROTOCOL_CLAIMS {
        claims.remove(*name);
    }
    claims.remove("nbf");
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(Value::Object(claims)),
    )
        .into_response())
}
