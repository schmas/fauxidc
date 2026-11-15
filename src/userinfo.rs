//! The userinfo endpoint: scope-filtered claims for a bearer access token.

use axum::{
    Json,
    body::Bytes,
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

/// `GET /userinfo`: the token claims without protocol claims and `nbf`.
pub async fn userinfo_get(State(ctx): State<IssuerCtx>, headers: HeaderMap) -> Response {
    record_endpoint(&ctx.id, "userinfo");
    let result = match bearer_token(&headers) {
        Some(token) => respond(&ctx, token).await,
        None => Err(OAuthError::BearerMissing),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}

/// `POST /userinfo`: as `GET`, and the token may also come as a form `access_token`
/// (RFC 6750 2.2). Both methods in one request are an `invalid_request` (RFC 6750 2).
pub async fn userinfo_post(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    record_endpoint(&ctx.id, "userinfo");
    let body_token = form_access_token(&headers, &body);
    let result = match (bearer_token(&headers), body_token.as_deref()) {
        (Some(_), Some(_)) => Err(OAuthError::json(
            "invalid_request",
            "use one bearer token method",
        )),
        (Some(token), None) | (None, Some(token)) => respond(&ctx, token).await,
        (None, None) => Err(OAuthError::BearerMissing),
    };
    result.unwrap_or_else(IntoResponse::into_response)
}

/// The non-empty `access_token` of an `application/x-www-form-urlencoded` body.
fn form_access_token(headers: &HeaderMap, body: &[u8]) -> Option<String> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| {
            v.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return None;
    }
    serde_urlencoded::from_bytes::<Vec<(String, String)>>(body)
        .ok()?
        .into_iter()
        .find(|(k, v)| k == "access_token" && !v.is_empty())
        .map(|(_, v)| v)
}

async fn respond(ctx: &IssuerCtx, token: &str) -> Result<Response, OAuthError> {
    let keys = ctx.keys().await?;
    let mut claims = verify_access_token(&keys, &ctx.issuer().issuer_url, token)?;
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
