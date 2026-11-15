//! RFC 7009 token revocation.

use axum::{
    Form,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::client_auth::authenticate_client;
use crate::error::OAuthError;
use crate::logging::record_endpoint;
use crate::state::IssuerCtx;
use crate::token_check::decode_own_token;
use crate::token_endpoint::form_rejection;

/// The form fields of a revocation request.
#[derive(Deserialize)]
pub struct RevokeForm {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// `true` if the request carries client credentials: an `Authorization` header or a form
/// `client_id` or `client_secret`.
pub(crate) fn has_credentials(
    headers: &HeaderMap,
    client_id: Option<&str>,
    client_secret: Option<&str>,
) -> bool {
    headers.contains_key(header::AUTHORIZATION)
        || client_id.is_some_and(|v| !v.is_empty())
        || client_secret.is_some_and(|v| !v.is_empty())
}

/// `POST {issuer}/revoke`.
pub async fn revoke(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    record_endpoint(&ctx.id, "revoke");
    let Form(f) = match form {
        Ok(form) => form,
        Err(rejection) => return form_rejection(&ctx, "revoke", &rejection).into_response(),
    };
    match respond(&ctx, &headers, &f).await {
        Ok(()) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn respond(ctx: &IssuerCtx, headers: &HeaderMap, f: &RevokeForm) -> Result<(), OAuthError> {
    let (client_id, client_secret) = (f.client_id.as_deref(), f.client_secret.as_deref());
    // Lenient: no client authentication is needed (spec 6.2).
    let client = if ctx.issuer().lenient && !has_credentials(headers, client_id, client_secret) {
        None
    } else {
        Some(authenticate_client(ctx, headers, client_id, client_secret)?.client)
    };
    let token = f
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| OAuthError::json("invalid_request", "token is missing"))?;
    // `token_type_hint` is ignored (RFC 7009 2.1).
    let key = ctx
        .app
        .keys
        .get()
        .await
        .map_err(|_| OAuthError::Unavailable)?;
    let Some(own) = decode_own_token(&key, &ctx.issuer().issuer_url, token) else {
        // RFC 7009 2.2: an invalid token is not an error.
        tracing::info!(issuer = %ctx.id, "revoke: not a valid token of this issuer");
        return Ok(());
    };
    let owner_matches = client
        .as_ref()
        .is_none_or(|c| c.client_id == own.client_id());
    if ctx
        .enforce(owner_matches, || {
            format!(
                "token was not issued to {}",
                client.as_ref().map_or("", |c| c.client_id.as_str())
            )
        })
        .is_err()
    {
        return Ok(());
    }
    ctx.app.store.revoke(own.jti(), own.exp());
    Ok(())
}
