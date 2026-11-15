//! RFC 7009 token revocation.

use axum::{
    Form,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::client_auth::{ClientCredentials, authenticate_client};
use crate::config::Endpoint;
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
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

impl RevokeForm {
    /// The client credentials of the form.
    pub fn credentials(&self) -> ClientCredentials<'_> {
        ClientCredentials {
            client_id: self.client_id.as_deref(),
            client_secret: self.client_secret.as_deref(),
            client_assertion_type: self.client_assertion_type.as_deref(),
            client_assertion: self.client_assertion.as_deref(),
        }
    }
}

/// `true` if the request carries client credentials: a Basic `Authorization` header or a form
/// `client_id`, `client_secret` or `client_assertion`. Other schemes (for example a Bearer token that a resource
/// server sends, RFC 7662 2.1) are not client credentials.
pub(crate) fn has_credentials(headers: &HeaderMap, creds: ClientCredentials<'_>) -> bool {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("basic"));
    let present = |v: Option<&str>| v.is_some_and(|v| !v.is_empty());
    basic
        || present(creds.client_id)
        || present(creds.client_secret)
        || present(creds.client_assertion)
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
    let creds = f.credentials();
    // Lenient: no client authentication is needed (spec 6.2).
    let client = if ctx.issuer().lenient && !has_credentials(headers, creds) {
        None
    } else {
        Some(
            authenticate_client(ctx, headers, Endpoint::Revoke, creds)
                .await?
                .client,
        )
    };
    let token = f
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| OAuthError::json("invalid_request", "token is missing"))?;
    // `token_type_hint` is ignored (RFC 7009 2.1).
    let keys = ctx.keys().await?;
    let Some(own) = decode_own_token(&keys, &ctx.issuer().issuer_url, token) else {
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
