//! The RFC 7523 jwt-bearer grant (section 2.1), the On-Behalf-Of flow.
//!
//! The `assertion` is checked like a token exchange `subject_token`: a JWT of any fauxidc
//! Issuer is verified; Lenient mode uses a JWT that fails verification unverified. The result
//! is an access token of this Issuer only, with no `id_token` and no refresh token.

use axum::http::HeaderMap;
use serde_json::{Value, json};

use crate::client_auth::{ClientAuth, authenticate_client};
use crate::config::Endpoint;
use crate::error::OAuthError;
use crate::state::IssuerCtx;
use crate::token_endpoint::{TokenForm, require_grant};
use crate::token_exchange::{DROPPED_CLAIMS, split_scope, token_claims};
use crate::tokens::{AccessTokenInput, lifetime_secs, sign_access_token};

/// The jwt-bearer grant type.
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// The jwt-bearer grant. `scope` comes from the request, else from the assertion `scope`
/// claim; without both the request is `invalid_scope` in both modes.
pub async fn grant(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    let ClientAuth { client, .. } =
        authenticate_client(ctx, headers, Endpoint::Token, f.credentials()).await?;
    require_grant(ctx, &client, GRANT_JWT_BEARER)?;
    let assertion = f
        .assertion
        .as_deref()
        .filter(|a| !a.is_empty())
        .ok_or_else(|| OAuthError::json("invalid_request", "assertion is missing"))?;
    let subject = token_claims(ctx, headers, assertion, "assertion", "invalid_grant").await?;
    let scope = split_scope(f.scope.as_deref())
        .or_else(|| split_scope(subject.get("scope").and_then(Value::as_str)))
        .ok_or_else(|| {
            OAuthError::json(
                "invalid_scope",
                "scope must be in the request or in the assertion",
            )
        })?;
    let mut claims = subject.clone();
    for name in DROPPED_CLAIMS {
        claims.remove(name);
    }

    let non_empty = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_owned);
    let audience = non_empty(f.audience.as_deref())
        .or_else(|| non_empty(f.resource.as_deref()))
        .or_else(|| non_empty(Some(client.config.audience.as_str())))
        .unwrap_or_else(|| client.client_id.clone());
    let keys = ctx.keys().await?;
    let lifetime = lifetime_secs(
        ctx.issuer()
            .lifetimes
            .with_override(&client.config.lifetimes)
            .access_token,
    );
    let access_token = sign_access_token(
        &keys.active,
        AccessTokenInput {
            issuer_url: &ctx.issuer_url(headers),
            client_id: &client.client_id,
            audience: &audience,
            claims,
            scope: &scope,
            auth_time: subject.get("auth_time").and_then(Value::as_u64),
            lifetime,
        },
    )
    .await?;
    Ok(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": lifetime,
        "scope": scope.join(" "),
    }))
}
