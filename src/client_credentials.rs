//! The `client_credentials` grant (RFC 6749 4.4).

use axum::http::HeaderMap;
use serde_json::{Value, json};

use crate::claims::PROTOCOL_CLAIMS;
use crate::client_auth::{ClientAuth, authenticate_client};
use crate::config::Endpoint;
use crate::error::OAuthError;
use crate::state::IssuerCtx;
use crate::token_endpoint::{TokenForm, require_grant};
use crate::tokens::{AccessTokenInput, lifetime_secs, sign_access_token};

/// Issues an access token for the Client itself: `sub = client_id`, claims from the Client
/// `access_claims`. No `id_token` and no refresh token (spec 9).
pub async fn grant(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    let ClientAuth { client, .. } =
        authenticate_client(ctx, headers, Endpoint::Token, f.credentials()).await?;
    ctx.enforce(!client.is_public(), || {
        "client_credentials needs a confidential client".to_owned()
    })
    .map_err(|rule| OAuthError::json("unauthorized_client", rule))?;
    require_grant(ctx, &client, "client_credentials")?;

    let scope: Vec<String> = f
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let unknown: Vec<&str> = scope
        .iter()
        .filter(|s| !client.config.scopes.contains(s))
        .map(String::as_str)
        .collect();
    ctx.enforce(unknown.is_empty(), || {
        format!("unknown scope: {}", unknown.join(" "))
    })
    .map_err(|rule| OAuthError::json("invalid_scope", rule))?;

    let non_empty = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_owned);
    let audience = non_empty(f.audience.as_deref())
        .or_else(|| non_empty(f.resource.as_deref()))
        .or_else(|| non_empty(Some(client.config.audience.as_str())))
        .unwrap_or_else(|| client.client_id.clone());

    let mut claims = client.config.access_claims.clone();
    for name in PROTOCOL_CLAIMS {
        claims.remove(*name);
    }
    claims.insert("sub".to_owned(), json!(client.client_id));

    let keys = ctx.keys().await?;
    let issuer = ctx.issuer();
    let lifetimes = issuer.lifetimes.with_override(&client.config.lifetimes);
    let access_token = sign_access_token(
        &keys.active,
        AccessTokenInput {
            issuer_url: &ctx.issuer_url(headers),
            client_id: &client.client_id,
            audience: &audience,
            claims,
            scope: &scope,
            auth_time: None,
            now: ctx.app.now(),
            lifetime: lifetime_secs(lifetimes.access_token),
        },
    )
    .await?;
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": lifetime_secs(lifetimes.access_token),
    });
    if !scope.is_empty() {
        body["scope"] = json!(scope.join(" "));
    }
    Ok(body)
}
