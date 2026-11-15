//! RFC 7662 token introspection.

use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::client_auth::{AuthMethod, ClientCredentials, authenticate_client};
use crate::clients::find_client;
use crate::config::{ClientConfig, Endpoint};
use crate::error::OAuthError;
use crate::logging::record_endpoint;
use crate::refresh::RefreshClaims;
use crate::revoke::has_credentials;
use crate::state::IssuerCtx;
use crate::token_check::{OwnToken, decode_own_token};
use crate::token_endpoint::form_rejection;

/// The form fields of an introspection request.
#[derive(Deserialize)]
pub struct IntrospectForm {
    pub token: Option<String>,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

impl IntrospectForm {
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

/// `POST {issuer}/introspect`.
pub async fn introspect(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    form: Result<Form<IntrospectForm>, FormRejection>,
) -> Response {
    record_endpoint(&ctx.id, "introspect");
    let Form(f) = match form {
        Ok(form) => form,
        Err(rejection) => return form_rejection(&ctx, "introspect", &rejection).into_response(),
    };
    match respond(&ctx, &headers, &f).await {
        Ok(body) => (
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(body),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn respond(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &IntrospectForm,
) -> Result<Value, OAuthError> {
    let creds = f.credentials();
    // Lenient: no client authentication is needed (spec 6.2).
    if !ctx.issuer().lenient || has_credentials(headers, creds) {
        let auth = authenticate_client(ctx, headers, Endpoint::Introspect, creds).await?;
        ctx.enforce(auth.method != AuthMethod::None, || {
            "introspection needs a confidential client".to_owned()
        })
        .map_err(|rule| OAuthError::json("invalid_client", rule))?;
    }
    let token = f
        .token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| OAuthError::json("invalid_request", "token is missing"))?;
    let keys = ctx.keys().await?;
    let inactive = json!({ "active": false });
    let now = ctx.app.now();
    let Some(own) = decode_own_token(&keys, &ctx.issuer_url(headers), token, now) else {
        return Ok(inactive);
    };
    if ctx.app.store.is_revoked(own.jti(), now) {
        return Ok(inactive);
    }
    match own {
        OwnToken::Access(mut claims) => {
            claims.insert("active".to_owned(), json!(true));
            claims.insert("token_type".to_owned(), json!("Bearer"));
            Ok(Value::Object(claims))
        }
        OwnToken::Refresh(claims) => {
            if rotated_out(ctx, &claims, now) {
                return Ok(inactive);
            }
            Ok(json!({
                "active": true,
                "token_type": "refresh_token",
                "scope": claims.scope,
                "client_id": claims.client_id,
                "sub": claims.sub,
                "iss": claims.iss,
                "aud": claims.aud,
                "exp": claims.exp,
                "iat": claims.iat,
                "jti": claims.jti,
            }))
        }
    }
}

/// `true` if a rotating Client already used this refresh token and the refresh grant would
/// reject it again: leeway 0, or the reuse window has passed.
fn rotated_out(ctx: &IssuerCtx, claims: &RefreshClaims, now: u64) -> bool {
    let Some(used_at) = ctx.app.store.refresh_used_at(&claims.jti) else {
        return false;
    };
    let config =
        find_client(ctx, &claims.client_id).map_or_else(ClientConfig::default, |c| c.config);
    let leeway = config.refresh_reuse_leeway_secs;
    config.rotate_refresh_tokens && (leeway == 0 || now > used_at.saturating_add(leeway))
}
