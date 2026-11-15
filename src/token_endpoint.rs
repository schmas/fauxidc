//! The token endpoint: grant dispatch and the `authorization_code` grant.

use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::authorize::valid_pkce_value;
use crate::claims::{ClaimTarget, build_claims, filter_by_scope};
use crate::client_auth::{ClientAuth, authenticate_client, constant_time_eq};
use crate::clients::ResolvedClient;
use crate::error::OAuthError;
use crate::keys::SigningKey;
use crate::logging::record_endpoint;
use crate::refresh::{RefreshClaims, sign_refresh_token};
use crate::state::{IssuerCtx, PkceMethod, Subject, now_secs};
use crate::tokens::{AccessTokenInput, IdTokenInput, sign_access_token, sign_id_token};

/// The form fields of a token request.
#[derive(Deserialize)]
pub struct TokenForm {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
}

/// `unauthorized_client` (through `ctx.enforce`) unless the Client allows `grant`.
pub(crate) fn require_grant(
    ctx: &IssuerCtx,
    client: &ResolvedClient,
    grant: &str,
) -> Result<(), OAuthError> {
    ctx.enforce(client.config.grant_types.iter().any(|g| g == grant), || {
        format!("client is not allowed the {grant} grant")
    })
    .map_err(|rule| OAuthError::json("unauthorized_client", rule))
}

/// Checks a PKCE verifier against the stored challenge.
pub(crate) fn pkce_matches(challenge: &str, method: PkceMethod, verifier: &str) -> bool {
    match method {
        PkceMethod::S256 => {
            let digest = Sha256::digest(verifier.as_bytes());
            let computed = URL_SAFE_NO_PAD.encode(digest);
            constant_time_eq(computed.as_bytes(), challenge.as_bytes())
        }
        PkceMethod::Plain => constant_time_eq(verifier.as_bytes(), challenge.as_bytes()),
    }
}

/// Checks the `code_verifier` of a token request for a code with a PKCE challenge.
fn check_verifier(
    ctx: &IssuerCtx,
    challenge: &str,
    method: PkceMethod,
    verifier: Option<&str>,
) -> Result<(), OAuthError> {
    let rule = match verifier.filter(|v| !v.is_empty()) {
        None => Some("code_verifier missing"),
        Some(v) if !valid_pkce_value(v) => {
            Some("code_verifier must be 43 to 128 characters of [A-Za-z0-9-._~]")
        }
        Some(v) if !pkce_matches(challenge, method, v) => Some("PKCE verification failed"),
        Some(_) => None,
    };
    ctx.enforce(rule.is_none(), || {
        rule.unwrap_or("PKCE verification failed").to_owned()
    })
    .map_err(|_| OAuthError::json("invalid_grant", "PKCE verification failed"))
}

/// The `invalid_request` error for a form body that does not parse. `endpoint` names the
/// endpoint in the log line.
pub(crate) fn form_rejection(
    ctx: &IssuerCtx,
    endpoint: &str,
    rejection: &FormRejection,
) -> OAuthError {
    let description = match rejection {
        FormRejection::InvalidFormContentType(_) => {
            "body must be application/x-www-form-urlencoded"
        }
        _ => "malformed form body",
    };
    tracing::info!(issuer = %ctx.id, "{endpoint} request rejected: {rejection}");
    OAuthError::json("invalid_request", description)
}

/// `POST /token`.
pub async fn token(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    form: Result<Form<TokenForm>, FormRejection>,
) -> Response {
    record_endpoint(&ctx.id, "token");
    let Form(f) = match form {
        Ok(form) => form,
        Err(rejection) => return form_rejection(&ctx, "token", &rejection).into_response(),
    };
    match dispatch(&ctx, &headers, &f).await {
        Ok(body) => (
            [
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (header::PRAGMA, HeaderValue::from_static("no-cache")),
            ],
            Json(body),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// Runs the grant that `grant_type` names. The grant type is checked before client authentication.
async fn dispatch(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    match f.grant_type.as_deref() {
        Some("authorization_code") => exchange_code(ctx, headers, f).await,
        Some("refresh_token") => crate::refresh::refresh_grant(ctx, headers, f).await,
        Some("client_credentials") => crate::client_credentials::grant(ctx, headers, f).await,
        Some(other) => Err(OAuthError::json(
            "unsupported_grant_type",
            format!("unsupported grant_type: {other}"),
        )),
        None => Err(OAuthError::json(
            "unsupported_grant_type",
            "grant_type is missing",
        )),
    }
}

async fn exchange_code(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    let ClientAuth { client, .. } = authenticate_client(
        ctx,
        headers,
        f.client_id.as_deref(),
        f.client_secret.as_deref(),
    )?;
    require_grant(ctx, &client, "authorization_code")?;
    let invalid_grant = |d: &str| {
        tracing::info!(issuer = %ctx.id, "{d}");
        OAuthError::json("invalid_grant", d)
    };
    let grant = f
        .code
        .as_deref()
        .filter(|code| !code.is_empty())
        .and_then(|code| ctx.app.store.take_code(code))
        .ok_or_else(|| invalid_grant("code is invalid or was already used"))?;
    if grant.issuer_id != ctx.id || grant.client_id != client.client_id {
        return Err(invalid_grant("code was not issued to this client"));
    }
    if now_secs() >= grant.expires_at {
        return Err(invalid_grant("code expired"));
    }
    ctx.enforce(
        f.redirect_uri.as_deref() == Some(grant.redirect_uri.as_str()),
        || "redirect_uri does not match the authorization request".to_owned(),
    )
    .map_err(|_| OAuthError::json("invalid_grant", "redirect_uri does not match"))?;
    if let Some((challenge, method)) = &grant.pkce {
        check_verifier(ctx, challenge, *method, f.code_verifier.as_deref())?;
    }
    let key = ctx
        .app
        .keys
        .get()
        .await
        .map_err(|_| OAuthError::Unavailable)?;

    issue_user_tokens(
        ctx,
        &key,
        &UserGrant {
            client: &client,
            subject: &grant.subject,
            scope: &grant.scope,
            audience: grant.audience.as_deref(),
            auth_time: grant.auth_time,
            nonce: grant.nonce.as_deref(),
            refresh: RefreshMode::ByPolicy,
            refresh_scope: None,
        },
    )
}

/// Whether and how a token response gets a refresh token.
pub(crate) enum RefreshMode {
    /// Issue one when `refresh_allowed`.
    ByPolicy,
    /// Always issue a new one.
    Issue,
    /// Return this presented refresh token unchanged.
    Echo(String),
}

/// What a user token response is built from.
pub(crate) struct UserGrant<'a> {
    pub client: &'a ResolvedClient,
    pub subject: &'a Subject,
    pub scope: &'a [String],
    /// Request audience; `None` → Client audience → `client_id`.
    pub audience: Option<&'a str>,
    pub auth_time: u64,
    pub nonce: Option<&'a str>,
    pub refresh: RefreshMode,
    /// Scope of a new refresh token; `None` uses `scope`. A narrowed refresh keeps the
    /// original scope here (RFC 6749 section 6).
    pub refresh_scope: Option<&'a [String]>,
}

/// Strict: `offline_access` in scope AND the Client allows `refresh_token`. Lenient: always.
pub(crate) fn refresh_allowed(ctx: &IssuerCtx, client: &ResolvedClient, scope: &[String]) -> bool {
    if ctx.issuer().lenient {
        return true;
    }
    scope.iter().any(|s| s == "offline_access")
        && client
            .config
            .grant_types
            .iter()
            .any(|g| g == "refresh_token")
}

/// Signs the access token, the `id_token` (if `openid` is in scope) and the refresh token
/// (per `refresh`). Returns the token response JSON body.
pub(crate) fn issue_user_tokens(
    ctx: &IssuerCtx,
    key: &SigningKey,
    g: &UserGrant<'_>,
) -> Result<Value, OAuthError> {
    let client = g.client;
    let issuer = ctx.issuer();
    let lifetimes = issuer.lifetimes.with_override(&client.config.lifetimes);
    let audience = match (g.audience, client.config.audience.as_str()) {
        (Some(a), _) => a.to_owned(),
        (None, a) if !a.is_empty() => a.to_owned(),
        (None, _) => client.client_id.clone(),
    };
    let config = &ctx.app.config;
    let access_claims = filter_by_scope(
        build_claims(
            config,
            &ctx.id,
            &client.config,
            g.subject,
            ClaimTarget::Access,
        ),
        g.scope,
    );
    let sub = access_claims
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let access_token = sign_access_token(
        key,
        AccessTokenInput {
            issuer_url: &issuer.issuer_url,
            client_id: &client.client_id,
            audience: &audience,
            claims: access_claims,
            scope: g.scope,
            auth_time: Some(g.auth_time),
            lifetime: lifetimes.access_token,
        },
    )?;
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": lifetimes.access_token,
        "scope": g.scope.join(" "),
    });
    if g.scope.iter().any(|s| s == "openid") {
        let id_claims = filter_by_scope(
            build_claims(
                config,
                &ctx.id,
                &client.config,
                g.subject,
                ClaimTarget::IdToken,
            ),
            g.scope,
        );
        body["id_token"] = json!(sign_id_token(
            key,
            IdTokenInput {
                issuer_url: &issuer.issuer_url,
                client_id: &client.client_id,
                claims: id_claims,
                auth_time: g.auth_time,
                nonce: g.nonce,
                lifetime: lifetimes.id_token,
            },
        )?);
    }
    let issue = match &g.refresh {
        RefreshMode::ByPolicy => refresh_allowed(ctx, client, g.scope),
        RefreshMode::Issue => true,
        RefreshMode::Echo(token) => {
            body["refresh_token"] = json!(token);
            false
        }
    };
    if issue {
        let now = now_secs();
        body["refresh_token"] = json!(sign_refresh_token(
            key,
            &RefreshClaims {
                iss: issuer.issuer_url.clone(),
                aud: client.client_id.clone(),
                client_id: client.client_id.clone(),
                sub,
                jti: uuid::Uuid::new_v4().to_string(),
                iat: now,
                exp: now.saturating_add(lifetimes.refresh_token),
                scope: g.refresh_scope.unwrap_or(g.scope).join(" "),
                auth_time: g.auth_time,
                token_aud: g.audience.map(str::to_owned),
                subject: g.subject.clone(),
            },
        )?);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_rfc7636_vector_and_plain() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert!(pkce_matches(challenge, PkceMethod::S256, verifier));
        assert!(!pkce_matches(challenge, PkceMethod::S256, "other"));
        assert!(pkce_matches("abc", PkceMethod::Plain, "abc"));
        assert!(!pkce_matches("abc", PkceMethod::Plain, "abd"));
    }
}
