//! The refresh token format (`typ: rt+jwt`) and the `refresh_token` grant.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client_auth::{ClientAuth, authenticate_client};
use crate::config::Endpoint;
use crate::error::OAuthError;
use crate::keys::{KeySet, SigningKey};
use crate::state::{IssuerCtx, Subject};
use crate::token_endpoint::{RefreshMode, TokenForm, UserGrant, issue_user_tokens, require_grant};

/// The JWT header `typ` of a refresh token.
pub const REFRESH_TOKEN_TYP: &str = "rt+jwt";

/// The claims of a refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub iss: String,
    /// The `client_id`.
    pub aud: String,
    pub client_id: String,
    /// The merged `sub` at issue time (for `/introspect`).
    pub sub: String,
    /// UUID v4.
    pub jti: String,
    pub iat: u64,
    pub exp: u64,
    /// The space-separated granted scope.
    pub scope: String,
    pub auth_time: u64,
    /// The access token audience requested at `/authorize`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_aud: Option<String>,
    /// User id + Claim overrides, or Custom user sub + claims (spec 9).
    pub subject: Subject,
}

/// Signs a refresh token (the key's `alg`, `typ: rt+jwt`).
pub async fn sign_refresh_token(
    key: &SigningKey,
    claims: &RefreshClaims,
) -> Result<String, OAuthError> {
    crate::tokens::sign_jwt(key, REFRESH_TOKEN_TYP, claims.clone())
        .await
        .map_err(|e| OAuthError::ServerError(format!("token signing failed: {e}")))
}

/// A key of `keys` (by `kid`, `alg` must match), header `typ` must be `rt+jwt`, `iss` must equal
/// `issuer_url`, `exp` checked against `now` with leeway 0. Every failure is
/// `OAuthError::json("invalid_grant", ..)`.
pub fn verify_refresh_token(
    keys: &KeySet,
    issuer_url: &str,
    token: &str,
    now: u64,
) -> Result<RefreshClaims, OAuthError> {
    let invalid =
        |d: &str| OAuthError::json("invalid_grant", format!("invalid refresh token: {d}"));
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid("malformed token"))?;
    if header.typ.as_deref() != Some(REFRESH_TOKEN_TYP) {
        return Err(invalid("not a refresh token"));
    }
    let (_, claims) = keys
        .verify(token, now, |v| {
            v.leeway = 0;
            v.validate_aud = false;
            v.set_issuer(&[issuer_url]);
            v.set_required_spec_claims(&["exp", "iss"]);
        })
        .map_err(|e| invalid(&e))?;
    serde_json::from_value(Value::Object(claims)).map_err(|e| invalid(&e.to_string()))
}

/// The `refresh_token` grant: verifies the refresh token, applies rotation and the reuse
/// check, and issues new tokens with claims merged again from the current config (spec 9).
pub async fn refresh_grant(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    let ClientAuth { client, .. } =
        authenticate_client(ctx, headers, Endpoint::Token, f.credentials()).await?;
    require_grant(ctx, &client, "refresh_token")?;
    let presented = f
        .refresh_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .ok_or_else(|| OAuthError::json("invalid_request", "refresh_token is missing"))?;
    let invalid_grant = |d: String| {
        tracing::info!(issuer = %ctx.id, "{d}");
        OAuthError::json("invalid_grant", d)
    };
    let keys = ctx.keys().await?;
    let now = ctx.app.now();
    let claims = verify_refresh_token(&keys, &ctx.issuer_url(headers), presented, now)
        .inspect_err(|e| tracing::info!(issuer = %ctx.id, "refresh token rejected: {e}"))?;
    if claims.client_id != client.client_id {
        return Err(invalid_grant(
            "refresh token was not issued to this client".to_owned(),
        ));
    }
    if ctx.app.store.is_revoked(&claims.jti, now) {
        return Err(invalid_grant("refresh token was revoked".to_owned()));
    }
    let original: Vec<String> = claims.scope.split_whitespace().map(str::to_owned).collect();
    let scope = match f.scope.as_deref().filter(|s| !s.trim().is_empty()) {
        Some(requested) => {
            let requested: Vec<String> = requested.split_whitespace().map(str::to_owned).collect();
            let wider: Vec<&str> = requested
                .iter()
                .filter(|s| !original.contains(s))
                .map(String::as_str)
                .collect();
            ctx.enforce(wider.is_empty(), || {
                format!("scope exceeds the original grant: {}", wider.join(" "))
            })
            .map_err(|rule| OAuthError::json("invalid_scope", rule))?;
            requested
        }
        None => original.clone(),
    };
    if let Subject::User { id, .. } = &claims.subject
        && !ctx.app.config.user.contains_key(id)
    {
        return Err(invalid_grant(format!("user no longer exists: {id}")));
    }
    let refresh = if client.config.rotate_refresh_tokens {
        let fresh = ctx.app.store.use_refresh_jti(
            &claims.jti,
            claims.exp,
            now,
            client.config.refresh_reuse_leeway_secs,
        );
        if !fresh {
            return Err(invalid_grant("refresh token was already used".to_owned()));
        }
        RefreshMode::Issue
    } else {
        RefreshMode::Echo(presented.to_owned())
    };
    issue_user_tokens(
        ctx,
        &keys.active,
        &UserGrant {
            iss: &ctx.issuer_url(headers),
            client: &client,
            subject: &claims.subject,
            scope: &scope,
            audience: claims.token_aud.as_deref(),
            auth_time: claims.auth_time,
            sid: None,
            nonce: None,
            refresh,
            refresh_scope: Some(&original),
            expires_in: None,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Claims;
    use crate::state::Subject;
    use crate::tokens::{AccessTokenInput, sign_access_token};

    const ISS: &str = "http://localhost:9000/auth0/";

    fn key() -> SigningKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| SigningKey::generate().unwrap()).clone()
    }

    fn set() -> crate::keys::KeySet {
        crate::keys::KeySet::single(std::sync::Arc::new(key()))
    }

    fn claims(exp: u64) -> RefreshClaims {
        RefreshClaims {
            iss: ISS.into(),
            aud: "example-app".into(),
            client_id: "example-app".into(),
            sub: "auth0|alice".into(),
            jti: "j-1".into(),
            iat: 1000,
            exp,
            scope: "openid offline_access".into(),
            auth_time: 100,
            token_aud: Some("https://api.example.com".into()),
            subject: Subject::User {
                id: "alice".into(),
                overrides: Claims::new(),
            },
        }
    }

    #[tokio::test]
    async fn es256_refresh_token_round_trip() {
        let k = std::sync::Arc::new(
            SigningKey::generate_for(crate::config::SigningAlg::ES256).unwrap(),
        );
        let t = sign_refresh_token(&k, &claims(1060)).await.unwrap();
        let header = jsonwebtoken::decode_header(&t).unwrap();
        assert_eq!(header.alg, jsonwebtoken::Algorithm::ES256);
        let set = crate::keys::KeySet::single(k);
        assert_eq!(
            verify_refresh_token(&set, ISS, &t, 1000).unwrap().jti,
            "j-1"
        );
    }

    #[tokio::test]
    async fn sign_verify_round_trip() {
        let t = sign_refresh_token(&key(), &claims(1060)).await.unwrap();
        let c = verify_refresh_token(&set(), ISS, &t, 1000).unwrap();
        assert_eq!(c.jti, "j-1");
        assert_eq!(c.token_aud.as_deref(), Some("https://api.example.com"));
        assert!(matches!(c.subject, Subject::User { ref id, .. } if id == "alice"));
    }

    #[tokio::test]
    async fn verify_rejects_other_issuer() {
        let t = sign_refresh_token(&key(), &claims(1060)).await.unwrap();
        let e = verify_refresh_token(&set(), "http://localhost:9000/okta/", &t, 1000).unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "invalid_grant",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn verify_rejects_access_token() {
        let at = sign_access_token(
            &key(),
            AccessTokenInput {
                issuer_url: ISS,
                client_id: "example-app",
                audience: "example-app",
                claims: Claims::new(),
                scope: &[],
                auth_time: Some(1),
                now: 1000,
                lifetime: 60,
            },
        )
        .await
        .unwrap();
        let e = verify_refresh_token(&set(), ISS, &at, 1000).unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "invalid_grant",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn verify_rejects_expired() {
        let t = sign_refresh_token(&key(), &claims(999)).await.unwrap();
        let e = verify_refresh_token(&set(), ISS, &t, 1000).unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "invalid_grant",
                ..
            }
        ));
    }
}
