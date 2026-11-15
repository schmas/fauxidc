//! Decodes tokens this Issuer signed, for `/revoke` and `/introspect`.

use crate::config::Claims;
use crate::keys::SigningKey;
use crate::refresh::{REFRESH_TOKEN_TYP, RefreshClaims, verify_refresh_token};
use crate::tokens::verify_access_token;

/// A valid, unexpired token of this Issuer.
// A short-lived value on one request; boxing the refresh claims buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum OwnToken {
    /// An access token (`typ: at+jwt`).
    Access(Claims),
    /// A refresh token (`typ: rt+jwt`).
    Refresh(RefreshClaims),
}

impl OwnToken {
    /// The `jti` claim (empty if an access token has none).
    pub fn jti(&self) -> &str {
        match self {
            OwnToken::Access(c) => c.get("jti").and_then(|v| v.as_str()).unwrap_or_default(),
            OwnToken::Refresh(c) => &c.jti,
        }
    }

    /// The `exp` claim.
    pub fn exp(&self) -> u64 {
        match self {
            OwnToken::Access(c) => c
                .get("exp")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            OwnToken::Refresh(c) => c.exp,
        }
    }

    /// The `client_id` claim (empty if an access token has none).
    pub fn client_id(&self) -> &str {
        match self {
            OwnToken::Access(c) => c
                .get("client_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            OwnToken::Refresh(c) => &c.client_id,
        }
    }
}

/// A token this Issuer signed and that has not expired: an access token (`typ: at+jwt`, via
/// `verify_access_token`) or a refresh token (`typ: rt+jwt`, via `verify_refresh_token`).
/// Anything else, including ID tokens, is `None`.
pub fn decode_own_token(key: &SigningKey, issuer_url: &str, token: &str) -> Option<OwnToken> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if header.typ.as_deref() == Some(REFRESH_TOKEN_TYP) {
        verify_refresh_token(key, issuer_url, token)
            .ok()
            .map(OwnToken::Refresh)
    } else {
        verify_access_token(key, issuer_url, token)
            .ok()
            .map(OwnToken::Access)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh::sign_refresh_token;
    use crate::state::{Subject, now_secs};
    use crate::tokens::{AccessTokenInput, IdTokenInput, sign_access_token, sign_id_token};

    const ISS: &str = "http://localhost:9000/auth0/";

    fn key() -> SigningKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| SigningKey::generate().unwrap()).clone()
    }

    #[test]
    fn decodes_access_and_refresh_but_not_id_tokens() {
        let at = sign_access_token(
            &key(),
            AccessTokenInput {
                issuer_url: ISS,
                client_id: "example-app",
                audience: "example-app",
                claims: Claims::new(),
                scope: &[],
                auth_time: Some(1),
                lifetime: 60,
            },
        )
        .unwrap();
        let t = decode_own_token(&key(), ISS, &at).unwrap();
        assert!(matches!(t, OwnToken::Access(_)));
        assert_eq!(t.client_id(), "example-app");
        assert!(!t.jti().is_empty() && t.exp() > now_secs());

        let rt = sign_refresh_token(
            &key(),
            &RefreshClaims {
                iss: ISS.into(),
                aud: "example-app".into(),
                client_id: "example-app".into(),
                sub: "auth0|alice".into(),
                jti: "j-1".into(),
                iat: now_secs(),
                exp: now_secs() + 60,
                scope: "openid offline_access".into(),
                auth_time: 1,
                token_aud: None,
                subject: Subject::Custom {
                    sub: "c".into(),
                    claims: Claims::new(),
                },
            },
        )
        .unwrap();
        let t = decode_own_token(&key(), ISS, &rt).unwrap();
        assert!(matches!(t, OwnToken::Refresh(_)));
        assert_eq!((t.jti(), t.client_id()), ("j-1", "example-app"));

        let idt = sign_id_token(
            &key(),
            IdTokenInput {
                issuer_url: ISS,
                client_id: "example-app",
                claims: Claims::new(),
                auth_time: 1,
                nonce: None,
                lifetime: 60,
            },
        )
        .unwrap();
        assert!(decode_own_token(&key(), ISS, &idt).is_none());
        assert!(decode_own_token(&key(), ISS, "abc").is_none());
        assert!(decode_own_token(&key(), "http://localhost:9000/okta/", &at).is_none());
    }
}
