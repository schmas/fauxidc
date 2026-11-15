//! ID token and RFC 9068 access token signing, plus access token verification.

use jsonwebtoken::{Algorithm, Header, Validation};
use serde_json::{Value, json};

use crate::config::Claims;
use crate::error::OAuthError;
use crate::keys::SigningKey;
use crate::state::now_secs;

/// Inputs for an ID token. `claims` holds the already merged and filtered user claims.
pub struct IdTokenInput<'a> {
    pub issuer_url: &'a str,
    pub client_id: &'a str,
    pub claims: Claims,
    pub auth_time: u64,
    pub nonce: Option<&'a str>,
    pub lifetime: i64,
}

/// Inputs for an RFC 9068 access token.
pub struct AccessTokenInput<'a> {
    pub issuer_url: &'a str,
    pub client_id: &'a str,
    pub audience: &'a str,
    pub claims: Claims,
    pub scope: &'a [String],
    /// The `auth_time` claim; `None` (for `client_credentials`) omits it.
    pub auth_time: Option<u64>,
    pub lifetime: i64,
}

/// A configured lifetime in seconds as the signed value the signers take.
pub fn lifetime_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

const ACCESS_TOKEN_TYP: &str = "at+jwt";

fn sign(key: &SigningKey, typ: &str, claims: &Claims) -> Result<String, OAuthError> {
    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some(typ.to_owned());
    header.kid = Some(key.kid.clone());
    jsonwebtoken::encode(&header, claims, &key.encoding)
        .map_err(|e| OAuthError::json("server_error", format!("token signing failed: {e}")))
}

/// Set the protocol claims last so they always win over the user claims.
fn set_protocol(claims: &mut Claims, pairs: Vec<(&str, Value)>) {
    for (name, value) in pairs {
        claims.insert(name.to_owned(), value);
    }
}

/// Sign an ID token (`typ: JWT`).
pub fn sign_id_token(key: &SigningKey, input: IdTokenInput<'_>) -> Result<String, OAuthError> {
    let now = now_secs();
    let mut claims = input.claims;
    let mut protocol = vec![
        ("iss", json!(input.issuer_url)),
        ("aud", json!(input.client_id)),
        ("azp", json!(input.client_id)),
        ("iat", json!(now)),
        ("exp", json!(now.saturating_add_signed(input.lifetime))),
        ("auth_time", json!(input.auth_time)),
        ("jti", json!(uuid::Uuid::new_v4().to_string())),
    ];
    if let Some(nonce) = input.nonce {
        protocol.push(("nonce", json!(nonce)));
    }
    set_protocol(&mut claims, protocol);
    sign(key, "JWT", &claims)
}

/// Sign an access token (`typ: at+jwt`, RFC 9068). An empty scope omits the `scope` claim.
pub fn sign_access_token(
    key: &SigningKey,
    input: AccessTokenInput<'_>,
) -> Result<String, OAuthError> {
    let now = now_secs();
    let mut claims = input.claims;
    let mut protocol = vec![
        ("iss", json!(input.issuer_url)),
        ("aud", json!(input.audience)),
        ("client_id", json!(input.client_id)),
        ("iat", json!(now)),
        ("exp", json!(now.saturating_add_signed(input.lifetime))),
        ("jti", json!(uuid::Uuid::new_v4().to_string())),
    ];
    if !input.scope.is_empty() {
        protocol.push(("scope", json!(input.scope.join(" "))));
    }
    if let Some(auth_time) = input.auth_time {
        protocol.push(("auth_time", json!(auth_time)));
    }
    set_protocol(&mut claims, protocol);
    sign(key, ACCESS_TOKEN_TYP, &claims)
}

/// Verify an access token: RS256, `typ: at+jwt`, `iss` and `exp`. The audience is not checked.
pub fn verify_access_token(
    key: &SigningKey,
    issuer_url: &str,
    token: &str,
) -> Result<Claims, OAuthError> {
    let bearer = |description: &str| OAuthError::Bearer {
        description: description.to_owned(),
    };
    let header = jsonwebtoken::decode_header(token).map_err(|_| bearer("malformed token"))?;
    if header.typ.as_deref() != Some(ACCESS_TOKEN_TYP) {
        return Err(bearer("not an access token"));
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.validate_aud = false;
    validation.set_issuer(&[issuer_url]);
    validation.set_required_spec_claims(&["exp", "iss"]);
    jsonwebtoken::decode::<Claims>(token, &key.decoding, &validation)
        .map(|data| data.claims)
        .map_err(|e| bearer(&e.to_string()))
}

/// Verify an `id_token_hint` (RP-Initiated Logout 1.0 section 2): RS256, header `typ` = `JWT`,
/// `iss` = `issuer_url`. `exp` is NOT checked: an expired hint is accepted.
pub fn verify_id_token_hint(
    key: &SigningKey,
    issuer_url: &str,
    token: &str,
) -> Result<Claims, OAuthError> {
    let invalid =
        |d: &str| OAuthError::json("invalid_request", format!("id_token_hint is invalid: {d}"));
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid("malformed token"))?;
    if header.typ.as_deref() != Some("JWT") {
        return Err(invalid("not an id_token"));
    }
    let mut validation = Validation::new(Algorithm::RS256);
    validation.leeway = 0;
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.set_issuer(&[issuer_url]);
    validation.set_required_spec_claims(&["iss"]);
    jsonwebtoken::decode::<Claims>(token, &key.decoding, &validation)
        .map(|data| data.claims)
        .map_err(|e| invalid(&e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde_json::{Value, json};

    fn key() -> SigningKey {
        use std::sync::OnceLock;
        static KEY: OnceLock<SigningKey> = OnceLock::new();
        KEY.get_or_init(|| SigningKey::generate().unwrap()).clone()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn obj(v: Value) -> Claims {
        v.as_object().unwrap().clone()
    }

    fn decode_unverified(t: &str) -> (Value, Value) {
        let mut parts = t.split('.');
        let mut part = || {
            let bytes = URL_SAFE_NO_PAD.decode(parts.next().unwrap()).unwrap();
            serde_json::from_slice::<Value>(&bytes).unwrap()
        };
        (part(), part())
    }

    fn id_input(issuer: &str) -> IdTokenInput<'_> {
        IdTokenInput {
            issuer_url: issuer,
            client_id: "example-app",
            claims: obj(json!({"sub": "alice"})),
            auth_time: 1,
            nonce: None,
            lifetime: 60,
        }
    }

    fn access_input(issuer: &str) -> AccessTokenInput<'_> {
        AccessTokenInput {
            issuer_url: issuer,
            client_id: "example-app",
            audience: "https://api.example.com",
            claims: obj(json!({"sub": "alice"})),
            scope: &[],
            auth_time: Some(1),
            lifetime: 60,
        }
    }

    #[test]
    fn id_token_has_protocol_claims() {
        let t = sign_id_token(
            &key(),
            IdTokenInput {
                issuer_url: "http://localhost:9000/auth0/",
                client_id: "example-app",
                claims: obj(json!({"sub": "auth0|alice"})),
                auth_time: 100,
                nonce: Some("n1"),
                lifetime: 3600,
            },
        )
        .unwrap();
        let (h, c) = decode_unverified(&t);
        assert_eq!(h["typ"], "JWT");
        assert_eq!(h["kid"], key().kid.as_str());
        assert_eq!(c["iss"], "http://localhost:9000/auth0/");
        assert_eq!(c["aud"], "example-app");
        assert_eq!(c["azp"], "example-app");
        assert_eq!(c["nonce"], "n1");
        assert_eq!(c["auth_time"], 100);
        assert_eq!(
            c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(),
            3600
        );
    }

    #[test]
    fn access_token_rfc9068_round_trip() {
        let t = sign_access_token(
            &key(),
            AccessTokenInput {
                issuer_url: "http://h/a",
                client_id: "example-app",
                audience: "https://api.example.com",
                claims: obj(json!({"sub": "alice", "email": "alice@example.com"})),
                scope: &["openid".into(), "email".into()],
                auth_time: Some(1),
                lifetime: 60,
            },
        )
        .unwrap();
        let (h, _) = decode_unverified(&t);
        assert_eq!(h["typ"], "at+jwt");
        let c = verify_access_token(&key(), "http://h/a", &t).unwrap();
        assert_eq!(c["aud"], "https://api.example.com");
        assert_eq!(c["scope"], "openid email");
        assert_eq!(c["client_id"], "example-app");
    }

    #[test]
    fn verify_rejects_other_issuer_and_id_tokens() {
        let at = sign_access_token(&key(), access_input("http://h/a")).unwrap();
        assert!(verify_access_token(&key(), "http://h/b", &at).is_err());
        let idt = sign_id_token(&key(), id_input("http://h/a")).unwrap();
        assert!(verify_access_token(&key(), "http://h/a", &idt).is_err());
    }

    #[test]
    fn id_token_hint_accepts_expired_and_rejects_access_tokens() {
        let mut i = id_input("http://h/a");
        i.lifetime = 0;
        let t = sign_id_token(&key(), i).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let c = verify_id_token_hint(&key(), "http://h/a", &t).unwrap();
        assert_eq!(c["aud"], "example-app");
        assert!(verify_id_token_hint(&key(), "http://h/b", &t).is_err());
        let at = sign_access_token(&key(), access_input("http://h/a")).unwrap();
        assert!(verify_id_token_hint(&key(), "http://h/a", &at).is_err());
    }

    #[test]
    fn verify_rejects_expired() {
        let mut i = access_input("http://h/a");
        i.lifetime = 0;
        let t = sign_access_token(&key(), i).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(verify_access_token(&key(), "http://h/a", &t).is_err());
    }
}
