//! ID token and RFC 9068 access token signing, plus access token verification.

use jsonwebtoken::Header;
use serde_json::{Value, json};

use crate::config::Claims;
use crate::error::OAuthError;
use crate::keys::{KeySet, SigningKey};

/// Inputs for an ID token. `claims` holds the already merged and filtered user claims.
pub struct IdTokenInput<'a> {
    pub issuer_url: &'a str,
    pub client_id: &'a str,
    pub claims: Claims,
    pub auth_time: u64,
    pub nonce: Option<&'a str>,
    /// The `iat` claim: the server clock (ADR 0007). `exp` is `now + lifetime`.
    pub now: u64,
    pub lifetime: i64,
    /// The Session `sid` claim; `None` omits it.
    pub sid: Option<&'a str>,
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
    /// The `iat` claim: the server clock (ADR 0007). `exp` is `now + lifetime`.
    pub now: u64,
    pub lifetime: i64,
}

/// A configured lifetime in seconds as the signed value the signers take.
pub fn lifetime_secs(secs: u64) -> i64 {
    i64::try_from(secs).unwrap_or(i64::MAX)
}

const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// Runs `f` on the tokio blocking pool. RSA signing takes about 2 ms of CPU, so signing on
/// the `current_thread` runtime would limit the server to one core and block other requests.
/// On the blocking pool, signatures run in parallel on all cores (ADR 0005).
pub(crate) async fn on_blocking_pool<R, F>(f: F) -> Result<R, OAuthError>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| OAuthError::ServerError(format!("signing task failed: {e}")))
}

/// Signs `claims` with `key` on the blocking pool. The key is cloned (about 1 KB) because the
/// task needs owned data. The error is the failure text.
pub(crate) async fn sign_jwt<T>(key: &SigningKey, typ: &str, claims: T) -> Result<String, String>
where
    T: serde::Serialize + Send + 'static,
{
    let mut header = Header::new(key.alg.jwt());
    header.typ = Some(typ.to_owned());
    header.kid = Some(key.kid.clone());
    let encoding = key.encoding.clone();
    on_blocking_pool(move || jsonwebtoken::encode(&header, &claims, &encoding))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

async fn sign(key: &SigningKey, typ: &str, claims: Claims) -> Result<String, OAuthError> {
    sign_jwt(key, typ, claims)
        .await
        .map_err(|e| OAuthError::json("server_error", format!("token signing failed: {e}")))
}

/// Set the protocol claims last so they always win over the user claims.
fn set_protocol(claims: &mut Claims, pairs: Vec<(&str, Value)>) {
    for (name, value) in pairs {
        claims.insert(name.to_owned(), value);
    }
}

/// Sign an ID token (`typ: JWT`).
pub async fn sign_id_token(
    key: &SigningKey,
    input: IdTokenInput<'_>,
) -> Result<String, OAuthError> {
    let now = input.now;
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
    if let Some(sid) = input.sid {
        protocol.push(("sid", json!(sid)));
    }
    set_protocol(&mut claims, protocol);
    sign(key, "JWT", claims).await
}

/// Sign an access token (`typ: at+jwt`, RFC 9068). An empty scope omits the `scope` claim.
pub async fn sign_access_token(
    key: &SigningKey,
    input: AccessTokenInput<'_>,
) -> Result<String, OAuthError> {
    let now = input.now;
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
    sign(key, ACCESS_TOKEN_TYP, claims).await
}

/// Verify an access token: a key of `keys` (by `kid`, `alg` must match), `typ: at+jwt`, `iss`
/// and `exp` against `now`. The audience is not checked.
pub fn verify_access_token(
    keys: &KeySet,
    issuer_url: &str,
    token: &str,
    now: u64,
) -> Result<Claims, OAuthError> {
    let bearer = |description: &str| OAuthError::Bearer {
        description: description.to_owned(),
    };
    let header = jsonwebtoken::decode_header(token).map_err(|_| bearer("malformed token"))?;
    if header.typ.as_deref() != Some(ACCESS_TOKEN_TYP) {
        return Err(bearer("not an access token"));
    }
    keys.verify(token, now, |v| {
        v.leeway = 0;
        v.validate_aud = false;
        v.set_issuer(&[issuer_url]);
        v.set_required_spec_claims(&["exp", "iss"]);
    })
    .map(|(_, claims)| claims)
    .map_err(|e| bearer(&e))
}

/// Verify an `id_token_hint` (RP-Initiated Logout 1.0 section 2): a key of `keys`, header
/// `typ` = `JWT`, `iss` = `issuer_url`. `exp` is NOT checked: an expired hint is accepted.
pub fn verify_id_token_hint(
    keys: &KeySet,
    issuer_url: &str,
    token: &str,
) -> Result<Claims, OAuthError> {
    let invalid =
        |d: &str| OAuthError::json("invalid_request", format!("id_token_hint is invalid: {d}"));
    let header = jsonwebtoken::decode_header(token).map_err(|_| invalid("malformed token"))?;
    if header.typ.as_deref() != Some("JWT") {
        return Err(invalid("not an id_token"));
    }
    // `exp` is not checked, so the time does not matter.
    keys.verify(token, 0, |v| {
        v.leeway = 0;
        v.validate_exp = false;
        v.validate_aud = false;
        v.set_issuer(&[issuer_url]);
        v.set_required_spec_claims(&["iss"]);
    })
    .map(|(_, claims)| claims)
    .map_err(|e| invalid(&e))
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

    fn set() -> crate::keys::KeySet {
        crate::keys::KeySet::single(std::sync::Arc::new(key()))
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
            now: 1000,
            lifetime: 60,
            sid: None,
        }
    }

    #[tokio::test]
    async fn signing_runs_on_the_blocking_pool_not_the_caller_thread() {
        let caller = std::thread::current().id();
        let worker = on_blocking_pool(|| std::thread::current().id())
            .await
            .unwrap();
        assert_ne!(caller, worker);
    }

    fn access_input(issuer: &str) -> AccessTokenInput<'_> {
        AccessTokenInput {
            issuer_url: issuer,
            client_id: "example-app",
            audience: "https://api.example.com",
            claims: obj(json!({"sub": "alice"})),
            scope: &[],
            auth_time: Some(1),
            now: 1000,
            lifetime: 60,
        }
    }

    #[tokio::test]
    async fn id_token_has_protocol_claims() {
        let t = sign_id_token(
            &key(),
            IdTokenInput {
                issuer_url: "http://localhost:9000/auth0/",
                client_id: "example-app",
                claims: obj(json!({"sub": "auth0|alice", "sid": "user-value"})),
                auth_time: 100,
                nonce: Some("n1"),
                now: 1000,
                lifetime: 3600,
                sid: Some("s-1"),
            },
        )
        .await
        .unwrap();
        let (h, c) = decode_unverified(&t);
        assert_eq!(h["typ"], "JWT");
        assert_eq!(h["kid"], key().kid.as_str());
        assert_eq!(c["iss"], "http://localhost:9000/auth0/");
        assert_eq!(c["aud"], "example-app");
        assert_eq!(c["azp"], "example-app");
        assert_eq!(c["nonce"], "n1");
        assert_eq!(c["auth_time"], 100);
        assert_eq!(c["sid"], "s-1");
        assert_eq!(c["iat"], 1000);
        assert_eq!(c["exp"], 4600);
    }

    #[tokio::test]
    async fn id_token_header_alg_follows_key() {
        let k = SigningKey::generate_for(crate::config::SigningAlg::ES256).unwrap();
        let t = sign_id_token(&k, id_input("http://h/a")).await.unwrap();
        let (h, _) = decode_unverified(&t);
        assert_eq!(h["alg"], "ES256");
        assert_eq!(h["kid"], k.kid.as_str());
    }

    #[tokio::test]
    async fn access_token_rfc9068_round_trip() {
        let t = sign_access_token(
            &key(),
            AccessTokenInput {
                issuer_url: "http://h/a",
                client_id: "example-app",
                audience: "https://api.example.com",
                claims: obj(json!({"sub": "alice", "email": "alice@example.com"})),
                scope: &["openid".into(), "email".into()],
                auth_time: Some(1),
                now: 1000,
                lifetime: 60,
            },
        )
        .await
        .unwrap();
        let (h, _) = decode_unverified(&t);
        assert_eq!(h["typ"], "at+jwt");
        let c = verify_access_token(&set(), "http://h/a", &t, 1000).unwrap();
        assert_eq!(c["aud"], "https://api.example.com");
        assert_eq!(c["scope"], "openid email");
        assert_eq!(c["client_id"], "example-app");
    }

    #[tokio::test]
    async fn verify_rejects_other_issuer_and_id_tokens() {
        let at = sign_access_token(&key(), access_input("http://h/a"))
            .await
            .unwrap();
        assert!(verify_access_token(&set(), "http://h/b", &at, 1000).is_err());
        let idt = sign_id_token(&key(), id_input("http://h/a")).await.unwrap();
        assert!(verify_access_token(&set(), "http://h/a", &idt, 1000).is_err());
    }

    #[tokio::test]
    async fn id_token_hint_accepts_expired_and_rejects_access_tokens() {
        let mut i = id_input("http://h/a");
        i.lifetime = 0;
        let t = sign_id_token(&key(), i).await.unwrap();
        let c = verify_id_token_hint(&set(), "http://h/a", &t).unwrap();
        assert_eq!(c["aud"], "example-app");
        assert!(verify_id_token_hint(&set(), "http://h/b", &t).is_err());
        let at = sign_access_token(&key(), access_input("http://h/a"))
            .await
            .unwrap();
        assert!(verify_id_token_hint(&set(), "http://h/a", &at).is_err());
    }

    #[tokio::test]
    async fn verify_rejects_expired() {
        let mut i = access_input("http://h/a");
        i.lifetime = 0;
        let t = sign_access_token(&key(), i).await.unwrap();
        assert!(verify_access_token(&set(), "http://h/a", &t, 1000).is_ok());
        assert!(verify_access_token(&set(), "http://h/a", &t, 1001).is_err());
    }
}
