//! Client authentication for `/token`, `/introspect` and `/revoke`.

use std::sync::Arc;

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::clients::{ResolvedClient, find_client};
use crate::config::{ClientConfig, Endpoint, SigningAlg};
use crate::error::OAuthError;
use crate::jwks_fetch::{FETCH_TIMEOUT, fetch_jwks};
use crate::logging::record_client;
use crate::state::{IssuerCtx, now_secs};

/// The `client_assertion_type` of a JWT client assertion (RFC 7523 2.2).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The `alg` values accepted for a client assertion.
pub const ASSERTION_ALGS: [&str; 3] = ["RS256", "PS256", "ES256"];

/// The client credentials of a request: form fields (the Basic header is read separately).
#[derive(Debug, Clone, Copy, Default)]
pub struct ClientCredentials<'a> {
    pub client_id: Option<&'a str>,
    pub client_secret: Option<&'a str>,
    pub client_assertion_type: Option<&'a str>,
    pub client_assertion: Option<&'a str>,
}

/// How a Client authenticated (RFC 6749 2.3, OpenID Connect Core 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    PrivateKeyJwt,
    None,
}

impl AuthMethod {
    /// The registered name of the method.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::ClientSecretBasic => "client_secret_basic",
            AuthMethod::ClientSecretPost => "client_secret_post",
            AuthMethod::PrivateKeyJwt => "private_key_jwt",
            AuthMethod::None => "none",
        }
    }
}

/// An authenticated Client and the method it used.
#[derive(Debug, Clone)]
pub struct ClientAuth {
    pub client: ResolvedClient,
    pub method: AuthMethod,
}

/// Compares two byte strings without stopping at the first difference.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for (i, byte) in b.iter().enumerate() {
        diff |= a.get(i).copied().unwrap_or(0) ^ byte;
    }
    diff == 0
}

/// Form-urldecodes one part of Basic credentials (RFC 6749 2.3.1).
fn form_decode(part: &str) -> Option<String> {
    let pairs: Vec<(String, String)> =
        serde_urlencoded::from_str(&format!("v={}", part.replace('&', "%26"))).ok()?;
    pairs.into_iter().next().map(|(_, v)| v)
}

/// What the `Authorization` header holds.
enum BasicAuth {
    /// No header, or a scheme other than Basic.
    Absent,
    /// A Basic header that does not decode to `id:secret`.
    Malformed,
    Credentials(String, String),
}

fn basic_credentials(headers: &HeaderMap) -> BasicAuth {
    let Some((scheme, encoded)) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
    else {
        return BasicAuth::Absent;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return BasicAuth::Absent;
    }
    let parsed = (|| {
        let bytes = STANDARD.decode(encoded.trim()).ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let (id, secret) = text.split_once(':')?;
        Some((form_decode(id)?, form_decode(secret)?))
    })();
    match parsed {
        Some((id, secret)) => BasicAuth::Credentials(id, secret),
        None => BasicAuth::Malformed,
    }
}

fn invalid_client(description: &str, basic_auth: bool) -> OAuthError {
    OAuthError::Json {
        error: "invalid_client",
        description: description.to_owned(),
        basic_auth,
    }
}

/// `true` if a Basic header or a form `client_secret` was sent.
fn sent_secret(headers: &HeaderMap, creds: ClientCredentials<'_>) -> bool {
    !matches!(basic_credentials(headers), BasicAuth::Absent)
        || creds.client_secret.is_some_and(|s| !s.is_empty())
}

/// The Lenient stand-in for an unknown Client: a public Client with this id.
fn lenient_client(ctx: &IssuerCtx, client_id: &str) -> ResolvedClient {
    ResolvedClient {
        key: client_id.to_owned(),
        client_id: client_id.to_owned(),
        config: ClientConfig {
            issuer: ctx.id.clone(),
            client_id: Some(client_id.to_owned()),
            ..ClientConfig::default()
        },
        lenient_registered: false,
    }
}

/// Finds and authenticates the Client. `endpoint` is the endpoint called (Token, Introspect or
/// Revoke); its published URL is one accepted assertion `aud`.
pub async fn authenticate_client(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    endpoint: Endpoint,
    creds: ClientCredentials<'_>,
) -> Result<ClientAuth, OAuthError> {
    match creds.client_assertion.filter(|a| !a.is_empty()) {
        Some(assertion) => authenticate_assertion(ctx, headers, endpoint, creds, assertion).await,
        None => authenticate_secret(ctx, headers, creds),
    }
}

/// `client_secret_basic`, `client_secret_post` and `none`.
fn authenticate_secret(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    creds: ClientCredentials<'_>,
) -> Result<ClientAuth, OAuthError> {
    let form_client_id = creds.client_id;
    let form_secret = creds.client_secret.filter(|s| !s.is_empty());
    let (client_id, presented, method) = match basic_credentials(headers) {
        BasicAuth::Credentials(id, secret) => {
            if form_client_id.is_some_and(|f| !f.is_empty() && f != id) {
                tracing::info!(issuer = %ctx.id, "client_id does not match the Basic credentials");
                return Err(invalid_client(
                    "client_id does not match the Basic credentials",
                    true,
                ));
            }
            ctx.enforce(form_secret.is_none(), || {
                "more than one client authentication method".to_owned()
            })
            .map_err(|rule| OAuthError::json("invalid_request", rule))?;
            (id, Some(secret), AuthMethod::ClientSecretBasic)
        }
        BasicAuth::Malformed => return Err(invalid_client("malformed Basic credentials", true)),
        BasicAuth::Absent => {
            let id = form_client_id.unwrap_or_default().to_owned();
            match form_secret {
                Some(secret) => (id, Some(secret.to_owned()), AuthMethod::ClientSecretPost),
                None => (id, None, AuthMethod::None),
            }
        }
    };
    let basic_auth = method == AuthMethod::ClientSecretBasic;
    if client_id.is_empty() {
        return Err(invalid_client(
            "client authentication is required",
            basic_auth,
        ));
    }
    record_client(&client_id);
    let Some(client) = find_client(ctx, &client_id) else {
        ctx.enforce(false, || format!("unknown client_id: {client_id}"))
            .map_err(|rule| invalid_client(&rule, basic_auth))?;
        return Ok(ClientAuth {
            client: lenient_client(ctx, &client_id),
            method,
        });
    };
    let Some(expected) = client.config.client_secret.as_deref() else {
        if client.has_keys() {
            // A `private_key_jwt` Client without a secret must send an assertion.
            ctx.enforce(false, || "client authentication failed".to_owned())
                .map_err(|rule| invalid_client(&rule, basic_auth))?;
            return Ok(ClientAuth { client, method });
        }
        // Public Client: a sent secret is ignored.
        return Ok(ClientAuth {
            client,
            method: AuthMethod::None,
        });
    };
    let ok = method != AuthMethod::None
        && presented
            .as_deref()
            .is_some_and(|p| constant_time_eq(p.as_bytes(), expected.as_bytes()));
    ctx.enforce(ok, || "client authentication failed".to_owned())
        .map_err(|rule| invalid_client(&rule, basic_auth))?;
    Ok(ClientAuth { client, method })
}

/// `private_key_jwt` (RFC 7523 2.2, OpenID Connect Core 9). Every failed check goes through
/// `ctx.enforce`; Lenient mode warns and accepts.
async fn authenticate_assertion(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    endpoint: Endpoint,
    creds: ClientCredentials<'_>,
    assertion: &str,
) -> Result<ClientAuth, OAuthError> {
    let fail = |rule: String| invalid_client(&rule, false);
    ctx.enforce(!sent_secret(headers, creds), || {
        "more than one client authentication method".to_owned()
    })
    .map_err(|rule| OAuthError::json("invalid_request", rule))?;
    ctx.enforce(creds.client_assertion_type == Some(ASSERTION_TYPE), || {
        format!("client_assertion_type must be {ASSERTION_TYPE}")
    })
    .map_err(fail)?;

    let header = jsonwebtoken::decode_header(assertion).ok();
    let unverified =
        jsonwebtoken::dangerous::insecure_decode_claims::<crate::config::Claims>(assertion).ok();
    ctx.enforce(header.is_some() && unverified.is_some(), || {
        "malformed client assertion".to_owned()
    })
    .map_err(fail)?;
    let unverified = unverified.unwrap_or_default();
    let sub = unverified
        .get("sub")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let form_id = creds.client_id.filter(|s| !s.is_empty());
    ctx.enforce(sub.is_some(), || "client assertion has no sub".to_owned())
        .map_err(fail)?;
    if let (Some(sub), Some(form_id)) = (sub, form_id) {
        ctx.enforce(sub == form_id, || {
            "client_id does not match the client assertion sub".to_owned()
        })
        .map_err(fail)?;
    }
    let client_id = sub
        .or(form_id)
        .ok_or_else(|| fail("client authentication is required".to_owned()))?
        .to_owned();
    record_client(&client_id);

    let Some(client) = find_client(ctx, &client_id) else {
        ctx.enforce(false, || format!("unknown client_id: {client_id}"))
            .map_err(fail)?;
        return Ok(ClientAuth {
            client: lenient_client(ctx, &client_id),
            method: AuthMethod::PrivateKeyJwt,
        });
    };

    let verified =
        match verify_assertion(ctx, headers, endpoint, &client, header.as_ref(), assertion).await {
            Ok(claims) => Some(claims),
            Err(rule) => {
                ctx.enforce(false, || rule).map_err(fail)?;
                None
            }
        };
    let claims = verified.as_ref().unwrap_or(&unverified);
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let now = now_secs();
    let exp = claims.get("exp").and_then(Value::as_u64).unwrap_or(now);
    let first_use = jti.is_some_and(|jti| {
        ctx.app
            .store
            .use_assertion_jti(&client.client_id, jti, exp, now)
    });
    ctx.enforce(first_use, || {
        if jti.is_some() {
            "client assertion was already used"
        } else {
            "client assertion has no jti"
        }
        .to_owned()
    })
    .map_err(fail)?;
    Ok(ClientAuth {
        client,
        method: AuthMethod::PrivateKeyJwt,
    })
}

/// The `SigningAlg` of an allowed assertion `alg`.
fn assertion_alg(alg: Algorithm) -> Option<SigningAlg> {
    match alg {
        Algorithm::RS256 => Some(SigningAlg::RS256),
        Algorithm::PS256 => Some(SigningAlg::PS256),
        Algorithm::ES256 => Some(SigningAlg::ES256),
        _ => None,
    }
}

/// `true` if `jwk` can verify `alg`: `kty` `RSA` for RS256 and PS256, `EC` P-256 for ES256,
/// and the JWK `alg`, if set, equals `alg`.
fn key_fits(jwk: &Jwk, alg: SigningAlg) -> bool {
    let kty = match (&jwk.algorithm, alg) {
        (AlgorithmParameters::RSA(_), SigningAlg::RS256 | SigningAlg::PS256) => true,
        (AlgorithmParameters::EllipticCurve(p), SigningAlg::ES256) => {
            p.curve == EllipticCurve::P256
        }
        _ => false,
    };
    kty && jwk
        .common
        .key_algorithm
        .is_none_or(|a| a == KeyAlgorithm::from(alg.jwt()))
}

/// The keys to try: the fitting keys with this `kid`, else every fitting key.
fn candidates<'a>(set: &'a JwkSet, kid: Option<&str>, alg: SigningAlg) -> Vec<&'a Jwk> {
    let fitting: Vec<&Jwk> = set.keys.iter().filter(|k| key_fits(k, alg)).collect();
    if let Some(kid) = kid {
        let by_kid: Vec<&Jwk> = fitting
            .iter()
            .copied()
            .filter(|k| k.common.key_id.as_deref() == Some(kid))
            .collect();
        if !by_kid.is_empty() {
            return by_kid;
        }
    }
    fitting
}

/// Verifies the signature and the claims of a client assertion. Returns the claims, or the
/// failed rule.
async fn verify_assertion(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    endpoint: Endpoint,
    client: &ResolvedClient,
    header: Option<&jsonwebtoken::Header>,
    assertion: &str,
) -> Result<crate::config::Claims, String> {
    let header = header.ok_or_else(|| "malformed client assertion".to_owned())?;
    let alg = assertion_alg(header.alg).ok_or_else(|| {
        format!(
            "client assertion alg {:?} is not allowed (use {})",
            header.alg,
            ASSERTION_ALGS.join(", ")
        )
    })?;
    let kid = header.kid.as_deref();
    let uri = client.config.jwks_uri.as_str();
    // A set fetched by this request is not fetched again for an unknown `kid`.
    let was_cached = !uri.is_empty() && ctx.app.store.cached_jwks(uri, now_secs()).is_some();
    let mut set = client_keys(ctx, client, false).await?;
    if let Some(kid) = kid
        && set.find(kid).is_none()
        && was_cached
    {
        set = client_keys(ctx, client, true).await?;
    }
    let keys = candidates(&set, kid, alg);
    if keys.is_empty() {
        return Err(format!(
            "no key of the client fits the client assertion (alg {})",
            alg.as_str()
        ));
    }
    let audience = [
        ctx.endpoint_url(headers, endpoint),
        ctx.endpoint_url(headers, Endpoint::Token),
        ctx.issuer().issuer_url.clone(),
    ];
    let mut validation = Validation::new(alg.jwt());
    validation.leeway = 0;
    validation.set_issuer(&[&client.client_id]);
    validation.set_audience(&audience);
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    let mut last = "no usable key".to_owned();
    for jwk in keys {
        let key = match DecodingKey::from_jwk(jwk) {
            Ok(key) => key,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        match jsonwebtoken::decode::<crate::config::Claims>(assertion, &key, &validation) {
            Ok(data) => {
                if data.claims.get("sub").and_then(Value::as_str) != Some(&client.client_id) {
                    return Err("client assertion sub must equal the client_id".to_owned());
                }
                return Ok(data.claims);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(format!("client assertion rejected: {last}"))
}

/// Parses an inline Client `jwks` and checks that every key is an RSA key or an EC P-256 key.
pub(crate) fn parse_jwks(jwks: &crate::config::Claims) -> Result<JwkSet, String> {
    let set: JwkSet =
        serde_json::from_value(Value::Object(jwks.clone())).map_err(|e| e.to_string())?;
    for (i, jwk) in set.keys.iter().enumerate() {
        let supported = match &jwk.algorithm {
            AlgorithmParameters::RSA(_) => true,
            AlgorithmParameters::EllipticCurve(p) => p.curve == EllipticCurve::P256,
            _ => false,
        };
        if !supported {
            return Err(format!(
                "keys[{i}] must be an RSA key or an EC P-256 key with all its fields"
            ));
        }
        DecodingKey::from_jwk(jwk).map_err(|e| format!("keys[{i}]: {e}"))?;
    }
    Ok(set)
}

/// The keys of a Client: the inline `jwks`, else the `jwks_uri` set from the cache (60 s) or,
/// when absent, expired or `refetch` is set, fetched again. A failed fetch is not cached.
pub(crate) async fn client_keys(
    ctx: &IssuerCtx,
    client: &ResolvedClient,
    refetch: bool,
) -> Result<JwkSet, String> {
    if let Some(jwks) = &client.config.jwks {
        return parse_jwks(jwks);
    }
    let url = client.config.jwks_uri.as_str();
    if url.is_empty() {
        return Err("client has no jwks or jwks_uri".to_owned());
    }
    let store = &ctx.app.store;
    if !refetch && let Some(set) = store.cached_jwks(url, now_secs()) {
        return Ok((*set).clone());
    }
    let set = fetch_jwks(url, FETCH_TIMEOUT)
        .await
        .map_err(|e| format!("jwks_uri {url}: {e}"))?;
    store.cache_jwks(url, now_secs(), Arc::new(set.clone()));
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_ctx;
    use axum::http::HeaderValue;

    const CFG: &str = r#"[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"
sub_template = "auth0|{user_id}"

[client.example_app]
client_id = "example-app"
client_secret = "local"
redirect_uris = ["http://localhost:3000/api/auth/callback/*"]

[client.spa]
redirect_uris = ["http://localhost:5173/cb"]

[user.alice]
label = "Alice Admin"
claims = { email = "alice@example.com", email_verified = true, given_name = "Alice", family_name = "Admin", name = "Alice Admin", roles = ["admin"] }

[user.bob]
label = "Bobby Viewer"
claims = { email = "bob@example.com", name = "Bobby Viewer" }
"#;

    /// Runs `authenticate_client` at the token endpoint with form credentials.
    fn auth(
        ctx: &IssuerCtx,
        headers: &HeaderMap,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> Result<ClientAuth, OAuthError> {
        let creds = ClientCredentials {
            client_id,
            client_secret,
            ..ClientCredentials::default()
        };
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(authenticate_client(ctx, headers, Endpoint::Token, creds))
    }

    fn basic(id: &str, secret: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        let value = format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&value).unwrap(),
        );
        h
    }

    #[test]
    fn methods_are_detected() {
        let ctx = test_ctx(CFG, "auth0");
        let a = auth(&ctx, &basic("example-app", "local"), None, None).unwrap();
        assert_eq!(
            (a.client.client_id.as_str(), a.method),
            ("example-app", AuthMethod::ClientSecretBasic)
        );
        let a = auth(&ctx, &HeaderMap::new(), Some("example-app"), Some("local")).unwrap();
        assert_eq!(a.method, AuthMethod::ClientSecretPost);
        let a = auth(&ctx, &HeaderMap::new(), Some("spa"), None).unwrap();
        assert_eq!(a.method, AuthMethod::None);
    }

    #[test]
    fn basic_parts_are_form_decoded() {
        assert_eq!(form_decode("a%3Ab+c").as_deref(), Some("a:b c"));
        assert_eq!(form_decode("a&b").as_deref(), Some("a&b"));
    }

    #[test]
    fn constant_time_eq_handles_lengths() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
    }

    #[test]
    fn method_names() {
        assert_eq!(
            AuthMethod::ClientSecretBasic.as_str(),
            "client_secret_basic"
        );
        assert_eq!(AuthMethod::ClientSecretPost.as_str(), "client_secret_post");
        assert_eq!(AuthMethod::PrivateKeyJwt.as_str(), "private_key_jwt");
        assert_eq!(AuthMethod::None.as_str(), "none");
    }

    #[test]
    fn confidential_client_with_none_fails() {
        let ctx = test_ctx(CFG, "auth0");
        let e = auth(&ctx, &HeaderMap::new(), Some("example-app"), None).unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "invalid_client",
                ..
            }
        ));
    }

    #[test]
    fn two_methods_is_invalid_request_in_strict_only() {
        let e = auth(
            &test_ctx(CFG, "auth0"),
            &basic("example-app", "local"),
            None,
            Some("local"),
        )
        .unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "invalid_request",
                ..
            }
        ));
        let lenient = test_ctx(
            &CFG.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n"),
            "auth0",
        );
        assert!(
            auth(
                &lenient,
                &basic("example-app", "local"),
                None,
                Some("local")
            )
            .is_ok()
        );
    }

    #[test]
    fn basic_id_must_match_form_client_id() {
        let e = auth(
            &test_ctx(CFG, "auth0"),
            &basic("example-app", "local"),
            Some("spa"),
            None,
        )
        .unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "invalid_client",
                ..
            }
        ));
    }

    #[test]
    fn unknown_client_is_synthesized_in_lenient_only() {
        let strict = test_ctx(CFG, "auth0");
        assert!(auth(&strict, &HeaderMap::new(), Some("nope"), None).is_err());
        let lenient = test_ctx(
            &CFG.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n"),
            "auth0",
        );
        let a = auth(&lenient, &HeaderMap::new(), Some("nope"), None).unwrap();
        assert!(a.client.is_public());
        assert_eq!(a.client.config.issuer, "auth0");
    }

    #[test]
    fn key_fits_checks_kty_curve_and_alg() {
        let set: JwkSet = serde_json::from_value(serde_json::json!({"keys": [
            {"kty": "RSA", "alg": "RS256", "kid": "r", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "any", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "crv": "P-256", "kid": "e", "x": "AQAB", "y": "AQAB"},
            {"kty": "oct", "kid": "h", "k": "c2VjcmV0"},
        ]}))
        .unwrap();
        let kids = |kid, alg| -> Vec<String> {
            candidates(&set, kid, alg)
                .iter()
                .map(|k| k.common.key_id.clone().unwrap())
                .collect()
        };
        assert_eq!(kids(None, SigningAlg::PS256), vec!["any"]);
        assert_eq!(kids(Some("r"), SigningAlg::RS256), vec!["r"]);
        assert_eq!(kids(Some("e"), SigningAlg::RS256), vec!["r", "any"]);
        assert_eq!(kids(Some("h"), SigningAlg::ES256), vec!["e"]);
        assert!(assertion_alg(Algorithm::HS256).is_none());
    }

    #[test]
    fn require_grant_checks_grant_types() {
        let ctx = test_ctx(
            &CFG.replace(
                "client_secret = \"local\"\n",
                "client_secret = \"local\"\ngrant_types = [\"client_credentials\"]\n",
            ),
            "auth0",
        );
        let c = find_client(&ctx, "example-app").unwrap();
        let e = crate::token_endpoint::require_grant(&ctx, &c, "authorization_code").unwrap_err();
        assert!(matches!(
            e,
            OAuthError::Json {
                error: "unauthorized_client",
                ..
            }
        ));
        assert!(crate::token_endpoint::require_grant(&ctx, &c, "client_credentials").is_ok());
    }
}
