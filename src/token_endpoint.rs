//! The token endpoint: `authorization_code` grant.

use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::claims::{ClaimTarget, build_claims, filter_by_scope};
use crate::clients::{ResolvedClient, find_client};
use crate::config::ClientConfig;
use crate::error::OAuthError;
use crate::logging::{record_client, record_endpoint};
use crate::state::{IssuerCtx, PkceMethod, now_secs};
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
}

/// Compares two byte strings without stopping at the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
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

/// Finds and authenticates the client of a token request.
fn authenticate(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<ResolvedClient, OAuthError> {
    let (client_id, presented, basic_auth) = match basic_credentials(headers) {
        BasicAuth::Credentials(id, secret) => (id, Some(secret), true),
        BasicAuth::Malformed => return Err(invalid_client("malformed Basic credentials", true)),
        BasicAuth::Absent => (
            f.client_id.clone().unwrap_or_default(),
            f.client_secret.clone(),
            false,
        ),
    };
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
        // Lenient: treat the unknown client as a public client with this id.
        return Ok(ResolvedClient {
            key: client_id.clone(),
            client_id: client_id.clone(),
            config: ClientConfig {
                issuer: ctx.id.clone(),
                client_id: Some(client_id),
                ..ClientConfig::default()
            },
            lenient_registered: false,
        });
    };
    if let Some(expected) = client.config.client_secret.as_deref() {
        let ok = presented
            .as_deref()
            .is_some_and(|p| constant_time_eq(p.as_bytes(), expected.as_bytes()));
        ctx.enforce(ok, || "client authentication failed".to_owned())
            .map_err(|rule| invalid_client(&rule, basic_auth))?;
    }
    ctx.enforce(
        client
            .config
            .grant_types
            .iter()
            .any(|g| g == "authorization_code"),
        || "client is not allowed the authorization_code grant".to_owned(),
    )
    .map_err(|rule| OAuthError::json("unauthorized_client", rule))?;
    Ok(client)
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

/// `POST /token`.
pub async fn token(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Response {
    record_endpoint(&ctx.id, "token");
    match exchange_code(&ctx, &headers, &f).await {
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

async fn exchange_code(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    if f.grant_type.as_deref() != Some("authorization_code") {
        return Err(OAuthError::json(
            "unsupported_grant_type",
            "only the authorization_code grant is supported",
        ));
    }
    let client = authenticate(ctx, headers, f)?;
    let invalid_grant = |d: &str| OAuthError::json("invalid_grant", d);
    let grant = f
        .code
        .as_deref()
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
    .map_err(|_| invalid_grant("redirect_uri does not match"))?;
    if let Some((challenge, method)) = &grant.pkce {
        let ok = f
            .code_verifier
            .as_deref()
            .is_some_and(|v| pkce_matches(challenge, *method, v));
        ctx.enforce(ok, || "PKCE verification failed".to_owned())
            .map_err(|_| invalid_grant("PKCE verification failed"))?;
    }
    let key = ctx
        .app
        .keys
        .get()
        .await
        .map_err(|_| OAuthError::Unavailable)?;

    let issuer = ctx.issuer();
    let lifetimes = issuer.lifetimes.with_override(&client.config.lifetimes);
    let audience = match (&grant.audience, client.config.audience.as_str()) {
        (Some(a), _) => a.clone(),
        (None, a) if !a.is_empty() => a.to_owned(),
        (None, _) => client.client_id.clone(),
    };
    let config = &ctx.app.config;
    let access_claims = filter_by_scope(
        build_claims(
            config,
            &ctx.id,
            &client.config,
            &grant.subject,
            ClaimTarget::Access,
        ),
        &grant.scope,
    );
    let access_token = sign_access_token(
        &key,
        AccessTokenInput {
            issuer_url: &issuer.issuer_url,
            client_id: &client.client_id,
            audience: &audience,
            claims: access_claims,
            scope: &grant.scope,
            auth_time: grant.auth_time,
            lifetime: lifetimes.access_token,
        },
    )?;
    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": lifetimes.access_token,
        "scope": grant.scope.join(" "),
    });
    if grant.scope.iter().any(|s| s == "openid") {
        let id_claims = filter_by_scope(
            build_claims(
                config,
                &ctx.id,
                &client.config,
                &grant.subject,
                ClaimTarget::IdToken,
            ),
            &grant.scope,
        );
        body["id_token"] = json!(sign_id_token(
            &key,
            IdTokenInput {
                issuer_url: &issuer.issuer_url,
                client_id: &client.client_id,
                claims: id_claims,
                auth_time: grant.auth_time,
                nonce: grant.nonce.as_deref(),
                lifetime: lifetimes.id_token,
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
}
