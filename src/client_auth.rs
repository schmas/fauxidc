//! Client authentication for `/token`, `/introspect` and `/revoke`.

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::clients::{ResolvedClient, find_client};
use crate::config::ClientConfig;
use crate::error::OAuthError;
use crate::logging::record_client;
use crate::state::IssuerCtx;

/// How a Client authenticated (RFC 6749 2.3, OpenID Connect Core 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
    None,
}

impl AuthMethod {
    /// The registered name of the method.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMethod::ClientSecretBasic => "client_secret_basic",
            AuthMethod::ClientSecretPost => "client_secret_post",
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

/// Finds and authenticates the Client of a `/token`, `/introspect` or `/revoke` request.
pub fn authenticate_client(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    form_client_id: Option<&str>,
    form_client_secret: Option<&str>,
) -> Result<ClientAuth, OAuthError> {
    let form_secret = form_client_secret.filter(|s| !s.is_empty());
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
        // Lenient: treat the unknown Client as a public Client with this id.
        return Ok(ClientAuth {
            client: ResolvedClient {
                key: client_id.clone(),
                client_id: client_id.clone(),
                config: ClientConfig {
                    issuer: ctx.id.clone(),
                    client_id: Some(client_id),
                    ..ClientConfig::default()
                },
                lenient_registered: false,
            },
            method,
        });
    };
    let Some(expected) = client.config.client_secret.as_deref() else {
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
        let a = authenticate_client(&ctx, &basic("example-app", "local"), None, None).unwrap();
        assert_eq!(
            (a.client.client_id.as_str(), a.method),
            ("example-app", AuthMethod::ClientSecretBasic)
        );
        let a = authenticate_client(&ctx, &HeaderMap::new(), Some("example-app"), Some("local"))
            .unwrap();
        assert_eq!(a.method, AuthMethod::ClientSecretPost);
        let a = authenticate_client(&ctx, &HeaderMap::new(), Some("spa"), None).unwrap();
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
        assert_eq!(AuthMethod::None.as_str(), "none");
    }

    #[test]
    fn confidential_client_with_none_fails() {
        let ctx = test_ctx(CFG, "auth0");
        let e =
            authenticate_client(&ctx, &HeaderMap::new(), Some("example-app"), None).unwrap_err();
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
        let e = authenticate_client(
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
            authenticate_client(
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
        let e = authenticate_client(
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
        assert!(authenticate_client(&strict, &HeaderMap::new(), Some("nope"), None).is_err());
        let lenient = test_ctx(
            &CFG.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n"),
            "auth0",
        );
        let a = authenticate_client(&lenient, &HeaderMap::new(), Some("nope"), None).unwrap();
        assert!(a.client.is_public());
        assert_eq!(a.client.config.issuer, "auth0");
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
