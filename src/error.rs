//! Configuration errors that carry the origin of the bad value.

use std::fmt;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::config::Source;

/// One configuration error and where the value came from.
#[derive(Debug, thiserror::Error)]
#[error("{origin}: {message}")]
pub struct ConfigError {
    pub origin: Source,
    pub message: String,
}

/// A list of configuration errors, reported together.
#[derive(Debug)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, error) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}

/// Errors that stop the server from starting.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("cannot bind the listener: {0}")]
    Bind(std::io::Error),
    #[error("signing key error: {0}")]
    Key(crate::keys::KeyError),
    #[error("template error: {0}")]
    Templates(String),
    #[error("invalid configuration:\n{0}")]
    Config(ConfigErrors),
}

/// An OAuth error response, in one of the three styles the endpoints use.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// Token endpoint style: JSON body. Status 401 for `invalid_client`, else 400.
    #[error("{error}: {description}")]
    Json {
        error: &'static str,
        description: String,
        basic_auth: bool,
    },
    /// Authorization endpoint style: 302 to `redirect_uri` with the error.
    #[error("{error}: {description} (redirect to {redirect_uri})")]
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        error: &'static str,
        description: String,
    },
    /// Resource style (RFC 6750): 401 with a `WWW-Authenticate: Bearer` header.
    #[error("invalid_token: {description}")]
    Bearer { description: String },
    /// A request with no bearer token: 401 with a bare `WWW-Authenticate: Bearer` challenge
    /// and no error code (RFC 6750 3.1).
    #[error("missing bearer token")]
    BearerMissing,
    /// A valid token that lacks a needed scope (RFC 6750 3.1): 403 with
    /// `WWW-Authenticate: Bearer error="insufficient_scope"`.
    #[error("insufficient_scope: {description}")]
    InsufficientScope { description: String },
    /// A missing signing key.
    #[error("server_error: signing key not available")]
    Unavailable,
    /// An internal failure such as a lock poison or an RNG failure.
    #[error("server_error: {0}")]
    ServerError(String),
}

impl OAuthError {
    /// A token endpoint style error with `basic_auth` off.
    pub fn json(error: &'static str, description: impl Into<String>) -> Self {
        Self::Json {
            error,
            description: description.into(),
            basic_auth: false,
        }
    }
}

fn json_body(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// A response with only a `WWW-Authenticate: Bearer error=.., error_description=..` header.
/// If the description does not fit a header value, the challenge has only the error.
fn bearer_challenge(status: StatusCode, error: &'static str, description: &str) -> Response {
    let description = description.replace('"', "'");
    let challenge = format!("Bearer error=\"{error}\", error_description=\"{description}\"");
    let value = HeaderValue::try_from(challenge)
        .or_else(|_| HeaderValue::try_from(format!("Bearer error=\"{error}\"")));
    match value {
        Ok(value) => (status, [(header::WWW_AUTHENTICATE, value)]).into_response(),
        Err(_) => (
            status,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
        )
            .into_response(),
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        match self {
            Self::Json {
                error,
                description,
                basic_auth,
            } => {
                let invalid_client = error == "invalid_client";
                let status = if invalid_client {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::BAD_REQUEST
                };
                let mut response = json_body(status, error, &description);
                if basic_auth && invalid_client {
                    response.headers_mut().insert(
                        header::WWW_AUTHENTICATE,
                        HeaderValue::from_static("Basic realm=\"fauxidc\""),
                    );
                }
                response
            }
            Self::Redirect {
                redirect_uri,
                state,
                error,
                description,
            } => {
                let mut pairs = vec![
                    ("error", error),
                    ("error_description", description.as_str()),
                ];
                if let Some(state) = state.as_deref() {
                    pairs.push(("state", state));
                }
                let location = append_query(&redirect_uri, &pairs);
                match HeaderValue::try_from(location) {
                    Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
                    Err(_) => {
                        OAuthError::ServerError("invalid redirect location".into()).into_response()
                    }
                }
            }
            Self::Bearer { description } => {
                bearer_challenge(StatusCode::UNAUTHORIZED, "invalid_token", &description)
            }
            Self::InsufficientScope { description } => {
                bearer_challenge(StatusCode::FORBIDDEN, "insufficient_scope", &description)
            }
            Self::BearerMissing => (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
            )
                .into_response(),
            Self::Unavailable => json_body(
                StatusCode::SERVICE_UNAVAILABLE,
                "server_error",
                "signing key not available",
            ),
            Self::ServerError(message) => {
                json_body(StatusCode::INTERNAL_SERVER_ERROR, "server_error", &message)
            }
        }
    }
}

/// Appends `pairs` to the query of `uri`, using `?` or `&` as needed.
pub fn append_query(uri: &str, pairs: &[(&str, &str)]) -> String {
    let encoded = serde_urlencoded::to_string(pairs).unwrap_or_default();
    if encoded.is_empty() {
        return uri.to_owned();
    }
    let separator = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{separator}{encoded}")
}

#[cfg(test)]
mod tests {
    use axum::response::IntoResponse;

    use super::OAuthError;

    #[tokio::test]
    async fn json_error_status_and_body() {
        let r = OAuthError::json("invalid_grant", "code expired").into_response();
        assert_eq!(r.status(), 400);
        assert_eq!(r.headers()["cache-control"], "no-store");
        let r = OAuthError::Json {
            error: "invalid_client",
            description: "x".into(),
            basic_auth: true,
        }
        .into_response();
        assert_eq!(r.status(), 401);
        assert!(
            r.headers()["www-authenticate"]
                .to_str()
                .unwrap()
                .starts_with("Basic")
        );
    }

    #[test]
    fn redirect_keeps_existing_query_and_state() {
        let r = OAuthError::Redirect {
            redirect_uri: "http://a/cb?x=1".into(),
            state: Some("s 1".into()),
            error: "invalid_request",
            description: "d".into(),
        }
        .into_response();
        assert_eq!(r.status(), 302);
        assert_eq!(
            r.headers()["location"],
            "http://a/cb?x=1&error=invalid_request&error_description=d&state=s+1"
        );
    }

    #[test]
    fn bearer_error_header() {
        let r = OAuthError::Bearer {
            description: "expired".into(),
        }
        .into_response();
        assert_eq!(r.status(), 401);
        assert_eq!(
            r.headers()["www-authenticate"],
            "Bearer error=\"invalid_token\", error_description=\"expired\""
        );
    }
}
