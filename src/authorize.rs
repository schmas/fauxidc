//! The authorization endpoint: request validation and the login page.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::clients::{ResolvedClient, find_client, redirect_uri_matches, register_lenient};
use crate::error::OAuthError;
use crate::state::{IssuerCtx, PkceMethod};
use crate::templates::{CONTEXT_VERSION, ErrorContext, LoginContext, STATIC_BASE, UserOption};

/// The query parameters of `GET /authorize` and the hidden fields of the login form.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub login_hint: Option<String>,
    pub prompt: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
}

impl AuthorizeParams {
    /// Every set field except `prompt`, in a fixed order. The login form posts them back.
    pub fn hidden_fields(&self) -> Vec<(String, String)> {
        [
            ("response_type", &self.response_type),
            ("client_id", &self.client_id),
            ("redirect_uri", &self.redirect_uri),
            ("scope", &self.scope),
            ("state", &self.state),
            ("nonce", &self.nonce),
            ("code_challenge", &self.code_challenge),
            ("code_challenge_method", &self.code_challenge_method),
            ("login_hint", &self.login_hint),
            ("audience", &self.audience),
            ("resource", &self.resource),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.as_ref().map(|v| (name.to_owned(), v.clone())))
        .collect()
    }
}

/// A request that passed all checks.
#[derive(Debug, Clone)]
pub struct ValidRequest {
    pub client: ResolvedClient,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub pkce: Option<(String, PkceMethod)>,
    pub params: AuthorizeParams,
}

/// Why a request failed.
#[derive(Debug)]
enum Rejection {
    /// An error page. The `redirect_uri` is not trusted, so there is no redirect.
    Page(StatusCode, String),
    /// A redirect to the registered `redirect_uri` with the error.
    Redirect(OAuthError),
}

fn page(message: String) -> Rejection {
    Rejection::Page(StatusCode::BAD_REQUEST, message)
}

fn validate(ctx: &IssuerCtx, p: &AuthorizeParams) -> Result<ValidRequest, Rejection> {
    let Some(client_id) = p.client_id.as_deref().filter(|v| !v.is_empty()) else {
        return Err(page("missing client_id".into()));
    };
    let Some(redirect_uri) = p.redirect_uri.as_deref().filter(|v| !v.is_empty()) else {
        return Err(page("missing redirect_uri".into()));
    };

    let client = if let Some(client) = find_client(ctx, client_id) {
        client
    } else {
        ctx.enforce(false, || format!("unknown client_id: {client_id}"))
            .map_err(page)?;
        register_lenient(ctx, client_id, redirect_uri)
    };

    let registered = client
        .config
        .redirect_uris
        .iter()
        .any(|r| redirect_uri_matches(r, redirect_uri));
    ctx.enforce(registered, || {
        format!("redirect_uri not registered: {redirect_uri}")
    })
    .map_err(page)?;

    let fail = |error: &'static str, description: &str| {
        Rejection::Redirect(OAuthError::Redirect {
            redirect_uri: redirect_uri.to_owned(),
            state: p.state.clone(),
            error,
            description: description.to_owned(),
        })
    };

    if p.response_type.as_deref() != Some("code") {
        let rule = format!(
            "unsupported response_type: {}",
            p.response_type.as_deref().unwrap_or("(none)")
        );
        tracing::info!(issuer = %ctx.id, "{rule}");
        return Err(fail("unsupported_response_type", &rule));
    }

    let allowed = client
        .config
        .grant_types
        .iter()
        .any(|g| g == "authorization_code");
    ctx.enforce(allowed, || {
        format!("client {client_id} lacks grant type authorization_code")
    })
    .map_err(|rule| fail("unauthorized_client", &rule))?;

    let pkce = parse_pkce(p).map_err(|rule| {
        tracing::info!(issuer = %ctx.id, "{rule}");
        fail("invalid_request", &rule)
    })?;

    ctx.enforce(
        pkce.is_some() || !(client.is_public() || client.config.require_pkce),
        || "code_challenge required".to_owned(),
    )
    .map_err(|rule| fail("invalid_request", &rule))?;

    ctx.enforce(!ctx.issuer().require_nonce || p.nonce.is_some(), || {
        "nonce required".to_owned()
    })
    .map_err(|rule| fail("invalid_request", &rule))?;

    if p.prompt
        .as_deref()
        .is_some_and(|v| v.split_whitespace().any(|w| w == "none"))
    {
        let rule = "prompt=none: no session exists";
        tracing::info!(issuer = %ctx.id, "{rule}");
        return Err(fail("login_required", rule));
    }

    Ok(ValidRequest {
        redirect_uri: redirect_uri.to_owned(),
        scope: p
            .scope
            .as_deref()
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect(),
        pkce,
        client,
        params: p.clone(),
    })
}

/// Reads the PKCE parameters. A challenge without a method uses `plain` (RFC 7636 4.3).
fn parse_pkce(p: &AuthorizeParams) -> Result<Option<(String, PkceMethod)>, String> {
    let method = match p.code_challenge_method.as_deref() {
        None => None,
        Some("S256") => Some(PkceMethod::S256),
        Some("plain") => Some(PkceMethod::Plain),
        Some(other) => return Err(format!("unsupported code_challenge_method: {other}")),
    };
    match (&p.code_challenge, method) {
        (Some(challenge), method) => Ok(Some((
            challenge.clone(),
            method.unwrap_or(PkceMethod::Plain),
        ))),
        (None, Some(_)) => Err("code_challenge_method without code_challenge".to_owned()),
        (None, None) => Ok(None),
    }
}

/// `GET {issuer}/authorize`.
pub async fn authorize_get(
    State(ctx): State<IssuerCtx>,
    _headers: HeaderMap,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    match validate(&ctx, &p) {
        Ok(request) => login_page(&ctx, &request),
        Err(Rejection::Redirect(error)) => error.into_response(),
        Err(Rejection::Page(status, message)) => error_page(&ctx, status, message),
    }
}

fn login_page(ctx: &IssuerCtx, request: &ValidRequest) -> Response {
    let selected = request
        .params
        .login_hint
        .as_ref()
        .filter(|hint| ctx.app.config.user.contains_key(*hint))
        .cloned();
    let login = LoginContext {
        context_version: CONTEXT_VERSION,
        issuer_id: ctx.id.clone(),
        client_id: request.client.client_id.clone(),
        action: format!("{}/authorize", ctx.path.trim_end_matches('/')),
        users: ctx
            .app
            .config
            .user
            .iter()
            .map(|(id, user)| UserOption {
                id: id.clone(),
                label: if user.label.is_empty() {
                    id.clone()
                } else {
                    user.label.clone()
                },
            })
            .collect(),
        selected,
        params: request.params.hidden_fields(),
        error: None,
        custom_sub: String::new(),
        custom_claims: String::new(),
        override_claims: String::new(),
        static_base: STATIC_BASE.to_owned(),
    };
    match ctx.app.templates.render_login(&ctx.id, &login) {
        Ok(html) => Html(html).into_response(),
        Err(e) => OAuthError::ServerError(format!("login page: {e}")).into_response(),
    }
}

fn error_page(ctx: &IssuerCtx, status: StatusCode, message: String) -> Response {
    let context = ErrorContext {
        context_version: CONTEXT_VERSION,
        issuer_id: ctx.id.clone(),
        message,
        static_base: STATIC_BASE.to_owned(),
    };
    match ctx.app.templates.render_error(&context) {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => OAuthError::ServerError(format!("error page: {e}")).into_response(),
    }
}
