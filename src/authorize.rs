//! The authorization endpoint: request validation and the login page.

use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::clients::{ResolvedClient, find_client, redirect_uri_matches, register_lenient};
use crate::config::Claims;
use crate::cookies::{auto_select_name, auto_select_set, read_cookie};
use crate::error::{OAuthError, append_query};
use crate::state::{CodeGrant, IssuerCtx, PkceMethod, Subject, now_secs};
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
    headers: HeaderMap,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    match validate(&ctx, &p) {
        Ok(request) => match skip_login(&ctx, &request, &headers) {
            Some(id) => issue_code(
                &ctx,
                &request,
                Subject::User {
                    id,
                    overrides: Claims::new(),
                },
            ),
            None => login_page(&ctx, &request, StatusCode::OK, None, &KeptInput::default()),
        },
        Err(Rejection::Redirect(error)) => error.into_response(),
        Err(Rejection::Page(status, message)) => error_page(&ctx, status, message),
    }
}

/// The configured user to sign in without the login page, if any.
///
/// `prompt=login` always shows the page. Else `auto_login` with a `login_hint` that names a
/// user wins, then the auto-select cookie.
fn skip_login(ctx: &IssuerCtx, request: &ValidRequest, headers: &HeaderMap) -> Option<String> {
    let users = &ctx.app.config.user;
    let wants_login = request
        .params
        .prompt
        .as_deref()
        .is_some_and(|v| v.split_whitespace().any(|w| w == "login"));
    if wants_login {
        return None;
    }
    if ctx.issuer().auto_login
        && let Some(hint) = request
            .params
            .login_hint
            .as_ref()
            .filter(|h| users.contains_key(*h))
    {
        return Some(hint.clone());
    }
    read_cookie(headers, &auto_select_name(&ctx.id)).filter(|id| users.contains_key(id))
}

/// The login form text that a re-rendered page keeps.
#[derive(Debug, Default)]
struct KeptInput {
    custom_sub: String,
    custom_claims: String,
    override_claims: String,
}

/// Renders the login page. `error` is shown on the page; `kept` refills the text fields.
fn login_page(
    ctx: &IssuerCtx,
    request: &ValidRequest,
    status: StatusCode,
    error: Option<&str>,
    kept: &KeptInput,
) -> Response {
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
        error: error.map(str::to_owned),
        custom_sub: kept.custom_sub.clone(),
        custom_claims: kept.custom_claims.clone(),
        override_claims: kept.override_claims.clone(),
        static_base: STATIC_BASE.to_owned(),
    };
    match ctx.app.templates.render_login(&ctx.id, &login) {
        Ok(html) => (status, Html(html)).into_response(),
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

/// The fields of the login form: the hidden request parameters plus the user's choices.
#[derive(Debug, Deserialize)]
pub struct LoginForm {
    #[serde(flatten)]
    pub params: AuthorizeParams,
    pub user: Option<String>,
    pub custom_sub: Option<String>,
    pub custom_claims: Option<String>,
    pub override_claims: Option<String>,
    pub remember: Option<String>,
}

/// Parses `text` as a JSON object. Empty text gives an empty object.
fn parse_claims(text: &str) -> Option<Claims> {
    if text.trim().is_empty() {
        return Some(Claims::new());
    }
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// `POST {issuer}/authorize`: the login form submit.
pub async fn authorize_post(State(ctx): State<IssuerCtx>, Form(f): Form<LoginForm>) -> Response {
    let request = match validate(&ctx, &f.params) {
        Ok(request) => request,
        Err(Rejection::Redirect(error)) => return error.into_response(),
        Err(Rejection::Page(status, message)) => return error_page(&ctx, status, message),
    };
    let kept = KeptInput {
        custom_sub: f.custom_sub.clone().unwrap_or_default(),
        custom_claims: f.custom_claims.clone().unwrap_or_default(),
        override_claims: f.override_claims.clone().unwrap_or_default(),
    };
    match subject_from_form(&ctx, &f) {
        Ok(subject) => {
            let remembered = match (&subject, f.remember.is_some()) {
                (Subject::User { id, .. }, true) => auto_select_set(&ctx.id, &ctx.path, id),
                _ => None,
            };
            let mut response = issue_code(&ctx, &request, subject);
            if let Some(cookie) = remembered
                && response.status() == StatusCode::FOUND
            {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
            response
        }
        Err(message) => {
            tracing::info!(issuer = %ctx.id, "login rejected: {message}");
            login_page(
                &ctx,
                &request,
                StatusCode::BAD_REQUEST,
                Some(message),
                &kept,
            )
        }
    }
}

/// Reads who signed in. The error is the message for the login page.
fn subject_from_form(ctx: &IssuerCtx, f: &LoginForm) -> Result<Subject, &'static str> {
    let override_claims = f.override_claims.as_deref().unwrap_or_default();
    let overrides = parse_claims(override_claims).ok_or("Override claims must be a JSON object");
    let user = f.user.as_deref().unwrap_or_default();
    if user == "__custom__" {
        let sub = f.custom_sub.as_deref().unwrap_or_default().trim();
        if sub.is_empty() {
            return Err("Custom user needs a sub");
        }
        let claims = parse_claims(f.custom_claims.as_deref().unwrap_or_default())
            .ok_or("Custom claims must be a JSON object")?;
        overrides?;
        return Ok(Subject::Custom {
            sub: sub.to_owned(),
            claims,
        });
    }
    if !ctx.app.config.user.contains_key(user) {
        return Err("Choose a user");
    }
    Ok(Subject::User {
        id: user.to_owned(),
        overrides: overrides?,
    })
}

/// Stores a code grant for `subject` and redirects to the client with the code.
pub(crate) fn issue_code(ctx: &IssuerCtx, req: &ValidRequest, subject: Subject) -> Response {
    let lifetimes = ctx
        .issuer()
        .lifetimes
        .with_override(&req.client.config.lifetimes);
    let now = now_secs();
    let audience = req
        .params
        .audience
        .clone()
        .or_else(|| req.params.resource.clone());
    let grant = CodeGrant {
        issuer_id: ctx.id.clone(),
        client_id: req.client.client_id.clone(),
        redirect_uri: req.redirect_uri.clone(),
        scope: req.scope.clone(),
        nonce: req.params.nonce.clone(),
        pkce: req.pkce.clone(),
        audience,
        subject,
        auth_time: now,
        expires_at: now + lifetimes.code,
    };
    let code = match ctx.app.store.insert_code(grant) {
        Ok(code) => code,
        Err(e) => return e.into_response(),
    };
    let mut pairs = vec![("code", code.as_str())];
    if let Some(state) = req.params.state.as_deref() {
        pairs.push(("state", state));
    }
    let location = append_query(&req.redirect_uri, &pairs);
    match HeaderValue::try_from(location) {
        Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
        Err(_) => OAuthError::ServerError("invalid redirect location".into()).into_response(),
    }
}
