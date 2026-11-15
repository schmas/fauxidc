//! The authorization endpoint: request validation and the login page.

use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::claims::{ClaimTarget, build_claims, fill_username};
use crate::clients::{
    ResolvedClient, debugger_redirect_ok, find_client, redirect_uri_matches, register_lenient,
};
use crate::config::{Claims, CustomUserConfig, Endpoint};
use crate::cookies::{auto_select_name, auto_select_set, read_cookie, session_name, session_set};
use crate::error::{OAuthError, append_query};
use crate::logging::{record_client, record_endpoint};
use crate::prompt::{self, PromptError, PromptRequest};
use crate::session::Session;
use crate::state::{CodeGrant, IssuerCtx, PkceMethod, Subject, now_secs};
use crate::templates::{CONTEXT_VERSION, ErrorContext, LoginContext, STATIC_BASE, UserOption};
use crate::tokens::verify_id_token_hint;

/// The `user` form value that selects the Custom user.
pub const CUSTOM_USER: &str = "__custom__";

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
    pub max_age: Option<String>,
    /// Used only by `prompt=none`; never posted back by the login form.
    #[serde(skip_serializing)]
    pub id_token_hint: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    /// A request object (OIDC Core 6.1). Not supported; never posted back by the login form.
    #[serde(skip_serializing)]
    pub request: Option<String>,
    /// A request object by reference (OIDC Core 6.2). Not supported; never posted back.
    #[serde(skip_serializing)]
    pub request_uri: Option<String>,
}

impl AuthorizeParams {
    /// Every set field except `prompt` and `id_token_hint`, in a fixed order. The login form
    /// posts them back.
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
            ("max_age", &self.max_age),
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

/// The redirect URI rule: the built-in debugger Client accepts only the exact debugger
/// callback URL of this request, in both modes; any other Client needs a registered match
/// (through `enforce`).
fn check_redirect_uri(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    client: &ResolvedClient,
    redirect_uri: &str,
) -> Result<(), String> {
    if client.builtin {
        if debugger_redirect_ok(ctx, headers, redirect_uri) {
            return Ok(());
        }
        let rule = format!("redirect_uri is not the debugger callback: {redirect_uri}");
        tracing::info!(issuer = %ctx.id, "{rule}");
        return Err(rule);
    }
    let registered = client
        .config
        .redirect_uris
        .iter()
        .any(|r| redirect_uri_matches(r, redirect_uri));
    ctx.enforce(registered, || {
        format!("redirect_uri not registered: {redirect_uri}")
    })
}

fn validate(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    p: &AuthorizeParams,
) -> Result<ValidRequest, Rejection> {
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

    check_redirect_uri(ctx, headers, &client, redirect_uri).map_err(page)?;

    let fail = |error: &'static str, description: &str| {
        Rejection::Redirect(OAuthError::Redirect {
            redirect_uri: redirect_uri.to_owned(),
            state: p.state.clone(),
            error,
            description: description.to_owned(),
        })
    };

    // OIDC Core 3.1.2.6: request objects are not supported, in both modes.
    if p.request.as_deref().is_some_and(|v| !v.is_empty()) {
        let rule = "request objects are not supported";
        tracing::info!(issuer = %ctx.id, "{rule}");
        return Err(fail("request_not_supported", rule));
    }
    if p.request_uri.as_deref().is_some_and(|v| !v.is_empty()) {
        let rule = "request_uri is not supported";
        tracing::info!(issuer = %ctx.id, "{rule}");
        return Err(fail("request_uri_not_supported", rule));
    }

    match p.response_type.as_deref().filter(|v| !v.is_empty()) {
        Some("code") => {}
        None => {
            let rule = "missing response_type";
            tracing::info!(issuer = %ctx.id, "{rule}");
            return Err(fail("invalid_request", rule));
        }
        Some(other) => {
            let rule = format!("unsupported response_type: {other}");
            tracing::info!(issuer = %ctx.id, "{rule}");
            return Err(fail("unsupported_response_type", &rule));
        }
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

    // The built-in debugger Client: PKCE with S256 in both modes (plan Ruling 34).
    if client.builtin && !matches!(pkce, Some((_, PkceMethod::S256))) {
        let rule = "the debugger Client needs PKCE with S256";
        tracing::info!(issuer = %ctx.id, "{rule}");
        return Err(fail("invalid_request", rule));
    }
    ctx.enforce(
        pkce.is_some() || !(client.is_public() || client.config.require_pkce),
        || "code_challenge required".to_owned(),
    )
    .map_err(|rule| fail("invalid_request", &rule))?;

    let has_nonce = p.nonce.as_deref().is_some_and(|v| !v.is_empty());
    ctx.enforce(!ctx.issuer().require_nonce || has_nonce, || {
        "nonce required".to_owned()
    })
    .map_err(|rule| fail("invalid_request", &rule))?;

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

/// `true` if `value` is 43 to 128 characters of `[A-Za-z0-9-._~]`: the format of a PKCE
/// `code_verifier` and `code_challenge` (RFC 7636 4.1, 4.2).
pub(crate) fn valid_pkce_value(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// Reads the PKCE parameters. Empty values count as absent. A challenge without a method
/// uses `plain` (RFC 7636 4.3).
fn parse_pkce(p: &AuthorizeParams) -> Result<Option<(String, PkceMethod)>, String> {
    let method = match p.code_challenge_method.as_deref().filter(|v| !v.is_empty()) {
        None => None,
        Some("S256") => Some(PkceMethod::S256),
        Some("plain") => Some(PkceMethod::Plain),
        Some(other) => return Err(format!("unsupported code_challenge_method: {other}")),
    };
    let challenge = p.code_challenge.as_deref().filter(|v| !v.is_empty());
    match (challenge, method) {
        (Some(challenge), _) if !valid_pkce_value(challenge) => {
            Err("code_challenge must be 43 to 128 characters of [A-Za-z0-9-._~]".to_owned())
        }
        (Some(challenge), method) => Ok(Some((
            challenge.to_owned(),
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
    authorize_request(&ctx, &headers, &p).await
}

/// An authorization request, sent by `GET` or as a `POST` form without a `user` field
/// (OIDC Core 3.1.2.1): validate; `prompt=none` uses the Session only; `login`,
/// `select_account` and `max_age=0` show the page; a Session not older than `max_age` is
/// reused; else sign in without the page (Auto-select, `auto_login`) or show the login page.
async fn authorize_request(ctx: &IssuerCtx, headers: &HeaderMap, p: &AuthorizeParams) -> Response {
    record_endpoint(&ctx.id, "authorize");
    if let Some(client_id) = p.client_id.as_deref() {
        record_client(client_id);
    }
    let request = match validate(ctx, headers, p) {
        Ok(request) => request,
        Err(rejection) => return reject(ctx, rejection),
    };
    let prompt = match prompt_request(ctx, &request) {
        Ok(prompt) => prompt,
        Err(rejection) => return reject(ctx, rejection),
    };
    if prompt.none {
        // `max_age=0` acts as `prompt=login` (Ruling 7), which `prompt=none` forbids.
        if prompt.force_login {
            return reject(
                ctx,
                redirect_error(
                    ctx,
                    &request,
                    "login_required",
                    "prompt=none: max_age=0 requires a new sign-in",
                ),
            );
        }
        return match silent_session(ctx, headers, &request, &prompt).await {
            Ok(session) => resume(ctx, &request, &session),
            Err(rejection) => reject(ctx, rejection),
        };
    }
    if prompt.force_login {
        return login_page(ctx, &request, StatusCode::OK, None, &KeptInput::default());
    }
    // `max_age` is checked against the Session `auth_time` (spec 11): a Session that is not
    // older than `max_age` is reused, so `auth_time` stays (OIDF oidcc-max-age-10000).
    if prompt.max_age.is_some()
        && let Ok(session) = current_session(ctx, headers, prompt.max_age)
    {
        return resume(ctx, &request, &session);
    }
    match skip_login(ctx, &request, headers) {
        Some(id) => sign_in(
            ctx,
            &request,
            Subject::User {
                id,
                overrides: Claims::new(),
            },
        ),
        None => login_page(ctx, &request, StatusCode::OK, None, &KeptInput::default()),
    }
}

fn reject(ctx: &IssuerCtx, rejection: Rejection) -> Response {
    match rejection {
        Rejection::Redirect(error) => error.into_response(),
        Rejection::Page(status, message) => error_page(ctx, status, message),
    }
}

/// A redirect to the request `redirect_uri` with `error` and the rule text as description.
fn redirect_error(
    ctx: &IssuerCtx,
    req: &ValidRequest,
    error: &'static str,
    rule: &str,
) -> Rejection {
    tracing::info!(issuer = %ctx.id, "{rule}");
    Rejection::Redirect(OAuthError::Redirect {
        redirect_uri: req.redirect_uri.clone(),
        state: req.params.state.clone(),
        error,
        description: rule.to_owned(),
    })
}

/// Parses `prompt` and `max_age`. `none` with other values is an `invalid_request` in both
/// modes; a bad `max_age` goes through `enforce` (Lenient ignores it).
fn prompt_request(ctx: &IssuerCtx, req: &ValidRequest) -> Result<PromptRequest, Rejection> {
    let p = &req.params;
    let ignored = prompt::ignored_values(p.prompt.as_deref());
    if !ignored.is_empty() {
        tracing::info!(issuer = %ctx.id, "prompt values ignored: {}", ignored.join(" "));
    }
    match prompt::parse(p.prompt.as_deref(), p.max_age.as_deref()) {
        Ok(prompt) => Ok(prompt),
        Err(e @ PromptError::NoneWithOthers) => {
            Err(redirect_error(ctx, req, "invalid_request", &e.rule()))
        }
        Err(e @ PromptError::BadMaxAge(_)) => {
            ctx.enforce(false, || e.rule())
                .map_err(|rule| redirect_error(ctx, req, "invalid_request", &rule))?;
            prompt::parse(p.prompt.as_deref(), None)
                .map_err(|e| redirect_error(ctx, req, "invalid_request", &e.rule()))
        }
    }
}

/// `prompt=none`: the Session named by this Issuer's Session cookie if it exists for this
/// Issuer, belongs to a User that still exists (else it is removed), is not older than
/// `max_age`, and matches the `id_token_hint` `sub`. Else a `login_required` redirect, or an
/// `invalid_request` redirect for an invalid hint (through `enforce`: Lenient ignores the hint).
async fn silent_session(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    req: &ValidRequest,
    prompt: &PromptRequest,
) -> Result<Session, Rejection> {
    let login_required = |rule: &str| redirect_error(ctx, req, "login_required", rule);
    let hint_sub = match req
        .params
        .id_token_hint
        .as_deref()
        .filter(|h| !h.is_empty())
    {
        None => None,
        Some(hint) => {
            let keys = ctx.keys().await.map_err(Rejection::Redirect)?;
            match verify_id_token_hint(&keys, &ctx.issuer_url(headers), hint) {
                Ok(claims) => Some(
                    claims
                        .get("sub")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                ),
                Err(e) => {
                    tracing::info!(issuer = %ctx.id, "{e}");
                    ctx.enforce(false, || "id_token_hint is invalid".to_owned())
                        .map_err(|rule| redirect_error(ctx, req, "invalid_request", &rule))?;
                    None
                }
            }
        }
    };
    let session = current_session(ctx, headers, prompt.max_age).map_err(login_required)?;
    // The `sub` merged for this request's Client (plan Ruling 25): a Client whose `id_claims`
    // sets `sub` compares with its own `sub`.
    if let Some(sub) = hint_sub
        && sub != merged_sub(ctx, &req.client, &session.subject)
    {
        return Err(login_required(
            "prompt=none: id_token_hint does not match the session",
        ));
    }
    Ok(session)
}

/// The ID token `sub` of `subject` for `client`.
fn merged_sub(ctx: &IssuerCtx, client: &ResolvedClient, subject: &Subject) -> String {
    build_claims(
        &ctx.app.config,
        &ctx.id,
        &client.config,
        subject,
        ClaimTarget::IdToken,
    )
    .get("sub")
    .and_then(serde_json::Value::as_str)
    .unwrap_or_default()
    .to_owned()
}

/// The Session named by this Issuer's Session cookie if it exists for this Issuer, belongs
/// to a User that still exists (else it is removed), and is not older than `max_age`.
/// Else the `login_required` rule text.
fn current_session(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    max_age: Option<u64>,
) -> Result<Session, &'static str> {
    let no_session = "prompt=none: no session exists";
    let value = read_cookie(headers, &session_name(&ctx.id)).ok_or(no_session)?;
    let session = ctx
        .app
        .store
        .sessions
        .get(&ctx.id, &value)
        .ok_or(no_session)?;
    if let Subject::User { id, .. } = &session.subject
        && !ctx.app.config.user.contains_key(id)
    {
        ctx.app.store.sessions.remove(&ctx.id, &value);
        return Err("prompt=none: session user no longer exists");
    }
    if let Some(max_age) = max_age
        && now_secs() > session.auth_time.saturating_add(max_age)
    {
        return Err("prompt=none: session is older than max_age");
    }
    Ok(session)
}

/// The configured user to sign in without the login page, if any.
///
/// `auto_login` with a `login_hint` that names a user wins, then the Auto-select cookie.
/// The caller handles `prompt` first.
fn skip_login(ctx: &IssuerCtx, request: &ValidRequest, headers: &HeaderMap) -> Option<String> {
    let users = &ctx.app.config.user;
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

/// The login form input that a re-rendered page keeps.
#[derive(Debug, Default)]
struct KeptInput {
    /// The posted `user`: a user id or `__custom__`.
    user: Option<String>,
    remember: bool,
    custom_sub: String,
    custom_claims: String,
    override_claims: String,
    username: String,
}

/// Why the login form was rejected: the message for the page and the form field it is about.
#[derive(Debug, Clone, Copy)]
struct LoginError {
    /// The form field name: `user`, `username`, `custom_sub`, `custom_claims` or
    /// `override_claims`.
    field: &'static str,
    message: &'static str,
}

impl LoginError {
    fn new(field: &'static str, message: &'static str) -> Self {
        Self { field, message }
    }
}

/// Renders the login page. `error` is shown on the page and marks its field; `kept` refills
/// the text fields.
fn login_page(
    ctx: &IssuerCtx,
    request: &ValidRequest,
    status: StatusCode,
    error: Option<LoginError>,
    kept: &KeptInput,
) -> Response {
    let custom_user = ctx.issuer().custom_user.as_ref();
    let known = |id: &&String| ctx.app.config.user.contains_key(*id);
    let selected = kept
        .user
        .as_ref()
        .filter(|id| *id == CUSTOM_USER || known(id))
        .or_else(|| request.params.login_hint.as_ref().filter(known))
        .cloned();
    let login = LoginContext {
        context_version: CONTEXT_VERSION,
        issuer_id: ctx.id.clone(),
        client_id: request.client.client_id.clone(),
        action: ctx.endpoint_href(Endpoint::Authorize),
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
        error: error.map(|e| e.message.to_owned()),
        error_field: error.map(|e| e.field.to_owned()),
        custom_sub: kept.custom_sub.clone(),
        custom_claims: kept.custom_claims.clone(),
        override_claims: kept.override_claims.clone(),
        remember: kept.remember,
        static_base: STATIC_BASE.to_owned(),
        custom_label: custom_user
            .map_or_else(|| CustomUserConfig::default().label, |c| c.label.clone()),
        custom_username: custom_user.is_some(),
        username: kept.username.clone(),
    };
    match ctx.app.templates.render_login(&ctx.id, &login) {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => OAuthError::ServerError(format!("login page: {e}")).into_response(),
    }
}

pub(crate) fn error_page(ctx: &IssuerCtx, status: StatusCode, message: String) -> Response {
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
    /// The username of the Custom user template (`custom_user`).
    pub username: Option<String>,
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

/// `POST {issuer}/authorize`: the login form submit, or an authorization request sent as a
/// form when there is no `user` field.
pub async fn authorize_post(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Form(f): Form<LoginForm>,
) -> Response {
    if f.user.is_none() {
        return authorize_request(&ctx, &headers, &f.params).await;
    }
    record_endpoint(&ctx.id, "authorize");
    if let Some(client_id) = f.params.client_id.as_deref() {
        record_client(client_id);
    }
    let request = match validate(&ctx, &headers, &f.params) {
        Ok(request) => request,
        Err(rejection) => return reject(&ctx, rejection),
    };
    let kept = KeptInput {
        user: f.user.clone(),
        remember: f.remember.is_some(),
        custom_sub: f.custom_sub.clone().unwrap_or_default(),
        custom_claims: f.custom_claims.clone().unwrap_or_default(),
        override_claims: f.override_claims.clone().unwrap_or_default(),
        username: f.username.clone().unwrap_or_default(),
    };
    match subject_from_form(&ctx, &f) {
        Ok(subject) => {
            let remembered = match (&subject, f.remember.is_some()) {
                (Subject::User { id, .. }, true) => auto_select_set(&ctx.id, &ctx.path, id),
                _ => None,
            };
            sign_in_with(&ctx, &request, subject, remembered)
        }
        Err(error) => {
            tracing::info!(issuer = %ctx.id, "login rejected: {}", error.message);
            login_page(&ctx, &request, StatusCode::BAD_REQUEST, Some(error), &kept)
        }
    }
}

/// Reads who signed in. The error is the message for the login page and its field.
///
/// With `custom_user`, the Custom user reads only `username` and `override_claims` (plan
/// Ruling 40); without it, `custom_sub` and `custom_claims`.
fn subject_from_form(ctx: &IssuerCtx, f: &LoginForm) -> Result<Subject, LoginError> {
    let override_claims = f.override_claims.as_deref().unwrap_or_default();
    let overrides = parse_claims(override_claims).ok_or(LoginError::new(
        "override_claims",
        "Override claims must be a JSON object",
    ));
    let user = f.user.as_deref().unwrap_or_default();
    if user == CUSTOM_USER {
        if let Some(template) = &ctx.issuer().custom_user {
            return template_subject(template, f.username.as_deref(), overrides);
        }
        let sub = f.custom_sub.as_deref().unwrap_or_default().trim();
        if sub.is_empty() {
            return Err(LoginError::new("custom_sub", "Custom user needs a sub"));
        }
        let claims = parse_claims(f.custom_claims.as_deref().unwrap_or_default()).ok_or(
            LoginError::new("custom_claims", "Custom claims must be a JSON object"),
        )?;
        overrides?;
        return Ok(Subject::Custom {
            sub: sub.to_owned(),
            claims,
        });
    }
    if !ctx.app.config.user.contains_key(user) {
        return Err(LoginError::new("user", "Choose a user"));
    }
    Ok(Subject::User {
        id: user.to_owned(),
        overrides: overrides?,
    })
}

/// The Custom user of a `custom_user` template: `sub` is the username, trimmed and lowercase;
/// the claims are the template with `{username}` filled in, then `overrides` on top. The
/// username is checked before the overrides, as `custom_sub` is.
fn template_subject(
    template: &CustomUserConfig,
    username: Option<&str>,
    overrides: Result<Claims, LoginError>,
) -> Result<Subject, LoginError> {
    let username = username.unwrap_or_default().trim().to_lowercase();
    if username.is_empty() {
        return Err(LoginError::new("username", "Enter a username"));
    }
    let mut claims: Claims = template
        .claims
        .iter()
        .map(|(k, v)| (k.clone(), fill_username(v, &username)))
        .collect();
    claims.extend(overrides?);
    Ok(Subject::Custom {
        sub: username,
        claims,
    })
}

/// Creates a Session for `subject` (`auth_time` = now, new `sid`), issues the code with them,
/// and on a 302 appends the Session cookie.
pub(crate) fn sign_in(ctx: &IssuerCtx, req: &ValidRequest, subject: Subject) -> Response {
    sign_in_with(ctx, req, subject, None)
}

/// [`sign_in`], with an Auto-select cookie appended before the Session cookie.
fn sign_in_with(
    ctx: &IssuerCtx,
    req: &ValidRequest,
    subject: Subject,
    auto_select: Option<HeaderValue>,
) -> Response {
    let session = Session {
        issuer_id: ctx.id.clone(),
        subject: subject.clone(),
        sid: uuid::Uuid::new_v4().to_string(),
        auth_time: now_secs(),
    };
    let (auth_time, sid) = (session.auth_time, session.sid.clone());
    let value = match ctx.app.store.sessions.create(session) {
        Ok(value) => value,
        Err(e) => return e.into_response(),
    };
    let mut response = issue_code(ctx, req, subject, auth_time, Some(sid));
    if response.status() == StatusCode::FOUND {
        let cookies = auto_select
            .into_iter()
            .chain(session_set(&ctx.id, &ctx.path, &value));
        for cookie in cookies {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    response
}

/// Issues a code for an existing Session (its `auth_time` and `sid`). No new cookie.
pub(crate) fn resume(ctx: &IssuerCtx, req: &ValidRequest, session: &Session) -> Response {
    issue_code(
        ctx,
        req,
        session.subject.clone(),
        session.auth_time,
        Some(session.sid.clone()),
    )
}

/// Stores a code grant for `subject` with the sign-in facts and redirects to the client with
/// the code.
pub(crate) fn issue_code(
    ctx: &IssuerCtx,
    req: &ValidRequest,
    subject: Subject,
    auth_time: u64,
    sid: Option<String>,
) -> Response {
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
        auth_time,
        expires_at: now + lifetimes.code,
        sid,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_ctx;

    const CONFIG: &str = r#"[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"

[client.example_app]
client_id = "example-app"
client_secret = "local"
redirect_uris = ["http://localhost:3000/cb"]

[user.alice]
claims = { email = "alice@example.com" }
"#;

    #[tokio::test]
    async fn removed_user_session_is_deleted() {
        let ctx = test_ctx(CONFIG, "auth0");
        let params = AuthorizeParams {
            response_type: Some("code".into()),
            client_id: Some("example-app".into()),
            redirect_uri: Some("http://localhost:3000/cb".into()),
            prompt: Some("none".into()),
            ..Default::default()
        };
        let req = validate(&ctx, &HeaderMap::new(), &params).unwrap();
        let value = ctx
            .app
            .store
            .sessions
            .create(Session {
                issuer_id: "auth0".into(),
                subject: Subject::User {
                    id: "ghost".into(),
                    overrides: Claims::new(),
                },
                sid: "s-1".into(),
                auth_time: now_secs(),
            })
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::try_from(format!("fauxidc_session_auth0={value}")).unwrap(),
        );
        let result = silent_session(&ctx, &headers, &req, &PromptRequest::default()).await;
        let Err(Rejection::Redirect(OAuthError::Redirect { error, .. })) = result else {
            panic!("expected a redirect error");
        };
        assert_eq!(error, "login_required");
        assert!(ctx.app.store.sessions.get("auth0", &value).is_none());
    }
}
