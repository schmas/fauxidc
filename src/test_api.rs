//! The Test API: `POST /_mock/{issuer_id}/token` issues tokens without a browser, and
//! `POST /_mock/{issuer_id}/rotate-key` rotates an Issuer's signing key, and
//! `POST /_mock/reload` reloads the config files.
//!
//! The endpoint has no authentication. fauxidc must never run in production.

use std::sync::Arc;

use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::clients::{ResolvedClient, find_client};
use crate::config::{Claims, ClientConfig};
use crate::config_api;
use crate::error::OAuthError;
use crate::issuer::issuer_path;
use crate::reload::{ReloadError, RequestedReloadError};
use crate::state::{AppState, IssuerCtx, Subject};
use crate::token_endpoint::{RefreshMode, UserGrant, issue_user_tokens};

/// The JSON body of a Test API token request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestTokenRequest {
    /// A configured User id.
    pub user: Option<String>,
    /// A Custom user `sub`. Exactly one of `user` and `sub`.
    pub sub: Option<String>,
    /// Claim overrides (`user`) or Custom user claims (`sub`).
    #[serde(default)]
    pub claims: Claims,
    /// Defaults to `test-api`.
    pub client_id: Option<String>,
    /// Defaults to `openid profile email`.
    pub scope: Option<String>,
    pub audience: Option<String>,
    /// The `id_token` and access token lifetime in seconds; negative values are allowed.
    pub expires_in: Option<i64>,
}

const DEFAULT_CLIENT_ID: &str = "test-api";
const DEFAULT_SCOPE: &str = "openid profile email";

/// 404 `not_found` for an unknown Issuer id.
pub(crate) fn unknown_issuer(issuer_id: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "not_found",
            "error_description": format!("unknown issuer: {issuer_id}"),
        })),
    )
        .into_response()
}

/// The query of a key rotation request.
#[derive(Debug, Deserialize)]
pub struct RotateQuery {
    /// Remove every older key of the Issuer.
    #[serde(default)]
    pub retire: bool,
}

/// `true` when `headers` has no `Origin`, or `Origin` equals "<scheme>://<Host>" of this
/// request. The scheme is `https` when `server.tls` is on, else `http` (plan Ruling 4).
pub(crate) fn same_origin_or_none(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let scheme = if state.config.server.tls.enabled() {
        "https"
    } else {
        "http"
    };
    origin
        .to_str()
        .is_ok_and(|origin| origin == format!("{scheme}://{host}"))
}

/// `POST /_mock/{issuer_id}/rotate-key[?retire=true]`: a new active key with the Issuer's
/// `signing_alg`; older keys stay in JWKS unless `retire=true`, up to
/// [`MAX_KEYS`](crate::keys::MAX_KEYS) keys. 200 with the [`Rotation`] JSON; 404 `not_found`
/// for an unknown Issuer id; 403 `access_denied` for a cross-origin browser request (an
/// `Origin` header that is not this request's own origin), checked first.
///
/// [`Rotation`]: crate::keys::Rotation
pub async fn rotate_key(
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<RotateQuery>, QueryRejection>,
) -> Response {
    if !same_origin_or_none(&state, &headers) {
        return (
            StatusCode::FORBIDDEN,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Json(json!({
                "error": "access_denied",
                "error_description": "cross-origin Test API request",
            })),
        )
            .into_response();
    }
    let Some(issuer) = state.config.issuer.get(&issuer_id) else {
        return unknown_issuer(&issuer_id);
    };
    let Query(q) = match query {
        Ok(q) => q,
        Err(rejection) => {
            return OAuthError::json("invalid_request", format!("invalid query: {rejection}"))
                .into_response();
        }
    };
    match state
        .keys
        .rotate(&issuer_id, issuer.signing_alg, q.retire)
        .await
    {
        Ok(rotation) => {
            tracing::info!(
                issuer = %issuer_id,
                kid = %rotation.kid,
                retired = rotation.retired.len(),
                "signing key rotated"
            );
            Json(rotation).into_response()
        }
        Err(e) => {
            tracing::error!(issuer = %issuer_id, "key rotation failed: {e}");
            OAuthError::Unavailable.into_response()
        }
    }
}

/// The query of `DELETE /_mock/state`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetQuery {
    /// Clear only the state of this Issuer.
    pub issuer: Option<String>,
}

/// `DELETE /_mock/state[?issuer=<id>]`: clears the runtime state ([`Store::reset`]) and the
/// Request log. Config and signing keys do not change. 204; 404 for an unknown Issuer id;
/// 400 for an unknown query parameter.
///
/// [`Store::reset`]: crate::state::Store::reset
pub async fn reset_state(
    State(state): State<Arc<AppState>>,
    query: Result<Query<ResetQuery>, QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(rejection) => {
            return OAuthError::json("invalid_request", format!("invalid query: {rejection}"))
                .into_response();
        }
    };
    let issuer = q.issuer.as_deref();
    if let Some(id) = issuer
        && !state.config.issuer.contains_key(id)
    {
        return unknown_issuer(id);
    }
    state.store.reset(issuer);
    state.request_log.clear_issuer(issuer);
    tracing::info!(issuer = issuer.unwrap_or("*"), "runtime state reset");
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /_mock/reload`: loads the config files again and applies them at once
/// ([`ConfigWriter::reload`]). 200 with [`Reloaded`]; 422 `invalid_config` with the config
/// errors (the old config stays); 409 `conflict` with no config file; 403 `access_denied` for a
/// cross-origin browser request, checked first.
///
/// [`ConfigWriter::reload`]: crate::reload::ConfigWriter::reload
/// [`Reloaded`]: crate::reload::Reloaded
pub async fn reload(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if !same_origin_or_none(&state, &headers) {
        return config_api::error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "cross-origin Test API request",
        );
    }
    let result = match state.config_writer.get() {
        Some(writer) => writer.reload(),
        None => Err(RequestedReloadError::NoFile),
    };
    let error = match result {
        Ok(reloaded) => {
            return (
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(reloaded),
            )
                .into_response();
        }
        Err(error) => error,
    };
    let reload = match &error {
        RequestedReloadError::NoFile => {
            return config_api::error(StatusCode::CONFLICT, "conflict", error.to_string());
        }
        RequestedReloadError::Stopped => {
            return config_api::error(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                error.to_string(),
            );
        }
        RequestedReloadError::Reload(reload) => reload,
    };
    tracing::error!("config reload failed; keeping the old config\n{reload}");
    let errors: Vec<String> = match reload {
        ReloadError::Config(errors) => errors.0.iter().map(ToString::to_string).collect(),
        other => vec![other.to_string()],
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({
            "error": "invalid_config",
            "error_description": error.to_string(),
            "errors": errors,
        })),
    )
        .into_response()
}

/// `POST /_mock/{issuer_id}/token`.
pub async fn issue(
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<TestTokenRequest>, JsonRejection>,
) -> Response {
    if !state.config.issuer.contains_key(&issuer_id) {
        return unknown_issuer(&issuer_id);
    }
    let req = match body {
        Ok(Json(req)) => req,
        Err(rejection) => {
            return OAuthError::json("invalid_request", format!("invalid body: {rejection}"))
                .into_response();
        }
    };
    let path = issuer_path(&state.config.issuer[&issuer_id].issuer_url).unwrap_or_default();
    let ctx = IssuerCtx {
        app: state,
        id: issuer_id,
        path,
    };
    match respond(&ctx, &headers, req).await {
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

async fn respond(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    req: TestTokenRequest,
) -> Result<serde_json::Value, OAuthError> {
    let invalid = |d: &str| OAuthError::json("invalid_request", d);
    let subject = match (req.user, req.sub) {
        (Some(id), None) => {
            if !ctx.app.config.user.contains_key(&id) {
                return Err(OAuthError::json(
                    "invalid_request",
                    format!("unknown user: {id}"),
                ));
            }
            Subject::User {
                id,
                overrides: req.claims,
            }
        }
        (None, Some(sub)) => Subject::Custom {
            sub,
            claims: req.claims,
        },
        _ => return Err(invalid("exactly one of user and sub is required")),
    };
    let client_id = req.client_id.as_deref().unwrap_or(DEFAULT_CLIENT_ID);
    let client = find_client(ctx, client_id).unwrap_or_else(|| ResolvedClient {
        key: client_id.to_owned(),
        client_id: client_id.to_owned(),
        config: ClientConfig {
            issuer: ctx.id.clone(),
            client_id: Some(client_id.to_owned()),
            ..ClientConfig::default()
        },
        lenient_registered: false,
        builtin: false,
    });
    let scope: Vec<String> = req
        .scope
        .as_deref()
        .unwrap_or(DEFAULT_SCOPE)
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let keys = ctx.keys().await?;
    issue_user_tokens(
        ctx,
        &keys.active,
        &UserGrant {
            iss: &ctx.issuer_url(headers),
            client: &client,
            subject: &subject,
            scope: &scope,
            audience: req.audience.as_deref(),
            auth_time: ctx.app.now(),
            sid: None,
            nonce: None,
            refresh: RefreshMode::ByPolicy,
            refresh_scope: None,
            expires_in: req.expires_in,
        },
    )
    .await
}
