//! The Test API: `POST /_mock/{issuer_id}/token` issues tokens without a browser, and
//! `POST /_mock/{issuer_id}/rotate-key` rotates an Issuer's signing key.
//!
//! The endpoint has no authentication. fauxidc must never run in production.

use std::sync::Arc;

use axum::{
    Json,
    extract::{
        Path, Query, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::clients::{ResolvedClient, find_client};
use crate::config::{Claims, ClientConfig};
use crate::error::OAuthError;
use crate::issuer::issuer_path;
use crate::state::{AppState, IssuerCtx, Subject, now_secs};
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

/// `POST /_mock/{issuer_id}/rotate-key[?retire=true]`: a new active key with the Issuer's
/// `signing_alg`; older keys stay in JWKS unless `retire=true`. 200 with the [`Rotation`]
/// JSON; 404 `not_found` for an unknown Issuer id.
///
/// [`Rotation`]: crate::keys::Rotation
pub async fn rotate_key(
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
    query: Result<Query<RotateQuery>, QueryRejection>,
) -> Response {
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

/// `POST /_mock/{issuer_id}/token`.
pub async fn issue(
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
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
    match respond(&ctx, req).await {
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

async fn respond(ctx: &IssuerCtx, req: TestTokenRequest) -> Result<serde_json::Value, OAuthError> {
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
            client: &client,
            subject: &subject,
            scope: &scope,
            audience: req.audience.as_deref(),
            auth_time: now_secs(),
            sid: None,
            nonce: None,
            refresh: RefreshMode::ByPolicy,
            refresh_scope: None,
            expires_in: req.expires_in,
        },
    )
}
