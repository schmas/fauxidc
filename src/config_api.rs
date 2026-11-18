//! Shared code of the Test API routes that change the config file: `/_mock/users` and
//! `/_mock/clients` (ADR 0008).

use axum::{
    Json,
    extract::rejection::JsonRejection,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::config::edit::{Edit, EditError};
use crate::config::{LoadInputs, Loaded};
use crate::reload::WriteError;
use crate::state::AppState;
use crate::test_api::same_origin_or_none;

/// A JSON error answer with `Cache-Control: no-store`.
pub(crate) fn error(status: StatusCode, code: &str, description: impl Into<String>) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({ "error": code, "error_description": description.into() })),
    )
        .into_response()
}

/// 404 `not_found` for an unknown entry, for example `unknown user: zed`.
pub(crate) fn not_found(noun: &str, id: &str) -> Response {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("unknown {noun}: {id}"),
    )
}

/// 400 `invalid_request` for a body that is not valid JSON.
pub(crate) fn bad_body(rejection: &JsonRejection) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        format!("invalid body: {rejection}"),
    )
}

/// The answer to a failed write.
pub(crate) fn write_error(e: &WriteError) -> Response {
    let (status, code) = match e {
        WriteError::Edit(edit) => match edit {
            EditError::InvalidId(_) | EditError::BadInput(_) | EditError::Invalid(_) => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            EditError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found"),
            EditError::NoFile
            | EditError::Exists { .. }
            | EditError::Conflict { .. }
            | EditError::Lenient { .. } => (StatusCode::CONFLICT, "conflict"),
            EditError::Parse { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        },
        // Like `NoFile`: the server has no file it can write. A retry does not help, so 409, not
        // 503.
        WriteError::ReadOnly { .. } => (StatusCode::CONFLICT, "conflict"),
        WriteError::Io { .. } | WriteError::Reload(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
        WriteError::Stopped => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    };
    error(status, code, e.to_string())
}

/// Checks the origin, writes the edit of `prepare`, applies it, then answers with `respond`.
pub(crate) fn write(
    state: &AppState,
    headers: &HeaderMap,
    prepare: impl FnOnce(&LoadInputs) -> Result<Edit, EditError>,
    respond: impl FnOnce(&Loaded) -> Response,
) -> Response {
    if !same_origin_or_none(state, headers) {
        return error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "cross-origin Test API request",
        );
    }
    let Some(writer) = state.config_writer.get() else {
        return write_error(&WriteError::Edit(EditError::NoFile));
    };
    match writer.write(prepare) {
        Ok(loaded) => respond(&loaded),
        Err(e) => write_error(&e),
    }
}
