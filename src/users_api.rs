//! The Test API for Users: `/_mock/users` and `/_mock/users/{user_id}`.
//!
//! Reads show the running config. Writes change the last config file and apply it at once
//! (ADR 0008). The routes have no authentication, the same as the rest of the Test API.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::config::UserConfig;
use crate::config::edit::{Edit, EditError};
use crate::config::{LoadInputs, Loaded};
use crate::reload::WriteError;
use crate::state::AppState;
use crate::test_api::same_origin_or_none;
use crate::users::{self, NewUser};

fn error(status: StatusCode, code: &str, description: impl Into<String>) -> Response {
    (
        status,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({ "error": code, "error_description": description.into() })),
    )
        .into_response()
}

fn not_found(id: &str) -> Response {
    error(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("unknown user: {id}"),
    )
}

fn bad_body(rejection: &JsonRejection) -> Response {
    error(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        format!("invalid body: {rejection}"),
    )
}

fn write_error(e: &WriteError) -> Response {
    let (status, code) = match e {
        WriteError::Edit(edit) => match edit {
            EditError::InvalidId(_) | EditError::BadInput(_) | EditError::Invalid(_) => {
                (StatusCode::BAD_REQUEST, "invalid_request")
            }
            EditError::NotFound { .. } => (StatusCode::NOT_FOUND, "not_found"),
            EditError::NoFile | EditError::Exists { .. } | EditError::Conflict { .. } => {
                (StatusCode::CONFLICT, "conflict")
            }
            EditError::Parse { .. } => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        },
        WriteError::Io { .. } | WriteError::Reload(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        }
        WriteError::Stopped => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
    };
    error(status, code, e.to_string())
}

/// Checks the origin, writes the edit of `prepare`, applies it, then answers with `respond`.
fn write(
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

fn view(loaded: &Loaded, id: &str) -> Response {
    match users::get(&loaded.config, id) {
        Some(user) => Json(user).into_response(),
        None => not_found(id),
    }
}

/// `GET /_mock/users`: all Users of the running config.
pub async fn list(State(state): State<Arc<AppState>>) -> Response {
    Json(users::list(&state.config)).into_response()
}

/// `GET /_mock/users/{user_id}`: one User, or 404.
pub async fn get(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> Response {
    match users::get(&state.config, &id) {
        Some(user) => Json(user).into_response(),
        None => not_found(&id),
    }
}

/// `POST /_mock/users`: adds a User. 201 with the User; 409 if the id exists.
pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Json<NewUser>, JsonRejection>,
) -> Response {
    let (id, user) = match body {
        Ok(Json(new)) => new.into_parts(),
        Err(rejection) => return bad_body(&rejection),
    };
    write(
        &state,
        &headers,
        |inputs| users::create(inputs, &id, &user),
        |loaded| {
            let mut response = view(loaded, &id);
            *response.status_mut() = StatusCode::CREATED;
            if let Ok(location) = HeaderValue::from_str(&format!("/_mock/users/{id}")) {
                response.headers_mut().insert(header::LOCATION, location);
            }
            response
        },
    )
}

/// `PUT /_mock/users/{user_id}`: replaces a User. 404 if it does not exist.
pub async fn replace(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UserConfig>, JsonRejection>,
) -> Response {
    let user = match body {
        Ok(Json(user)) => user,
        Err(rejection) => return bad_body(&rejection),
    };
    write(
        &state,
        &headers,
        |inputs| users::replace(inputs, &id, &user),
        |loaded| view(loaded, &id),
    )
}

/// `PATCH /_mock/users/{user_id}`: merges a JSON Merge Patch (RFC 7396) into a User.
pub async fn merge(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let patch = match body {
        Ok(Json(patch)) => patch,
        Err(rejection) => return bad_body(&rejection),
    };
    write(
        &state,
        &headers,
        |inputs| users::merge(inputs, &id, &patch),
        |loaded| view(loaded, &id),
    )
}

/// `DELETE /_mock/users/{user_id}`: removes a User. 204; 404 if it does not exist.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    write(
        &state,
        &headers,
        |inputs| users::remove(inputs, &id),
        |_| StatusCode::NO_CONTENT.into_response(),
    )
}
