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

use crate::config::{Loaded, UserConfig};
use crate::config_api::{bad_body, write};
use crate::state::AppState;
use crate::users::{self, NewUser};

fn not_found(id: &str) -> Response {
    crate::config_api::not_found("user", id)
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
