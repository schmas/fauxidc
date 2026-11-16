//! The Test API for Clients: `/_mock/clients` and `/_mock/clients/{client_key}`.
//!
//! The path uses the config key (`[client.<key>]`), not the `client_id`. Reads show the running
//! config and the Lenient-registered Clients, with `client_secret` masked. Writes change the last
//! config file and apply it at once (ADR 0008). A Lenient-registered Client is read-only. The
//! routes have no authentication, the same as the rest of the Test API.

use std::sync::{Arc, PoisonError};

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::clients_admin::{self, LenientClients};
use crate::config::edit::{Edit, EditError};
use crate::config::{ClientConfig, LoadInputs, Loaded};
use crate::config_api::{bad_body, not_found, write, write_error};
use crate::reload::WriteError;
use crate::state::AppState;

fn lenient(state: &AppState) -> LenientClients {
    state
        .store
        .lenient_clients
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn view(loaded: &Loaded, key: &str) -> Response {
    match clients_admin::get(&loaded.config, &LenientClients::new(), key) {
        Some(client) => Json(client).into_response(),
        None => not_found("client", key),
    }
}

/// Refuses a change to a Lenient-registered Client, then prepares the edit.
fn writable(
    state: &AppState,
    key: &str,
    prepare: impl FnOnce(&LoadInputs) -> Result<Edit, EditError>,
) -> impl FnOnce(&LoadInputs) -> Result<Edit, EditError> {
    let checked = clients_admin::check_writable(&state.config, &lenient(state), key);
    move |inputs| {
        checked?;
        prepare(inputs)
    }
}

/// `GET /_mock/clients`: the configured Clients, then the Lenient-registered Clients.
pub async fn list(State(state): State<Arc<AppState>>) -> Response {
    Json(clients_admin::list(&state.config, &lenient(&state))).into_response()
}

/// `GET /_mock/clients/{client_key}`: one Client, or 404.
pub async fn get(State(state): State<Arc<AppState>>, Path(key): Path<String>) -> Response {
    match clients_admin::get(&state.config, &lenient(&state), &key) {
        Some(client) => Json(client).into_response(),
        None => not_found("client", &key),
    }
}

/// `POST /_mock/clients`: adds a Client. 201 with the Client; 409 if the key exists.
pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Result<Json<serde_json::Value>, JsonRejection>,
) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(rejection) => return bad_body(&rejection),
    };
    let (key, client) = match clients_admin::split_new(body) {
        Ok(parts) => parts,
        Err(e) => return write_error(&WriteError::Edit(e)),
    };
    write(
        &state,
        &headers,
        |inputs| clients_admin::create(inputs, &key, &client),
        |loaded| {
            let mut response = view(loaded, &key);
            *response.status_mut() = StatusCode::CREATED;
            if let Ok(location) = HeaderValue::from_str(&format!("/_mock/clients/{key}")) {
                response.headers_mut().insert(header::LOCATION, location);
            }
            response
        },
    )
}

/// `PUT /_mock/clients/{client_key}`: replaces a Client. 404 if it does not exist.
pub async fn replace(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ClientConfig>, JsonRejection>,
) -> Response {
    let client = match body {
        Ok(Json(client)) => client,
        Err(rejection) => return bad_body(&rejection),
    };
    write(
        &state,
        &headers,
        writable(&state, &key, |inputs| {
            clients_admin::replace(inputs, &key, &client)
        }),
        |loaded| view(loaded, &key),
    )
}

/// `PATCH /_mock/clients/{client_key}`: merges a JSON Merge Patch (RFC 7396) into a Client.
pub async fn merge(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
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
        writable(&state, &key, |inputs| {
            clients_admin::merge(inputs, &key, &patch)
        }),
        |loaded| view(loaded, &key),
    )
}

/// `DELETE /_mock/clients/{client_key}`: removes a Client. 204; 404 if it does not exist.
pub async fn remove(
    State(state): State<Arc<AppState>>,
    Path(key): Path<String>,
    headers: HeaderMap,
) -> Response {
    write(
        &state,
        &headers,
        writable(&state, &key, |inputs| clients_admin::remove(inputs, &key)),
        |_| StatusCode::NO_CONTENT.into_response(),
    )
}
