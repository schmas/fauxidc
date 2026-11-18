//! The Test API for the login page setting: `GET` and `PUT /_mock/{issuer_id}/login`.
//!
//! The setting is `issuer.<id>.show_user_list`. A write changes the last config file when
//! there is one (ADR 0008). Else, or when the file is read-only, the value stays in memory until
//! `DELETE /_mock/state`.
//! The routes have no authentication, the same as the rest of the Test API.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::config::edit::{EditError, prepare_issuer_bool};
use crate::config::{Loaded, Source, load};
use crate::config_api::{bad_body, error, write_error};
use crate::reload::WriteError;
use crate::state::AppState;
use crate::test_api::{same_origin_or_none, unknown_issuer};

const KEY: &str = "show_user_list";

/// The login page setting of an Issuer and where its value comes from.
#[derive(Debug, Clone, Serialize)]
pub struct LoginSetting {
    pub show_user_list: bool,
    /// `default`, `file`, `memory`, `env`, `inline`, `flag` or `unknown`.
    pub source: &'static str,
    /// The file position, env var or flag, for `file`, `env` and `flag`. Else null.
    pub origin: Option<String>,
}

/// The body of `PUT /_mock/{issuer_id}/login`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginBody {
    pub show_user_list: bool,
}

fn memory(value: bool) -> LoginSetting {
    LoginSetting {
        show_user_list: value,
        source: "memory",
        origin: None,
    }
}

fn from_loaded(loaded: &Loaded, issuer_id: &str, running: bool) -> LoginSetting {
    let path = ["issuer".to_owned(), issuer_id.to_owned(), KEY.to_owned()];
    let (source, origin) = match loaded.sources.get(path.as_slice()) {
        None | Some(Source::Default) => ("default", None),
        Some(s @ Source::File { .. }) => ("file", Some(s.to_string())),
        Some(s @ Source::Env(_)) => ("env", Some(s.to_string())),
        Some(s @ Source::Flag(_)) => ("flag", Some(s.to_string())),
        Some(Source::Inline) => ("inline", None),
    };
    LoginSetting {
        show_user_list: running,
        source,
        origin,
    }
}

/// The login setting of an Issuer, or `None` for an unknown Issuer.
///
/// A memory value wins. Else the source comes from loading the config inputs again. If there
/// are no inputs, or the new load has another value, the source is `default` for `false` and
/// `unknown` for `true`.
#[must_use]
pub fn setting(state: &AppState, issuer_id: &str) -> Option<LoginSetting> {
    let issuer = state.config.issuer.get(issuer_id)?;
    if let Some(value) = state.store.show_user_list_of(issuer_id) {
        return Some(memory(value));
    }
    let running = issuer.show_user_list;
    let fresh = state
        .config_writer
        .get()
        .and_then(|writer| load(writer.inputs()).ok())
        .filter(|loaded| {
            loaded
                .config
                .issuer
                .get(issuer_id)
                .is_some_and(|i| i.show_user_list == running)
        });
    Some(match fresh {
        Some(loaded) => from_loaded(&loaded, issuer_id, running),
        None => LoginSetting {
            show_user_list: running,
            source: if running { "unknown" } else { "default" },
            origin: None,
        },
    })
}

fn no_store(response: impl IntoResponse) -> Response {
    let mut response = response.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// `GET /_mock/{issuer_id}/login`: the setting. 404 for an unknown Issuer.
pub async fn get(State(state): State<Arc<AppState>>, Path(issuer_id): Path<String>) -> Response {
    match setting(&state, &issuer_id) {
        Some(setting) => no_store(Json(setting)),
        None => unknown_issuer(&issuer_id),
    }
}

/// `PUT /_mock/{issuer_id}/login`: sets `show_user_list`. Writes the config file, or keeps the
/// value in memory when there is no file or the file is read-only.
pub async fn put(
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<LoginBody>, JsonRejection>,
) -> Response {
    if !same_origin_or_none(&state, &headers) {
        return error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "cross-origin Test API request",
        );
    }
    if !state.config.issuer.contains_key(&issuer_id) {
        return unknown_issuer(&issuer_id);
    }
    let value = match body {
        Ok(Json(body)) => body.show_user_list,
        Err(rejection) => return bad_body(&rejection),
    };
    let Some(writer) = state.config_writer.get() else {
        return keep_in_memory(&state, &issuer_id, value);
    };
    match writer.write(|inputs| prepare_issuer_bool(inputs, &issuer_id, KEY, value)) {
        Ok(loaded) => {
            state.store.remove_show_user_list(&issuer_id);
            let answer = from_loaded(&loaded, &issuer_id, value);
            tracing::info!(issuer = %issuer_id, value, "login setting saved in the config file");
            no_store(Json(answer))
        }
        Err(WriteError::Edit(EditError::NoFile)) => keep_in_memory(&state, &issuer_id, value),
        Err(WriteError::ReadOnly { path }) => {
            tracing::warn!(
                issuer = %issuer_id,
                file = %path.display(),
                "config file is read-only; login setting kept in memory"
            );
            keep_in_memory(&state, &issuer_id, value)
        }
        Err(e) => write_error(&e),
    }
}

fn keep_in_memory(state: &AppState, issuer_id: &str, value: bool) -> Response {
    state.store.set_show_user_list(issuer_id, value);
    tracing::info!(issuer = %issuer_id, value, "login setting kept in memory");
    no_store(Json(memory(value)))
}
