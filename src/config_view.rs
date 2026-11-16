//! `GET /_mock/config`: the running config with the source of each value. Secrets are
//! masked the same as in `fauxidc config` ([`masked`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;

use crate::config::{Entry, LoadInputs, SourceMap, entries, load, masked};
use crate::config_api::error;
use crate::reload::ConfigWriter;
use crate::state::AppState;

/// The source of a value that the config inputs do not give now.
pub const UNKNOWN_SOURCE: &str = "unknown";

/// The answer format of `GET /_mock/config`.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// `{"config": .., "sources": {"<dotted path>": "<source>"}}`.
    #[default]
    Json,
    /// The config as TOML, without sources.
    Toml,
}

/// The query of `GET /_mock/config`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewQuery {
    #[serde(default)]
    pub format: Format,
}

/// The source of each leaf of the running config, by dotted path.
///
/// The running config has no source map: a reload applies a config only. So the load inputs
/// are loaded again. A leaf gets the source of the new load when the new load has the same
/// (masked) value there. Else, or when the new load fails or there are no load inputs, the
/// source is `unknown`. This happens for a restart-only key that changed in a file, and for a
/// file change that the poller has not applied yet.
#[must_use]
pub fn sources(running: &[Entry], inputs: Option<&LoadInputs>) -> BTreeMap<String, String> {
    let fresh: BTreeMap<String, Entry> =
        inputs
            .and_then(|inputs| load(inputs).ok())
            .map_or_else(BTreeMap::new, |loaded| {
                entries(&masked(&loaded.config), &loaded.sources)
                    .into_iter()
                    .map(|e| (e.path.clone(), e))
                    .collect()
            });
    running
        .iter()
        .map(|e| {
            let source = fresh
                .get(&e.path)
                .filter(|f| f.value == e.value)
                .map_or_else(|| UNKNOWN_SOURCE.to_owned(), |f| f.source.to_string());
            (e.path.clone(), source)
        })
        .collect()
}

/// `GET /_mock/config[?format=json|toml]`: the config of this app version, secrets masked.
/// 400 `invalid_request` for an unknown format or query parameter.
pub async fn view(
    State(state): State<Arc<AppState>>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> Response {
    let Query(q) = match query {
        Ok(q) => q,
        Err(rejection) => {
            return error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                format!("invalid query: {rejection}"),
            );
        }
    };
    let root = masked(&state.config);
    let mut response = match q.format {
        Format::Toml => match toml::to_string(&root) {
            Ok(text) => (
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/toml"),
                )],
                text,
            )
                .into_response(),
            Err(e) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    format!("cannot render the config: {e}"),
                );
            }
        },
        Format::Json => {
            let running = entries(&root, &SourceMap::new());
            let sources = sources(
                &running,
                state.config_writer.get().map(ConfigWriter::inputs),
            );
            Json(json!({ "config": root, "sources": sources })).into_response()
        }
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
