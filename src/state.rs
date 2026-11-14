//! Shared application state and the per-issuer request context.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::HeaderMap;

use crate::config::{ClientConfig, Config, IssuerConfig};
use crate::error::StartError;
use crate::issuer::endpoint_base;
use crate::keys::KeyHandle;

/// In-memory stores. Part 3 adds fields.
#[derive(Default)]
pub struct Store {
    /// Clients registered on the fly in Lenient mode, by `(issuer id, client_id)`.
    pub lenient_clients: Mutex<HashMap<(String, String), ClientConfig>>,
}

/// State shared by all handlers.
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: KeyHandle,
    pub store: Store,
}

impl AppState {
    pub fn new(config: Config, keys: KeyHandle) -> Result<AppState, StartError> {
        Ok(AppState {
            config: Arc::new(config),
            keys,
            store: Store::default(),
        })
    }
}

/// State of one issuer: the app state, the issuer id and its normalized path.
#[derive(Clone)]
pub struct IssuerCtx {
    pub app: Arc<AppState>,
    pub id: String,
    pub path: String,
}

impl IssuerCtx {
    /// The configuration of this issuer.
    ///
    /// The router only creates a context for an id that is in the configuration.
    pub fn issuer(&self) -> &IssuerConfig {
        &self.app.config.issuer[&self.id]
    }

    /// The URL that endpoint paths are appended to, without a trailing slash.
    pub fn base_url(&self, headers: &HeaderMap) -> String {
        endpoint_base(&self.app.config.server, self.issuer(), headers)
    }
}

/// Builds an issuer context from inline TOML. For tests.
#[cfg(test)]
pub(crate) fn test_ctx(toml: &str, issuer_id: &str) -> IssuerCtx {
    let loaded = crate::config::load_str(toml).expect("test config loads");
    let (keys, _publisher) = KeyHandle::channel();
    let app = Arc::new(AppState::new(loaded.config, keys).expect("test state builds"));
    IssuerCtx {
        app,
        id: issuer_id.to_owned(),
        path: format!("/{issuer_id}"),
    }
}
