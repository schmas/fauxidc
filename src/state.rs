//! Shared application state and the per-issuer request context.

use std::sync::Arc;

use axum::http::HeaderMap;

use crate::config::{Config, IssuerConfig};
use crate::error::StartError;
use crate::issuer::endpoint_base;
use crate::keys::KeyHandle;

/// In-memory stores. Part 3 adds fields.
#[derive(Default)]
pub struct Store {}

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
