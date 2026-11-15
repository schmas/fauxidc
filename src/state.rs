//! Shared application state and the per-issuer request context.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};

use crate::config::{Claims, ClientConfig, Config, Endpoint, IssuerConfig};
use crate::error::{OAuthError, StartError};
use crate::issuer::endpoint_base;
use crate::jwks_fetch::CACHE_TTL_SECS;
use crate::keys::{KeyHandle, KeySet, Keyring};
use crate::request_log::RequestLog;
use crate::templates::Templates;

/// The PKCE code challenge method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceMethod {
    S256,
    Plain,
}

/// Who signed in. Serialized into refresh tokens as `{"kind": "user" | "custom", ..}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    /// A configured user, with claim overrides from the login form.
    User { id: String, overrides: Claims },
    /// A custom subject typed on the login page.
    Custom { sub: String, claims: Claims },
}

/// What an authorization code stands for.
#[derive(Debug, Clone)]
pub struct CodeGrant {
    pub issuer_id: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Vec<String>,
    pub nonce: Option<String>,
    pub pkce: Option<(String, PkceMethod)>,
    pub audience: Option<String>,
    pub subject: Subject,
    pub auth_time: u64,
    pub expires_at: u64,
}

/// The current time in seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// In-memory stores.
#[derive(Default)]
pub struct Store {
    /// Clients registered on the fly in Lenient mode, by `(issuer id, client_id)`.
    pub lenient_clients: Mutex<HashMap<(String, String), ClientConfig>>,
    /// Issued authorization codes that are not yet used.
    pub codes: Mutex<HashMap<String, CodeGrant>>,
    /// Used refresh token `jti`s of rotating Clients.
    pub used_refresh: Mutex<HashMap<String, UsedRefresh>>,
    /// Revoked token `jti`s and their `exp`, for `/introspect` and the refresh grant.
    pub revoked: Mutex<HashMap<String, u64>>,
    /// Used client assertion `jti`s by `(client_id, jti)`, and their `exp`.
    pub used_assertions: Mutex<HashMap<(String, String), u64>>,
    /// Fetched Client JWK sets by `jwks_uri`: when they were fetched, and the set.
    pub jwks_cache: Mutex<HashMap<String, (u64, Arc<JwkSet>)>>,
}

/// When a refresh token was first used, and when it expires.
#[derive(Debug, Clone, Copy)]
pub struct UsedRefresh {
    pub used_at: u64,
    pub exp: u64,
}

impl Store {
    /// Stores a grant under a new random code and returns the code. Drops expired entries.
    pub fn insert_code(&self, g: CodeGrant) -> Result<String, OAuthError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| OAuthError::ServerError(format!("random source failed: {e}")))?;
        let code = URL_SAFE_NO_PAD.encode(bytes);
        let mut codes = self
            .codes
            .lock()
            .map_err(|_| OAuthError::ServerError("code store lock poisoned".into()))?;
        let now = now_secs();
        codes.retain(|_, grant| grant.expires_at > now);
        codes.insert(code.clone(), g);
        Ok(code)
    }

    /// Records the first use of `jti`. Returns true on the first use, or on a reuse when
    /// `leeway > 0` and `now <= used_at + leeway`, so the window includes both ends, in whole
    /// seconds. Drops entries whose `exp` has passed. One lock for the check and the insert.
    pub fn use_refresh_jti(&self, jti: &str, exp: u64, now: u64, leeway: u64) -> bool {
        let mut used = self
            .used_refresh
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        used.retain(|_, u| u.exp >= now);
        if let Some(u) = used.get(jti) {
            return leeway > 0 && now <= u.used_at.saturating_add(leeway);
        }
        used.insert(jti.to_owned(), UsedRefresh { used_at: now, exp });
        true
    }

    /// Records the use of a client assertion `jti`. Returns true on the first use. Drops
    /// entries whose `exp` has passed. One lock for the check and the insert.
    pub fn use_assertion_jti(&self, client_id: &str, jti: &str, exp: u64, now: u64) -> bool {
        let mut used = self
            .used_assertions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        used.retain(|_, e| *e >= now);
        let key = (client_id.to_owned(), jti.to_owned());
        if used.contains_key(&key) {
            return false;
        }
        used.insert(key, exp);
        true
    }

    /// The cached JWK set of `url`. `None` when absent or older than `CACHE_TTL_SECS`.
    pub fn cached_jwks(&self, url: &str, now: u64) -> Option<Arc<JwkSet>> {
        self.jwks_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(url)
            .filter(|(fetched_at, _)| now < fetched_at.saturating_add(CACHE_TTL_SECS))
            .map(|(_, set)| set.clone())
    }

    /// Stores the JWK set fetched from `url` at `now`.
    pub fn cache_jwks(&self, url: &str, now: u64, set: Arc<JwkSet>) {
        self.jwks_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(url.to_owned(), (now, set));
    }

    /// When `jti` was first used, if it was used and has not expired from the store.
    pub fn refresh_used_at(&self, jti: &str) -> Option<u64> {
        self.used_refresh
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(jti)
            .map(|u| u.used_at)
    }

    /// Adds `jti` to the revocation list until `exp`. Drops entries whose `exp` has passed.
    pub fn revoke(&self, jti: &str, exp: u64) {
        let mut revoked = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        let now = now_secs();
        revoked.retain(|_, e| *e >= now);
        revoked.insert(jti.to_owned(), exp);
    }

    /// `true` if `jti` is on the revocation list. Drops entries whose `exp` has passed.
    pub fn is_revoked(&self, jti: &str) -> bool {
        let mut revoked = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        let now = now_secs();
        revoked.retain(|_, e| *e >= now);
        revoked.contains_key(jti)
    }

    /// Removes and returns the grant for `code`. A code works once.
    pub fn take_code(&self, code: &str) -> Option<CodeGrant> {
        self.codes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(code)
    }
}

/// State shared by all handlers.
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: Arc<Keyring>,
    pub store: Store,
    pub templates: Templates,
    pub request_log: RequestLog,
}

impl AppState {
    /// Builds the state. `keys` is the server key; [`Keyring::start`] gives each Issuer its
    /// key set from it. Must run inside a tokio runtime when an Issuer needs its own key.
    pub fn new(config: Config, keys: KeyHandle) -> Result<AppState, StartError> {
        let templates = Templates::load(&config).map_err(StartError::Templates)?;
        let keys = Arc::new(Keyring::start(&config, keys).map_err(StartError::Key)?);
        let request_log = RequestLog::new(config.server.request_log_size);
        Ok(AppState {
            config: Arc::new(config),
            keys,
            store: Store::default(),
            templates,
            request_log,
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

    /// The key set of this Issuer. Waits for its first key.
    pub async fn keys(&self) -> Result<Arc<KeySet>, OAuthError> {
        self.app
            .keys
            .key_set(&self.id)
            .await
            .map_err(|_| OAuthError::Unavailable)
    }

    /// The URL that endpoint paths are appended to, without a trailing slash.
    pub fn base_url(&self, headers: &HeaderMap) -> String {
        endpoint_base(&self.app.config.server, self.issuer(), headers)
    }

    /// The router path of `e` relative to the Issuer path, for example `/oauth/token`.
    pub fn endpoint_path(&self, e: Endpoint) -> &str {
        self.issuer().paths.get(e)
    }

    /// The absolute URL of `e`: the base URL plus the endpoint path.
    pub fn endpoint_url(&self, headers: &HeaderMap, e: Endpoint) -> String {
        format!("{}{}", self.base_url(headers), self.endpoint_path(e))
    }

    /// The absolute path of `e` on this server, for HTML forms: the Issuer path plus
    /// the endpoint path, with one `/` between them.
    pub fn endpoint_href(&self, e: Endpoint) -> String {
        format!(
            "{}{}",
            self.path.trim_end_matches('/'),
            self.endpoint_path(e)
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_single_use() {
        let store = Store::default();
        let grant = CodeGrant {
            issuer_id: "auth0".into(),
            client_id: "example-app".into(),
            redirect_uri: "http://localhost:3000/cb".into(),
            scope: vec!["openid".into()],
            nonce: None,
            pkce: None,
            audience: None,
            subject: Subject::Custom {
                sub: "c-1".into(),
                claims: Claims::new(),
            },
            auth_time: now_secs(),
            expires_at: now_secs() + 60,
        };
        let code = store.insert_code(grant).unwrap();
        assert!(store.take_code(&code).is_some());
        assert!(store.take_code(&code).is_none());
    }

    #[test]
    fn refresh_jti_is_single_use_at_leeway_zero() {
        let store = Store::default();
        assert!(store.use_refresh_jti("j", 1000, 10, 0));
        assert_eq!(store.refresh_used_at("j"), Some(10));
        assert!(!store.use_refresh_jti("j", 1000, 10, 0));
        assert!(!store.use_refresh_jti("j", 1000, 11, 0));
    }

    #[test]
    fn refresh_jti_parallel_threads_get_one_success() {
        let store = Store::default();
        let wins = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| store.use_refresh_jti("j", 1000, 10, 0)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count()
        });
        assert_eq!(wins, 1);
    }

    #[test]
    fn used_assertion_parallel_one_success() {
        let store = Store::default();
        let wins = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| store.use_assertion_jti("backend", "j", 1000, 10)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|won| *won)
                .count()
        });
        assert_eq!(wins, 1);
    }

    #[test]
    fn jwks_cache_expires_after_the_ttl() {
        let store = Store::default();
        assert!(store.cached_jwks("u", 100).is_none());
        store.cache_jwks("u", 100, Arc::new(JwkSet { keys: Vec::new() }));
        assert!(store.cached_jwks("u", 100 + CACHE_TTL_SECS - 1).is_some());
        assert!(store.cached_jwks("u", 100 + CACHE_TTL_SECS).is_none());
    }

    #[test]
    fn used_assertion_is_per_client_and_pruned() {
        let store = Store::default();
        assert!(store.use_assertion_jti("a", "j", 20, 10));
        assert!(store.use_assertion_jti("b", "j", 20, 10));
        assert!(!store.use_assertion_jti("a", "j", 20, 10));
        // After exp the entry is dropped (the assertion itself has expired by then).
        assert!(store.use_assertion_jti("a", "j", 40, 21));
    }

    #[test]
    fn refresh_jti_reuse_within_leeway() {
        let store = Store::default();
        assert!(store.use_refresh_jti("j", 1000, 10, 5));
        assert!(store.use_refresh_jti("j", 1000, 15, 5));
        assert!(!store.use_refresh_jti("j", 1000, 16, 5));
        // The first use time stays; a reuse does not extend the window.
        assert_eq!(store.refresh_used_at("j"), Some(10));
    }

    #[test]
    fn revoke_and_prune() {
        let store = Store::default();
        assert!(!store.is_revoked("j"));
        store.revoke("j", now_secs() + 60);
        assert!(store.is_revoked("j"));
        store.revoke("old", 1);
        assert!(!store.is_revoked("old"));
        assert!(!store.revoked.lock().unwrap().contains_key("old"));
        assert!(store.is_revoked("j"));
    }

    #[test]
    fn expired_refresh_jti_is_pruned() {
        let store = Store::default();
        assert!(store.use_refresh_jti("old", 20, 10, 0));
        assert!(store.use_refresh_jti("new", 1000, 30, 0));
        assert_eq!(store.refresh_used_at("old"), None);
        assert_eq!(store.refresh_used_at("new"), Some(30));
    }
}
