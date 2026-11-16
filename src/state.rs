//! Shared application state and the per-issuer request context.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use axum::http::HeaderMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::jwk::JwkSet;
use serde::{Deserialize, Serialize};

use crate::clock::Clock;
use crate::config::{Claims, ClientConfig, Config, Endpoint, IssuerConfig};
use crate::error::{ConfigError, ConfigErrors, OAuthError, StartError};
use crate::failures::Injected;
use crate::issuer::{effective_issuer, endpoint_base};
use crate::jwks_fetch::CACHE_TTL_SECS;
use crate::keys::{KeyHandle, KeySet, Keyring};
use crate::reload::ConfigWriter;
use crate::reload::restart_only_changes;
use crate::request_log::RequestLog;
use crate::session::SessionStore;
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
    /// The Session `sid` of the sign-in; the ID token carries it.
    pub sid: Option<String>,
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
    /// The last unknown-`kid` refetch of each `jwks_uri`, in Unix seconds.
    pub jwks_refetched: Mutex<HashMap<String, u64>>,
    /// Sessions by cookie value.
    pub sessions: SessionStore,
    /// Injected failures by `(Issuer id, endpoint)`.
    pub failures: Mutex<HashMap<(String, String), Injected>>,
    /// Debugger login flows by `state`.
    pub debugger_flows: Mutex<HashMap<String, DebuggerFlow>>,
}

/// The most debugger flows the [`Store`] keeps.
pub const MAX_FLOWS: usize = 10_000;

/// A debugger login flow that waits for its callback.
#[derive(Debug, Clone)]
pub struct DebuggerFlow {
    pub issuer_id: String,
    /// The PKCE `code_verifier`; it never leaves the server.
    pub verifier: String,
    pub redirect_uri: String,
    pub expires_at: u64,
    /// The flow started from the debugger in the dashboard frame (`?embed=1`): the
    /// callback renders the page without its brand row and footer.
    pub embed: bool,
}

/// When a refresh token was first used, and when it expires.
#[derive(Debug, Clone, Copy)]
pub struct UsedRefresh {
    pub used_at: u64,
    pub exp: u64,
}

impl Store {
    /// Stores a grant under a new random code and returns the code. Drops entries expired at
    /// `now`.
    pub fn insert_code(&self, g: CodeGrant, now: u64) -> Result<String, OAuthError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|e| OAuthError::ServerError(format!("random source failed: {e}")))?;
        let code = URL_SAFE_NO_PAD.encode(bytes);
        let mut codes = self
            .codes
            .lock()
            .map_err(|_| OAuthError::ServerError("code store lock poisoned".into()))?;
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

    /// `true` and records `now` when no refetch of `url` happened in the last `cooldown`
    /// seconds.
    pub fn may_refetch(&self, url: &str, now: u64, cooldown: u64) -> bool {
        let mut refetched = self
            .jwks_refetched
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if refetched
            .get(url)
            .is_some_and(|last| now < last.saturating_add(cooldown))
        {
            return false;
        }
        refetched.insert(url.to_owned(), now);
        true
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

    /// Adds `jti` to the revocation list until `exp`. Drops entries whose `exp` is before `now`.
    pub fn revoke(&self, jti: &str, exp: u64, now: u64) {
        let mut revoked = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        revoked.retain(|_, e| *e >= now);
        revoked.insert(jti.to_owned(), exp);
    }

    /// `true` if `jti` is on the revocation list. Drops entries whose `exp` is before `now`.
    pub fn is_revoked(&self, jti: &str, now: u64) -> bool {
        let mut revoked = self.revoked.lock().unwrap_or_else(PoisonError::into_inner);
        revoked.retain(|_, e| *e >= now);
        revoked.contains_key(jti)
    }

    /// Stores the Injected failure of `endpoint`, replacing an older one. `None` removes it.
    pub fn inject(&self, issuer_id: &str, endpoint: &str, f: Option<Injected>) {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (issuer_id.to_owned(), endpoint.to_owned());
        match f {
            Some(f) if f.remaining > 0 => {
                failures.insert(key, f);
            }
            _ => {
                failures.remove(&key);
            }
        }
    }

    /// One use of the Injected failure of `endpoint`: returns a copy and decrements
    /// `remaining`; removes the entry at 0. One lock for the check and the update.
    pub fn take_failure(&self, issuer_id: &str, endpoint: &str) -> Option<Injected> {
        let mut failures = self.failures.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (issuer_id.to_owned(), endpoint.to_owned());
        let entry = failures.get_mut(&key)?;
        let taken = entry.clone();
        entry.remaining = entry.remaining.saturating_sub(1);
        if entry.remaining == 0 {
            failures.remove(&key);
        }
        Some(taken)
    }

    /// Removes every Injected failure of the Issuer.
    /// Clears the runtime state (spec 11): codes, Sessions, used refresh `jti`s, revocations,
    /// used client assertion `jti`s, Lenient-registered Clients, debugger flows, Injected
    /// failures and the Client JWKS cache. Config and signing keys do not change.
    ///
    /// With `issuer_id`, only the data that has an Issuer id is cleared, and only for that
    /// Issuer: codes, Sessions, Lenient Clients, debugger flows and Injected failures. The
    /// `jti` lists, revocations and the JWKS cache have no Issuer id and stay.
    ///
    /// Takes one lock at a time.
    pub fn reset(&self, issuer_id: Option<&str>) {
        fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
            m.lock().unwrap_or_else(PoisonError::into_inner)
        }
        // No `..`: a new field must be handled here before the crate compiles.
        let Store {
            lenient_clients,
            codes,
            used_refresh,
            revoked,
            used_assertions,
            jwks_cache,
            jwks_refetched,
            sessions,
            failures,
            debugger_flows,
        } = self;
        let other = |id: &str| issuer_id.is_some_and(|keep| keep != id);
        lock(codes).retain(|_, g| other(&g.issuer_id));
        sessions.clear(issuer_id);
        lock(lenient_clients).retain(|(id, _), _| other(id));
        lock(debugger_flows).retain(|_, f| other(&f.issuer_id));
        lock(failures).retain(|(id, _), _| other(id));
        if issuer_id.is_none() {
            lock(used_refresh).clear();
            lock(revoked).clear();
            lock(used_assertions).clear();
            lock(jwks_cache).clear();
            lock(jwks_refetched).clear();
        }
    }

    pub fn clear_failures(&self, issuer_id: &str) {
        self.failures
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(id, _), _| id != issuer_id);
    }

    /// Stores a debugger flow under `state`. Drops flows expired at `now`. Above [`MAX_FLOWS`],
    /// the flow with the smallest `expires_at` is dropped (plan Ruling 4).
    pub fn insert_flow(&self, state: String, f: DebuggerFlow, now: u64) {
        let mut flows = self
            .debugger_flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        flows.retain(|_, f| f.expires_at > now);
        flows.insert(state, f);
        while flows.len() > MAX_FLOWS {
            let Some(oldest) = flows
                .iter()
                .min_by_key(|(_, f)| f.expires_at)
                .map(|(state, _)| state.clone())
            else {
                break;
            };
            flows.remove(&oldest);
        }
    }

    /// Removes and returns the flow of `state`. A state works once; a flow expired at `now`
    /// gives `None`.
    pub fn take_flow(&self, state: &str, now: u64) -> Option<DebuggerFlow> {
        self.debugger_flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(state)
            .filter(|f| f.expires_at > now)
    }

    /// Removes and returns the grant for `code`. A code works once.
    pub fn take_code(&self, code: &str) -> Option<CodeGrant> {
        self.codes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(code)
    }
}

/// State shared by all handlers. One version per config: a reload builds the next version
/// with [`AppState::next`], which shares the `Store`, the `Keyring` and the `RequestLog`.
pub struct AppState {
    pub config: Arc<Config>,
    pub keys: Arc<Keyring>,
    pub store: Arc<Store>,
    pub templates: Templates,
    pub request_log: Arc<RequestLog>,
    /// The clock of `server.fixed_time` (ADR 0007). A reload builds it again.
    pub clock: Clock,
    /// Writes config file edits for the Test API (ADR 0008). Shared by all versions. Empty when
    /// the server was started without its load inputs (the library API).
    pub config_writer: Arc<OnceLock<ConfigWriter>>,
}

/// The clock of `config`. An invalid `server.fixed_time` is a config error.
fn clock_of(config: &Config) -> Result<Clock, StartError> {
    Clock::from_fixed_time(&config.server.fixed_time).map_err(|message| {
        StartError::Config(ConfigErrors(vec![ConfigError {
            origin: crate::config::Source::Default,
            message,
        }]))
    })
}

impl AppState {
    /// The current time of this config version, in seconds since the Unix epoch: the fixed
    /// time of `server.fixed_time`, else the system clock. Token times and token time checks
    /// use it (ADR 0007).
    #[must_use]
    pub fn now(&self) -> u64 {
        self.clock.now()
    }

    /// Builds the state. `keys` is the server key; [`Keyring::start`] gives each Issuer its
    /// key set from it; `server_key_from_file` is `true` when that key came from
    /// `server.key_file`. Must run inside a tokio runtime when an Issuer needs its own key.
    pub fn new(
        config: Config,
        keys: KeyHandle,
        server_key_from_file: bool,
    ) -> Result<AppState, StartError> {
        let clock = clock_of(&config)?;
        let templates = Templates::load(&config).map_err(StartError::Templates)?;
        let keys =
            Arc::new(Keyring::start(&config, keys, server_key_from_file).map_err(StartError::Key)?);
        let request_log = Arc::new(RequestLog::new(config.server.request_log_size));
        Ok(AppState {
            config: Arc::new(config),
            keys,
            store: Arc::new(Store::default()),
            templates,
            request_log,
            clock,
            config_writer: Arc::new(OnceLock::new()),
        })
    }

    /// The next version: new config and templates; the same `Store`, `Keyring` and `RequestLog`.
    /// Returns the restart warnings (from `restart_only_changes` and `Keyring::reconcile`).
    ///
    /// Keys that need a restart keep their running values in the stored config, so discovery
    /// and key rotation match the keys and the listener that exist. Must run inside a tokio
    /// runtime when a new Issuer needs its own key.
    pub fn next(&self, mut config: Config) -> Result<(AppState, Vec<String>), StartError> {
        let clock = clock_of(&config)?;
        let templates = Templates::load(&config).map_err(StartError::Templates)?;
        let mut warnings = restart_only_changes(&self.config, &config);
        for warning in self
            .keys
            .reconcile(&self.config, &config)
            .map_err(StartError::Key)?
        {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
        keep_running_values(&self.config, &self.keys, &mut config);
        Ok((
            AppState {
                config: Arc::new(config),
                keys: self.keys.clone(),
                store: self.store.clone(),
                templates,
                request_log: self.request_log.clone(),
                clock,
                config_writer: self.config_writer.clone(),
            },
            warnings,
        ))
    }
}

/// Puts the running values of the restart-only keys into `next`.
fn keep_running_values(running: &Config, keys: &Keyring, next: &mut Config) {
    let (old, new) = (&running.server, &mut next.server);
    new.port = old.port;
    new.bind.clone_from(&old.bind);
    new.log_format = old.log_format;
    new.request_log_size = old.request_log_size;
    new.key_file.clone_from(&old.key_file);
    new.tls.clone_from(&old.tls);
    for (id, issuer) in &mut next.issuer {
        if let Some((alg, key_file)) = keys.slot_settings(id) {
            issuer.signing_alg = alg;
            issuer.key_file = key_file;
        }
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

    /// The `iss` of this Issuer for a request with `headers` (ADR 0006).
    pub fn issuer_url(&self, headers: &HeaderMap) -> String {
        effective_issuer(&self.app.config.server, self.issuer(), headers)
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
    let app = Arc::new(AppState::new(loaded.config, keys, true).expect("test state builds"));
    IssuerCtx {
        app,
        id: issuer_id.to_owned(),
        path: format!("/{issuer_id}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Store with one entry of each kind for Issuers `a` and `b` (where the kind has an
    /// Issuer id).
    fn full_store() -> Store {
        let store = Store::default();
        for issuer in ["a", "b"] {
            let grant = CodeGrant {
                issuer_id: issuer.into(),
                client_id: "c".into(),
                redirect_uri: "http://localhost/cb".into(),
                scope: vec![],
                nonce: None,
                pkce: None,
                audience: None,
                subject: Subject::Custom {
                    sub: "s".into(),
                    claims: Claims::new(),
                },
                auth_time: 0,
                expires_at: u64::MAX,
                sid: None,
            };
            store.insert_code(grant, 0).unwrap();
            store
                .sessions
                .create(crate::session::Session {
                    issuer_id: issuer.into(),
                    subject: Subject::Custom {
                        sub: "s".into(),
                        claims: Claims::new(),
                    },
                    sid: issuer.into(),
                    auth_time: 0,
                })
                .unwrap();
            store
                .lenient_clients
                .lock()
                .unwrap()
                .insert((issuer.into(), "c".into()), ClientConfig::default());
            store.debugger_flows.lock().unwrap().insert(
                issuer.into(),
                DebuggerFlow {
                    issuer_id: issuer.into(),
                    verifier: String::new(),
                    redirect_uri: String::new(),
                    expires_at: u64::MAX,
                    embed: false,
                },
            );
            store.inject(
                issuer,
                "token",
                Some(crate::failures::Injected {
                    status: Some(500),
                    error: "server_error".into(),
                    remaining: 1,
                    delay_ms: 0,
                }),
            );
        }
        store.use_refresh_jti("j", u64::MAX, 0, 0);
        store.revoked.lock().unwrap().insert("r".into(), u64::MAX);
        store
            .used_assertions
            .lock()
            .unwrap()
            .insert(("c".into(), "j".into()), u64::MAX);
        store.jwks_cache.lock().unwrap().insert(
            "http://localhost/jwks".into(),
            (0, Arc::new(JwkSet { keys: vec![] })),
        );
        store
            .jwks_refetched
            .lock()
            .unwrap()
            .insert("http://localhost/jwks".into(), 0);
        store
    }

    /// The sizes of every Store field, in declaration order.
    fn sizes(store: &Store) -> [usize; 10] {
        [
            store.lenient_clients.lock().unwrap().len(),
            store.codes.lock().unwrap().len(),
            store.used_refresh.lock().unwrap().len(),
            store.revoked.lock().unwrap().len(),
            store.used_assertions.lock().unwrap().len(),
            store.jwks_cache.lock().unwrap().len(),
            store.jwks_refetched.lock().unwrap().len(),
            store.sessions.len(),
            store.failures.lock().unwrap().len(),
            store.debugger_flows.lock().unwrap().len(),
        ]
    }

    #[test]
    fn reset_clears_every_kind_of_state() {
        let store = full_store();
        assert_eq!(sizes(&store), [2, 2, 1, 1, 1, 1, 1, 2, 2, 2]);
        store.reset(None);
        assert_eq!(sizes(&store), [0; 10]);
    }

    #[test]
    fn reset_of_one_issuer_keeps_the_others_and_the_jti_lists() {
        let store = full_store();
        store.reset(Some("a"));
        assert_eq!(sizes(&store), [1, 1, 1, 1, 1, 1, 1, 1, 1, 1]);
        assert!(store.take_failure("b", "token").is_some());
        assert!(store.take_failure("a", "token").is_none());
    }

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
            auth_time: 1000,
            expires_at: 1060,
            sid: None,
        };
        let code = store.insert_code(grant, 1000).unwrap();
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
    fn may_refetch_once_per_cooldown() {
        let store = Store::default();
        assert!(store.may_refetch("u", 100, 10));
        assert!(!store.may_refetch("u", 109, 10));
        assert!(store.may_refetch("other", 109, 10));
        assert!(store.may_refetch("u", 110, 10));
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
        assert!(!store.is_revoked("j", 1000));
        store.revoke("j", 1060, 1000);
        assert!(store.is_revoked("j", 1000));
        store.revoke("old", 1, 1000);
        assert!(!store.is_revoked("old", 1000));
        assert!(!store.revoked.lock().unwrap().contains_key("old"));
        assert!(store.is_revoked("j", 1060));
        assert!(!store.is_revoked("j", 1061));
    }

    #[test]
    fn take_failure_is_exact_under_parallel_threads() {
        let store = Store::default();
        store.inject(
            "auth0",
            "jwks",
            Some(Injected {
                status: Some(500),
                error: "server_error".into(),
                remaining: 3,
                delay_ms: 0,
            }),
        );
        let taken = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| store.take_failure("auth0", "jwks")))
                .collect();
            handles
                .into_iter()
                .filter_map(|h| h.join().unwrap())
                .count()
        });
        assert_eq!(taken, 3);
        assert!(store.failures.lock().unwrap().is_empty());
    }

    #[test]
    fn failures_are_per_issuer_and_cleared_per_issuer() {
        let store = Store::default();
        let f = Injected {
            status: Some(503),
            error: "e".into(),
            remaining: 1,
            delay_ms: 0,
        };
        store.inject("auth0", "token", Some(f.clone()));
        store.inject("okta", "token", Some(f.clone()));
        assert!(store.take_failure("other", "token").is_none());
        store.clear_failures("auth0");
        assert!(store.take_failure("auth0", "token").is_none());
        assert_eq!(store.take_failure("okta", "token"), Some(f.clone()));
        store.inject("okta", "token", Some(f));
        store.inject("okta", "token", None);
        assert!(store.take_failure("okta", "token").is_none());
    }

    #[test]
    fn flow_store_is_capped() {
        let store = Store::default();
        let base = 2000;
        for i in 0..=MAX_FLOWS as u64 {
            // The flow "s0" has the smallest expires_at.
            store.insert_flow(
                format!("s{i}"),
                DebuggerFlow {
                    issuer_id: "a".into(),
                    verifier: "v".into(),
                    redirect_uri: "r".into(),
                    expires_at: base + i,
                    embed: false,
                },
                1000,
            );
        }
        assert_eq!(store.debugger_flows.lock().unwrap().len(), MAX_FLOWS);
        assert!(store.take_flow("s0", 1000).is_none());
        assert!(store.take_flow("s1", 1000).is_some());
        assert!(store.take_flow(&format!("s{MAX_FLOWS}"), 1000).is_some());
    }

    #[test]
    fn debugger_flow_is_single_use_and_expires() {
        let store = Store::default();
        let flow = |expires_at| DebuggerFlow {
            issuer_id: "auth0".into(),
            verifier: "v".into(),
            redirect_uri: "r".into(),
            expires_at,
            embed: false,
        };
        store.insert_flow("s".into(), flow(1060), 1000);
        assert!(store.take_flow("s", 1000).is_some());
        assert!(store.take_flow("s", 1000).is_none());
        store.insert_flow("old".into(), flow(1), 1000);
        assert!(store.take_flow("old", 1000).is_none());
        store.insert_flow("late".into(), flow(1060), 1000);
        assert!(store.take_flow("late", 1060).is_none());
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
