//! Hot reload: the served router forwards each request to the current version of the app.
//!
//! A reload builds the next [`AppState`] (new config and templates, the same in-memory state)
//! and a new [`Router`], then swaps both. A request runs entirely on the version it started
//! with. See ADR 0004.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use axum::{
    Router,
    extract::{Request, State},
    response::Response,
};
use tower::ServiceExt;

use crate::config::{Config, LoadInputs, SourceMap, load, validate};
use crate::error::{ConfigErrors, StartError};
use crate::keys::restart_warning;
use crate::router::build_router;
use crate::state::AppState;

/// Why a reload did not apply. The old config stays.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("invalid configuration:\n{0}")]
    Config(ConfigErrors),
    #[error("template error: {0}")]
    Templates(String),
    /// A new Issuer could not get its key, for example from an invalid `key_file`.
    #[error("{0}")]
    Start(StartError),
}

impl From<StartError> for ReloadError {
    fn from(e: StartError) -> Self {
        match e {
            StartError::Config(errors) => ReloadError::Config(errors),
            StartError::Templates(text) => ReloadError::Templates(text),
            other => ReloadError::Start(other),
        }
    }
}

struct Live {
    state: ArcSwap<AppState>,
    router: ArcSwap<Router>,
    /// One reload at a time: the file poller and SIGHUP may race.
    applying: Mutex<()>,
}

/// Applies a new config to a running server. Cheap to clone.
#[derive(Clone)]
pub struct ReloadHandle {
    live: Arc<Live>,
}

impl ReloadHandle {
    /// Validates (`config::validate` with an empty source map), builds the next state and
    /// router, swaps them, logs each warning at WARN and an INFO line `config reloaded`.
    /// On error nothing changes. Must run inside a tokio runtime when a new Issuer needs its
    /// own key.
    pub fn apply(&self, config: Config) -> Result<Vec<String>, ReloadError> {
        validate(&config, &SourceMap::new()).map_err(ReloadError::Config)?;
        let _applying = self
            .live
            .applying
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (next, warnings) = self.live.state.load().next(config)?;
        let next = Arc::new(next);
        let router = build_router(next.clone());
        self.live.state.store(next);
        self.live.router.store(Arc::new(router));
        for warning in &warnings {
            tracing::warn!("{warning}");
        }
        tracing::info!("config reloaded");
        Ok(warnings)
    }

    /// The current version of the app state.
    pub fn current(&self) -> Arc<AppState> {
        self.live.state.load_full()
    }
}

/// The router to serve and its handle. The served router forwards every request to the
/// current inner router.
pub fn live_router(state: Arc<AppState>) -> (Router, ReloadHandle) {
    let router = build_router(state.clone());
    let live = Arc::new(Live {
        state: ArcSwap::new(state),
        router: ArcSwap::from_pointee(router),
        applying: Mutex::new(()),
    });
    let outer = Router::new().fallback(forward).with_state(live.clone());
    (outer, ReloadHandle { live })
}

async fn forward(State(live): State<Arc<Live>>, req: Request) -> Response {
    let router = Router::clone(&live.router.load());
    match router.oneshot(req).await {
        Ok(response) => response,
        Err(never) => match never {},
    }
}

/// How often [`watch_files`] polls the config files.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// `config::load(inputs)` then `handle.apply`. Every error is logged at ERROR with its source
/// text and the old config stays. Returns whether the config changed. A config equal to the
/// running one is not applied.
pub fn reload_from(handle: &ReloadHandle, inputs: &LoadInputs) -> bool {
    let config = match load(inputs) {
        Ok(loaded) => loaded.config,
        Err(errors) => {
            tracing::error!("config reload failed; keeping the old config\n{errors}");
            return false;
        }
    };
    if config == *handle.current().config {
        tracing::info!("config unchanged");
        return false;
    }
    match handle.apply(config) {
        Ok(_) => true,
        Err(error) => {
            tracing::error!("config reload failed; keeping the old config\n{error}");
            false
        }
    }
}

/// What the poller compares: the modification time and length, or `None` when the file is
/// missing.
type Stamp = Option<(Option<SystemTime>, u64)>;

fn stamps(files: &[PathBuf]) -> Vec<Stamp> {
    files
        .iter()
        .map(|file| {
            std::fs::metadata(file)
                .ok()
                .map(|meta| (meta.modified().ok(), meta.len()))
        })
        .collect()
}

/// Polls `files` every `interval`; a change of (mtime, length) or of existence calls
/// `reload_from`. The first poll only records the start values.
pub fn watch_files(
    handle: ReloadHandle,
    inputs: LoadInputs,
    files: Vec<PathBuf>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last: Option<Vec<Stamp>> = None;
        loop {
            ticker.tick().await;
            let now = stamps(&files);
            if last.as_ref().is_some_and(|before| *before != now) {
                tracing::info!("config file changed");
                reload_from(&handle, &inputs);
            }
            last = Some(now);
        }
    })
}

/// Unix: calls `reload_from` on every SIGHUP. Other platforms: a no-op task.
pub fn on_sighup(
    handle: ReloadHandle,
    inputs: LoadInputs,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // Register before the task starts, so a SIGHUP right after this call reloads.
        let mut hangup = signal(SignalKind::hangup())?;
        Ok(tokio::spawn(async move {
            while hangup.recv().await.is_some() {
                tracing::info!("SIGHUP received");
                reload_from(&handle, &inputs);
            }
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = (handle, inputs);
        Ok(tokio::spawn(async {}))
    }
}

/// Human-readable lines for keys that need a restart (plan Ruling 5): `server.port`,
/// `server.bind`, `server.log_format`, `server.request_log_size`, `server.key_file`,
/// `issuer.<id>.signing_alg`, `issuer.<id>.key_file`. Format: "<key> changed; it needs a
/// restart". An Issuer that is new in `new` gets no line: it gets a key like at startup.
pub fn restart_only_changes(old: &Config, new: &Config) -> Vec<String> {
    let (o, n) = (&old.server, &new.server);
    let mut changed: Vec<String> = [
        ("server.port", o.port != n.port),
        ("server.bind", o.bind != n.bind),
        ("server.log_format", o.log_format != n.log_format),
        (
            "server.request_log_size",
            o.request_log_size != n.request_log_size,
        ),
        ("server.key_file", o.key_file != n.key_file),
    ]
    .into_iter()
    .filter(|(_, differs)| *differs)
    .map(|(key, _)| restart_warning(key))
    .collect();
    for (id, issuer) in &new.issuer {
        let Some(before) = old.issuer.get(id) else {
            continue;
        };
        if before.signing_alg != issuer.signing_alg {
            changed.push(restart_warning(&format!("issuer.{id}.signing_alg")));
        }
        if before.key_file != issuer.key_file {
            changed.push(restart_warning(&format!("issuer.{id}.key_file")));
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_str;

    const BASE: &str =
        "[issuer.a]\nissuer_url = \"http://localhost:9000/a\"\n\n[user.alice]\nlabel = \"Alice\"\n";

    #[test]
    fn restart_only_changes_lists_port_and_key_file() {
        let old = load_str(BASE).unwrap().config;
        let new = load_str(&format!(
            "[server]\nport = 9100\n{}",
            BASE.replace(
                "issuer_url = \"http://localhost:9000/a\"\n",
                "issuer_url = \"http://localhost:9000/a\"\nkey_file = \"a.pem\"\n"
            )
        ))
        .unwrap()
        .config;
        assert_eq!(
            restart_only_changes(&old, &new),
            vec![
                "server.port changed; it needs a restart".to_owned(),
                "issuer.a.key_file changed; it needs a restart".to_owned(),
            ]
        );
    }

    #[test]
    fn restart_only_changes_ignores_users_and_new_issuers() {
        let old = load_str(BASE).unwrap().config;
        let new = load_str(&format!(
            "{BASE}\n[user.bob]\nlabel = \"Bob\"\n\n[issuer.b]\nissuer_url = \"http://localhost:9000/b\"\nsigning_alg = \"ES256\"\n"
        ))
        .unwrap()
        .config;
        assert_eq!(restart_only_changes(&old, &new), Vec::<String>::new());
    }
}
