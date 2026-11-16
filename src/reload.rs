//! Hot reload: the served router forwards each request to the current version of the app.
//!
//! A reload builds the next [`AppState`] (new config and templates, the same in-memory state)
//! and a new [`Router`], then swaps both. A request runs entirely on the version it started
//! with. See ADR 0004.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use axum::{
    Router,
    extract::{Request, State},
    response::Response,
};
use tower::ServiceExt;

use crate::config::edit::{Edit, EditError};
use crate::config::{Config, LoadInputs, Loaded, SourceMap, load, validate};
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
    /// The last config `config::load` produced (plan Ruling 27). The running config holds the
    /// running values of the restart-only keys, so it cannot tell a real change from a touch.
    last_loaded: Mutex<Option<Config>>,
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

    /// The last config `reload_from` loaded (or the startup config). `None` before the first set.
    pub fn last_loaded(&self) -> Option<Config> {
        self.live
            .last_loaded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Records `config` as the last loaded config. `live_router` sets it to the startup config.
    pub fn set_last_loaded(&self, config: Config) {
        *self
            .live
            .last_loaded
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(config);
    }
}

impl ReloadHandle {
    /// A handle that does not keep the server state alive. [`AppState`] holds it through
    /// [`ConfigWriter`], so a strong handle would be a reference cycle.
    pub fn downgrade(&self) -> WeakReloadHandle {
        WeakReloadHandle(Arc::downgrade(&self.live))
    }
}

/// A [`ReloadHandle`] that does not keep the server alive.
#[derive(Clone)]
pub struct WeakReloadHandle(Weak<Live>);

impl WeakReloadHandle {
    /// The handle, while the server runs.
    pub fn upgrade(&self) -> Option<ReloadHandle> {
        self.0.upgrade().map(|live| ReloadHandle { live })
    }
}

/// Why a config write failed.
#[derive(Debug, thiserror::Error)]
pub enum WriteError {
    /// The edit was refused. The file did not change.
    #[error(transparent)]
    Edit(#[from] EditError),
    /// The file could not be written. It did not change.
    #[error("cannot write {}: {error}", .path.display())]
    Io {
        path: PathBuf,
        error: std::io::Error,
    },
    /// The new config did not apply. The old file text is back.
    #[error("the change did not apply; the file is unchanged: {0}")]
    Reload(ReloadError),
    /// The server stopped.
    #[error("the server is stopping")]
    Stopped,
}

/// Writes config file edits for the Test API, then applies them at once (ADR 0008).
///
/// Writes run one at a time. Env and inline values come from `inputs`, the startup snapshot,
/// the same as for a reload.
pub struct ConfigWriter {
    inputs: LoadInputs,
    handle: WeakReloadHandle,
    writing: Mutex<()>,
}

impl ConfigWriter {
    pub fn new(inputs: LoadInputs, handle: WeakReloadHandle) -> Self {
        ConfigWriter {
            inputs,
            handle,
            writing: Mutex::new(()),
        }
    }

    /// The load inputs of the server. `GET /_mock/config` loads them again for the source of
    /// each value.
    pub fn inputs(&self) -> &LoadInputs {
        &self.inputs
    }

    /// Prepares an edit with `prepare`, writes it and applies the new config. If the apply
    /// fails, the old file text is written back. Returns the new config.
    pub fn write(
        &self,
        prepare: impl FnOnce(&LoadInputs) -> Result<Edit, EditError>,
    ) -> Result<Loaded, WriteError> {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let handle = self.handle.upgrade().ok_or(WriteError::Stopped)?;
        let edit = prepare(&self.inputs)?;
        edit.write().map_err(|error| WriteError::Io {
            path: edit.path.clone(),
            error,
        })?;
        match handle.apply(edit.loaded.config.clone()) {
            Ok(_) => {
                handle.set_last_loaded(edit.loaded.config.clone());
                tracing::info!(file = %edit.path.display(), "config file written");
                Ok(edit.loaded)
            }
            Err(error) => {
                if let Err(e) = edit.restore() {
                    tracing::error!(file = %edit.path.display(), "cannot restore the config file: {e}");
                }
                Err(WriteError::Reload(error))
            }
        }
    }
}

/// Why a Test API reload (`POST /_mock/reload`) did not apply. The old config stays.
#[derive(Debug, thiserror::Error)]
pub enum RequestedReloadError {
    /// No config file is loaded (Zero config, inline config or env vars only).
    #[error("no config file is loaded; env and inline config change only at restart")]
    NoFile,
    /// The new config is invalid, or it did not apply.
    #[error(transparent)]
    Reload(#[from] ReloadError),
    /// The server stopped.
    #[error("the server is stopping")]
    Stopped,
}

impl ConfigWriter {
    /// Loads the config files again and applies them at once, like [`reload_from`]. It runs
    /// one at a time with the writes. Env and inline config come from the startup snapshot.
    pub fn reload(&self) -> Result<Reloaded, RequestedReloadError> {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let handle = self.handle.upgrade().ok_or(RequestedReloadError::Stopped)?;
        let loaded = load(&self.inputs).map_err(ReloadError::Config)?;
        if loaded.files.is_empty() {
            return Err(RequestedReloadError::NoFile);
        }
        Ok(reload_config(&handle, loaded.config)?)
    }
}

/// The router to serve and its handle. The served router forwards every request to the
/// current inner router.
pub fn live_router(state: Arc<AppState>) -> (Router, ReloadHandle) {
    let router = build_router(state.clone());
    let startup = state.config.as_ref().clone();
    let live = Arc::new(Live {
        state: ArcSwap::new(state),
        router: ArcSwap::from_pointee(router),
        applying: Mutex::new(()),
        last_loaded: Mutex::new(None),
    });
    let outer = Router::new().fallback(forward).with_state(live.clone());
    let handle = ReloadHandle { live };
    handle.set_last_loaded(startup);
    (outer, handle)
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

/// The result of a reload that did not fail.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Reloaded {
    /// `false` when the loaded config equals the last loaded config. Nothing was applied.
    pub changed: bool,
    /// The restart warnings of the apply, for example a changed key.
    pub warnings: Vec<String>,
}

/// `config::load(inputs)` then `handle.apply`. Every error is logged at ERROR with its source
/// text and the old config stays. Returns whether the config changed.
///
/// The new load is compared with `handle.last_loaded()`, not with the running config (plan
/// Ruling 27): equal → "config unchanged", no apply. So a touch of an unchanged file does
/// nothing, and a change of a restart-only key warns once. Only a successful apply makes the
/// new load `last_loaded`: after an apply error (for example a missing template file), the next
/// reload or SIGHUP tries the same config again.
pub fn reload_from(handle: &ReloadHandle, inputs: &LoadInputs) -> bool {
    match try_reload_from(handle, inputs) {
        Ok(reloaded) => reloaded.changed,
        Err(error) => {
            tracing::error!("config reload failed; keeping the old config\n{error}");
            false
        }
    }
}

/// Like [`reload_from`], but returns the error and the warnings and logs no error.
pub fn try_reload_from(
    handle: &ReloadHandle,
    inputs: &LoadInputs,
) -> Result<Reloaded, ReloadError> {
    let loaded = load(inputs).map_err(ReloadError::Config)?;
    reload_config(handle, loaded.config)
}

/// The step of [`try_reload_from`] after the load: compare with the last loaded config, then
/// apply.
fn reload_config(handle: &ReloadHandle, config: Config) -> Result<Reloaded, ReloadError> {
    let unchanged = match handle.last_loaded() {
        Some(last) => last == config,
        None => config == *handle.current().config,
    };
    if unchanged {
        tracing::info!("config unchanged");
        return Ok(Reloaded {
            changed: false,
            warnings: Vec::new(),
        });
    }
    let warnings = handle.apply(config.clone())?;
    handle.set_last_loaded(config);
    Ok(Reloaded {
        changed: true,
        warnings,
    })
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

/// The 1-poll debounce of [`watch_files`] (plan Ruling 3).
#[derive(Debug)]
struct Debounce {
    /// The stamps the running config came from.
    last_applied: Vec<Stamp>,
    /// New stamps seen on the previous poll, not applied yet.
    pending: Option<Vec<Stamp>>,
}

impl Debounce {
    fn new(start: Vec<Stamp>) -> Self {
        Debounce {
            last_applied: start,
            pending: None,
        }
    }

    /// Records one poll. `true` when the caller must reload: two polls in a row saw the same
    /// new stamps. A poll that differs from `pending` replaces it.
    fn observe(&mut self, now: Vec<Stamp>) -> bool {
        if now == self.last_applied {
            self.pending = None;
            return false;
        }
        if self.pending.as_ref() == Some(&now) {
            self.pending = None;
            self.last_applied = now;
            return true;
        }
        self.pending = Some(now);
        false
    }
}

/// `true` when a file exists with a modification time not older than `loaded_at`.
fn saved_since(stamps: &[Stamp], loaded_at: SystemTime) -> bool {
    stamps
        .iter()
        .flatten()
        .any(|(modified, _)| modified.is_some_and(|m| m >= loaded_at))
}

/// Polls `files` every `interval`. A change of (mtime, length) or of existence applies only
/// when two consecutive polls see the same new stamps (plan Ruling 3): an editor that saves in
/// place (truncate, then write) never gets a cut file applied. A change applies 1 to 2
/// intervals after the save.
///
/// The first poll records the start stamps. When a file has a modification time not older
/// than `loaded_at` (taken just before the startup `config::load`), it also calls
/// `reload_from`, which does nothing when the config is equal (plan Ruling 28).
pub fn watch_files(
    handle: ReloadHandle,
    inputs: LoadInputs,
    files: Vec<PathBuf>,
    interval: Duration,
    loaded_at: SystemTime,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        let start = stamps(&files);
        if saved_since(&start, loaded_at) {
            tracing::info!("config file changed");
            reload_from(&handle, &inputs);
        }
        let mut debounce = Debounce::new(start);
        loop {
            ticker.tick().await;
            if debounce.observe(stamps(&files)) {
                tracing::info!("config file changed");
                reload_from(&handle, &inputs);
            }
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
/// `server.tls`, `issuer.<id>.signing_alg`, `issuer.<id>.key_file`. Format: "<key> changed; it needs a
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
        ("server.tls", o.tls != n.tls),
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

    /// The stamps of one file with this length.
    fn stamp(len: u64) -> Vec<Stamp> {
        vec![Some((None, len))]
    }

    #[test]
    fn debounce_applies_after_two_equal_polls() {
        let mut d = Debounce::new(stamp(1));
        assert!(!d.observe(stamp(1)));
        assert!(!d.observe(stamp(2)), "first sighting");
        assert!(d.observe(stamp(2)), "second equal poll");
        assert!(!d.observe(stamp(2)), "already applied");
    }

    #[test]
    fn debounce_skips_a_state_seen_once() {
        let mut d = Debounce::new(stamp(10));
        assert!(!d.observe(stamp(3)), "cut file");
        assert!(!d.observe(stamp(11)), "full file replaces pending");
        assert!(d.observe(stamp(11)));
        // Back to the applied state before the second poll: nothing pending.
        assert!(!d.observe(stamp(12)));
        assert!(!d.observe(stamp(11)));
        assert!(!d.observe(stamp(11)));
    }

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
    fn restart_only_changes_lists_tls() {
        let old = load_str(BASE).unwrap().config;
        let mut new = old.clone();
        new.server.tls = crate::config::TlsConfig {
            cert_file: "c.pem".into(),
            key_file: "k.pem".into(),
        };
        assert_eq!(
            restart_only_changes(&old, &new),
            vec!["server.tls changed; it needs a restart".to_owned()]
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
