//! Starts the server in-process: validate, bind, resolve the signing key, serve.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, LoadInputs, SourceMap, validate};
use crate::error::StartError;
use crate::keys::{KeyHandle, KeySource};
use crate::logging::is_loopback_bind;
use crate::reload::{ConfigWriter, ReloadHandle, live_router};
use crate::state::AppState;

/// Options for [`Server::start_with`].
#[derive(Debug, Default)]
pub struct StartOptions {
    /// Signing key PEM. Wins over `server.key_file`.
    pub key_pem: Option<String>,
    /// The inputs `config` was loaded from. With them, the Test API can write Users to the last
    /// config file (ADR 0008). Without them, a write answers 409.
    pub load_inputs: Option<LoadInputs>,
}

impl StartOptions {
    /// Options with only a signing key PEM.
    pub fn with_key_pem(pem: impl Into<String>) -> Self {
        StartOptions {
            key_pem: Some(pem.into()),
            ..StartOptions::default()
        }
    }
}

/// Entry point for running the server inside another process, for example in tests.
///
/// This library API is unstable before 1.0.
pub struct Server;

impl Server {
    /// Starts the server with default [`StartOptions`].
    pub async fn start(config: Config) -> Result<RunningServer, StartError> {
        Server::start_with(config, StartOptions::default()).await
    }

    /// Validates the config, binds the listener, resolves the key and starts serving.
    pub async fn start_with(
        config: Config,
        opts: StartOptions,
    ) -> Result<RunningServer, StartError> {
        validate(&config, &SourceMap::new()).map_err(StartError::Config)?;
        #[cfg(feature = "tls")]
        let tls = if config.server.tls.enabled() {
            Some(
                crate::tls::server_config(
                    std::path::Path::new(&config.server.tls.cert_file),
                    std::path::Path::new(&config.server.tls.key_file),
                )
                .map_err(StartError::Tls)?,
            )
        } else {
            None
        };
        let listener = TcpListener::bind((config.server.bind.as_str(), config.server.port))
            .await
            .map_err(StartError::Bind)?;
        let addr = listener.local_addr().map_err(StartError::Bind)?;
        // The key starts after the listener binds, so generation never delays the bind.
        let key_file = Some(config.server.key_file.as_str())
            .filter(|f| !f.is_empty())
            .map(PathBuf::from);
        // Issuers share the server key by file name only when it came from the file.
        let server_key_from_file = opts.key_pem.is_none();
        let keys = KeyHandle::start(KeySource {
            pem: opts.key_pem,
            key_file,
        })
        .map_err(StartError::Key)?;
        #[cfg(feature = "tls")]
        if tls.is_some() {
            tracing::info!(%addr, scheme = "https", "listening");
        } else {
            tracing::info!(%addr, "listening");
        }
        #[cfg(not(feature = "tls"))]
        tracing::info!(%addr, "listening");
        for (id, issuer) in &config.issuer {
            tracing::info!(issuer_id = %id, issuer_url = %issuer.issuer_url, "issuer");
        }
        if !is_loopback_bind(&config.server.bind) {
            tracing::warn!(
                "bound to a non-loopback address: anyone who can reach it can mint tokens"
            );
        }
        let state = Arc::new(AppState::new(config, keys, server_key_from_file)?);
        let writer = state.config_writer.clone();
        let (router, reload) = live_router(state);
        if let Some(inputs) = opts.load_inputs {
            let _ = writer.set(ConfigWriter::new(inputs, reload.downgrade()));
        }
        let (tx, rx) = oneshot::channel::<()>();
        #[cfg(feature = "tls")]
        let task = match tls {
            Some(tls) => spawn_serve(crate::tls::TlsListener::new(listener, tls), router, rx),
            None => spawn_serve(listener, router, rx),
        };
        #[cfg(not(feature = "tls"))]
        let task = spawn_serve(listener, router, rx);
        Ok(RunningServer {
            addr,
            shutdown: tx,
            task,
            reload,
        })
    }
}

/// Serves `router` on `listener` until `rx` fires or its sender is dropped.
fn spawn_serve<L>(
    listener: L,
    router: axum::Router,
    rx: oneshot::Receiver<()>,
) -> JoinHandle<std::io::Result<()>>
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                // A dropped sender also stops the server.
                let _ = rx.await;
            })
            .await
    })
}

/// A server started by [`Server::start`].
pub struct RunningServer {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
    reload: ReloadHandle,
}

impl RunningServer {
    /// The handle that applies a new config to this server.
    pub fn reload_handle(&self) -> ReloadHandle {
        self.reload.clone()
    }

    /// The bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Stops accepting connections, waits for in-flight requests, then returns.
    pub async fn shutdown(self) -> std::io::Result<()> {
        let _ = self.shutdown.send(());
        join(self.task).await
    }

    /// Waits until the server stops.
    pub async fn wait(self) -> std::io::Result<()> {
        // Keep the sender alive so only an error or abort stops the server.
        let _shutdown = self.shutdown;
        join(self.task).await
    }
}

async fn join(task: JoinHandle<std::io::Result<()>>) -> std::io::Result<()> {
    task.await.map_err(std::io::Error::other)?
}
