//! Starts the server in-process: validate, bind, resolve the signing key, serve.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::{Config, SourceMap, validate};
use crate::error::StartError;
use crate::keys::{KeyHandle, KeySource};
use crate::router::build_router;
use crate::state::AppState;

/// Options for [`Server::start_with`].
#[derive(Debug, Default)]
pub struct StartOptions {
    /// Signing key PEM. Wins over `server.key_file`.
    pub key_pem: Option<String>,
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
        let listener = TcpListener::bind((config.server.bind.as_str(), config.server.port))
            .await
            .map_err(StartError::Bind)?;
        let addr = listener.local_addr().map_err(StartError::Bind)?;
        // The key starts after the listener binds, so generation never delays the bind.
        let key_file = Some(config.server.key_file.as_str())
            .filter(|f| !f.is_empty())
            .map(PathBuf::from);
        let keys = KeyHandle::start(KeySource {
            pem: opts.key_pem,
            key_file,
        })
        .map_err(StartError::Key)?;
        let state = Arc::new(AppState::new(config, keys)?);
        let router = build_router(state);
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    // A dropped sender also stops the server.
                    let _ = rx.await;
                })
                .await
        });
        Ok(RunningServer {
            addr,
            shutdown: tx,
            task,
        })
    }
}

/// A server started by [`Server::start`].
pub struct RunningServer {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<std::io::Result<()>>,
}

impl RunningServer {
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
