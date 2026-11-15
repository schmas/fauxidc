//! HTTPS listener from user-provided PEM files (`tls` feature, spec 12.4).
//!
//! Each TLS handshake runs on its own task, so a client that connects and sends nothing never
//! blocks the listener.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// The longest time one TLS handshake may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The most TLS handshakes that run at once (plan Ruling 37). Above it, the accept loop waits
/// for a running handshake to end; new clients wait in the kernel backlog.
pub const MAX_HANDSHAKES: usize = 256;

/// Finished handshakes that wait for `accept`.
const QUEUE: usize = 64;

/// Reads the PEM chain and key (PKCS#8, PKCS#1 or SEC1) and builds a ring-provider
/// `ServerConfig` with ALPN `http/1.1`.
pub fn server_config(
    cert_file: &Path,
    key_file: &Path,
) -> Result<Arc<rustls::ServerConfig>, String> {
    let certs = CertificateDer::pem_file_iter(cert_file)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("cannot read certificates from {}: {e}", cert_file.display()))?;
    if certs.is_empty() {
        return Err(format!("no certificate in {}", cert_file.display()));
    }
    let key = PrivateKeyDer::from_pem_file(key_file)
        .map_err(|e| format!("cannot read a private key from {}: {e}", key_file.display()))?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| e.to_string())?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| format!("certificate and key do not work together: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Accepts TCP connections and runs each handshake on its own task (bounded by
/// [`HANDSHAKE_TIMEOUT`], at most [`MAX_HANDSHAKES`] at once). Finished handshakes go through
/// a channel to `accept`, so one stalled client never blocks the listener.
pub struct TlsListener {
    addr: std::io::Result<SocketAddr>,
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
    acceptor_task: JoinHandle<()>,
}

impl TlsListener {
    /// Starts accepting on `tcp`. Must run inside a tokio runtime.
    pub fn new(tcp: TcpListener, config: Arc<rustls::ServerConfig>) -> TlsListener {
        let addr = tcp.local_addr();
        let (tx, ready) = mpsc::channel(QUEUE);
        let acceptor = TlsAcceptor::from(config);
        let acceptor_task = tokio::spawn(accept_loop(tcp, acceptor, tx));
        TlsListener {
            addr,
            ready,
            acceptor_task,
        }
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.acceptor_task.abort();
    }
}

async fn accept_loop(
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    tx: mpsc::Sender<(TlsStream<TcpStream>, SocketAddr)>,
) {
    let permits = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    loop {
        // The semaphore is never closed, so this only waits.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        let (stream, peer) = match tcp.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                // For example too many open files: wait a moment, as axum does.
                tracing::debug!(%error, "accept failed");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let handshake = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
            // The handshake has ended: free its place before waiting for `accept`.
            drop(permit);
            match handshake {
                Ok(Ok(tls)) => {
                    let _ = tx.send((tls, peer)).await;
                }
                Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
            }
        });
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            // The accept loop never ends while this listener lives.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        match &self.addr {
            Ok(addr) => Ok(*addr),
            Err(error) => Err(std::io::Error::new(error.kind(), error.to_string())),
        }
    }
}
