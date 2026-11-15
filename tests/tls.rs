// Fixtures: tests/fixtures/tls/{cert,key}.pem are a self-signed test-only pair for `localhost`, made with
// openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 36500 -subj "/CN=localhost"
// -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE"
// (CA:FALSE: rustls rejects a CA certificate as the server certificate). They are never a real key.
mod common;
use common::*;

#[cfg(not(feature = "tls"))]
#[test]
fn tls_config_without_feature_is_an_error() {
    let text = format!(
        "{AUTH0}\n[server.tls]\ncert_file = \"tests/fixtures/tls/cert.pem\"\nkey_file = \"tests/fixtures/tls/key.pem\"\n"
    );
    let e = fauxidc::config::load_str(&text).unwrap_err().to_string();
    assert!(e.contains("tls feature"), "{e}");
}

#[cfg(feature = "tls")]
mod with_tls {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::Arc;

    use fauxidc::config::{Config, TlsConfig};
    use fauxidc::{RunningServer, Server, StartOptions};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsConnector;
    use tokio_rustls::rustls::pki_types::pem::PemObject;
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
    use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};

    fn fixture(name: &str) -> String {
        format!("{}/tests/fixtures/tls/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn tls_config() -> Config {
        let mut cfg = fauxidc::config::load_str(AUTH0).unwrap().config;
        cfg.server.port = 0;
        cfg.server.tls = TlsConfig {
            cert_file: fixture("cert.pem"),
            key_file: fixture("key.pem"),
        };
        cfg
    }

    async fn start(cfg: Config) -> RunningServer {
        Server::start_with(
            cfg,
            StartOptions {
                key_pem: Some(KEY.to_pem().into()),
            },
        )
        .await
        .unwrap()
    }

    fn connector() -> TlsConnector {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(fixture("cert.pem")).unwrap() {
            roots.add(cert.unwrap()).unwrap();
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }

    /// Sends `GET path` over TLS by hand; returns the status and the body.
    async fn https_request(addr: SocketAddr, path: &str) -> (u16, String) {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut tls = connector().connect(name, tcp).await.unwrap();
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost:{}\r\nConnection: close\r\n\r\n",
            addr.port()
        );
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match tls.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&buf[..n]),
                // A peer that closes without close_notify: keep what was read.
                Err(_) if !raw.is_empty() => break,
                Err(e) => panic!("read failed: {e}"),
            }
        }
        let text = String::from_utf8_lossy(&raw).into_owned();
        let status = text
            .split(' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status line: {text}"));
        let body = text
            .split_once("\r\n\r\n")
            .map_or_else(String::new, |(_, b)| b.to_owned());
        (status, body)
    }

    async fn https_get(addr: SocketAddr, path: &str) -> u16 {
        https_request(addr, path).await.0
    }

    async fn https_get_body(addr: SocketAddr, path: &str) -> String {
        https_request(addr, path).await.1
    }

    #[tokio::test]
    async fn serves_https_with_the_given_certificate() {
        let server = start(tls_config()).await;
        let status = https_get(server.local_addr(), "/_mock/health").await;
        assert_eq!(status, 200);
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn discovery_uses_https_with_tls() {
        let server = start(tls_config()).await;
        let body = https_get_body(
            server.local_addr(),
            "/auth0/.well-known/openid-configuration",
        )
        .await;
        let d: Value = serde_json::from_str(&body).unwrap();
        assert!(
            d["token_endpoint"]
                .as_str()
                .unwrap()
                .starts_with("https://localhost:"),
            "{d}"
        );
        assert_eq!(d["issuer"], "http://localhost:9000/auth0/");
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn stalled_handshake_does_not_block_others() {
        let server = start(tls_config()).await;
        // Connects and sends nothing.
        let _stalled = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .unwrap();
        let t = std::time::Instant::now();
        assert_eq!(https_get(server.local_addr(), "/_mock/health").await, 200);
        assert!(t.elapsed() < Duration::from_secs(2));
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn plain_http_client_does_not_get_a_response() {
        let server = start(tls_config()).await;
        let result = reqwest::get(format!("http://{}/_mock/health", server.local_addr())).await;
        assert!(result.is_err(), "{result:?}");
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn tls_change_on_reload_needs_a_restart_and_keeps_the_listener() {
        let server = start(tls_config()).await;
        let mut next = tls_config();
        next.server.tls = TlsConfig::default();
        let warnings = server.reload_handle().apply(next).unwrap();
        assert!(
            warnings
                .iter()
                .any(|w| w == "server.tls changed; it needs a restart"),
            "{warnings:?}"
        );
        // The old listener stays: HTTPS still works and discovery keeps https.
        let body = https_get_body(
            server.local_addr(),
            "/auth0/.well-known/openid-configuration",
        )
        .await;
        let d: Value = serde_json::from_str(&body).unwrap();
        assert!(
            d["token_endpoint"]
                .as_str()
                .unwrap()
                .starts_with("https://"),
            "{d}"
        );
        server.shutdown().await.unwrap();
    }

    #[test]
    fn invalid_pem_is_a_tls_start_error() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut cfg = tls_config();
        // The certificate file as the key: no private key in it.
        cfg.server.tls.key_file = fixture("cert.pem");
        let result = rt.block_on(Server::start(cfg));
        assert!(
            matches!(result, Err(fauxidc::error::StartError::Tls(_))),
            "{:?}",
            result.err()
        );
    }
}
