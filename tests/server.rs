mod common;
use common::*;

#[tokio::test]
async fn start_serves_discovery_on_a_random_port() {
    let mut cfg = fauxidc::config::load_str(AUTH0).unwrap().config;
    cfg.server.bind = "127.0.0.1".into();
    cfg.server.port = 0;
    let srv = fauxidc::Server::start_with(
        cfg,
        fauxidc::StartOptions::with_key_pem(KEY.to_pem().to_string()),
    )
    .await
    .unwrap();
    let url = format!(
        "http://{}/auth0/.well-known/openid-configuration",
        srv.local_addr()
    );
    let d: serde_json::Value = reqwest::get(&url).await.unwrap().json().await.unwrap();
    assert_eq!(d["issuer"], "http://localhost:9000/auth0/");
    srv.shutdown().await.unwrap();
}

#[tokio::test]
async fn port_in_use_is_a_bind_error() {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut cfg = fauxidc::config::load_str(AUTH0).unwrap().config;
    cfg.server.bind = "127.0.0.1".into();
    cfg.server.port = l.local_addr().unwrap().port();
    assert!(matches!(
        fauxidc::Server::start(cfg).await,
        Err(fauxidc::error::StartError::Bind(_))
    ));
}

#[tokio::test]
async fn invalid_config_is_a_config_error() {
    // Config::default() has no Issuer: "no issuer configured".
    assert!(matches!(
        fauxidc::Server::start(fauxidc::config::Config::default()).await,
        Err(fauxidc::error::StartError::Config(_))
    ));
}

#[derive(Clone, Default)]
struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }

    fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync + use<> {
        let w = self.clone();
        tracing_subscriber::fmt()
            .with_writer(move || w.clone())
            .with_ansi(false)
            .finish()
    }
}

#[tokio::test]
async fn non_loopback_bind_logs_a_warning() {
    let logs = Capture::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let mut cfg = fauxidc::config::load_str(AUTH0).unwrap().config;
    cfg.server.bind = "0.0.0.0".into();
    cfg.server.port = 0;
    let srv = fauxidc::Server::start_with(
        cfg,
        fauxidc::StartOptions::with_key_pem(KEY.to_pem().to_string()),
    )
    .await
    .unwrap();
    let text = logs.text();
    assert!(text.contains("non-loopback"), "{text}");
    assert!(text.contains("listening"), "{text}");
    assert!(text.contains("issuer_id"), "{text}");
    srv.shutdown().await.unwrap();
}

#[tokio::test]
async fn request_span_logs_path_and_endpoint_but_never_the_query() {
    let logs = Capture::default();
    let _guard = tracing::subscriber::set_default(logs.subscriber());
    let app = app(AUTH0);
    let (status, _, _) = send(&app, get("/auth0/jwks?client_secret=hunter2&code=abc123")).await;
    assert_eq!(status, StatusCode::OK);
    let text = logs.text();
    assert!(text.contains("request"), "{text}");
    assert!(text.contains("path=/auth0/jwks"), "{text}");
    assert!(text.contains("endpoint=\"jwks\""), "{text}");
    assert!(text.contains("issuer=\"auth0\""), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
    assert!(!text.contains("abc123"), "{text}");
}
