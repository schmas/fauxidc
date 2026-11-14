mod common;
use common::*;

#[tokio::test]
async fn start_serves_discovery_on_a_random_port() {
    let mut cfg = fauxidc::config::load_str(AUTH0).unwrap().config;
    cfg.server.bind = "127.0.0.1".into();
    cfg.server.port = 0;
    let srv = fauxidc::Server::start_with(
        cfg,
        fauxidc::StartOptions {
            key_pem: Some(KEY.to_pem().into()),
        },
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
