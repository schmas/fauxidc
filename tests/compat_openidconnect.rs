mod common;
use common::*;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreUserInfoClaims,
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, http,
};

const CB: &str = "http://localhost:3000/api/auth/callback/auth0";

/// Sends `req` to `addr`, with `Host: localhost:9000` and no redirects.
async fn send_to(
    rq: &reqwest::Client,
    addr: std::net::SocketAddr,
    req: openidconnect::HttpRequest,
) -> Result<openidconnect::HttpResponse, reqwest::Error> {
    let (parts, body) = req.into_parts();
    let mut url = reqwest::Url::parse(&parts.uri.to_string()).unwrap();
    url.set_host(Some("127.0.0.1")).unwrap();
    url.set_port(Some(addr.port())).unwrap();
    let resp = rq
        .request(parts.method, url)
        .headers(parts.headers)
        .header("host", "localhost:9000")
        .body(body)
        .send()
        .await?;
    let mut b = http::Response::builder().status(resp.status());
    for (k, v) in resp.headers() {
        b = b.header(k, v);
    }
    let bytes = resp.bytes().await?;
    Ok(b.body(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn code_flow_with_pkce_and_nonce() {
    // 1. Start the server.
    let mut cfg = fauxidc::config::load_str(
        &STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nauto_login = true\n"),
    )
    .unwrap()
    .config;
    cfg.server.bind = "127.0.0.1".into();
    cfg.server.port = 0;
    let srv = fauxidc::Server::start_with(
        cfg,
        fauxidc::StartOptions::with_key_pem(KEY.to_pem().to_string()),
    )
    .await
    .unwrap();
    let addr = srv.local_addr();
    let rq = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let http_client = |req: openidconnect::HttpRequest| {
        let rq = rq.clone();
        async move { send_to(&rq, addr, req).await }
    };

    // 2. Discovery (also fetches JWKS).
    let meta = CoreProviderMetadata::discover_async(
        IssuerUrl::new("http://localhost:9000/auth0/".into()).unwrap(),
        &http_client,
    )
    .await
    .unwrap();

    // 3. Client.
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new("example-app".into()),
        Some(ClientSecret::new("local".into())),
    )
    .set_redirect_uri(RedirectUrl::new(CB.into()).unwrap());

    // 4. Authorization URL with PKCE, nonce, login_hint (auto_login signs alice in at once).
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .add_scope(Scope::new("offline_access".into()))
        .add_extra_param("login_hint", "alice")
        .set_pkce_challenge(challenge)
        .url();

    // 5. GET /authorize: 302 to the callback with code and the same state.
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(auth_url.as_str())
        .body(Vec::new())
        .unwrap();
    let resp = send_to(&rq, addr, req).await.unwrap();
    assert_eq!(resp.status(), 302);
    let loc = reqwest::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();
    assert!(loc.as_str().starts_with(CB), "{loc}");
    let q: std::collections::HashMap<_, _> = loc.query_pairs().into_owned().collect();
    assert_eq!(q["state"], *csrf.secret());

    // 6. Code exchange with the PKCE verifier (client_secret_basic).
    let tokens = client
        .exchange_code(AuthorizationCode::new(q["code"].clone()))
        .unwrap()
        .set_pkce_verifier(verifier)
        .request_async(&http_client)
        .await
        .unwrap();

    // 7. The ID token verifies (signature via JWKS, iss, aud, exp, nonce) and the claims match.
    let id = tokens
        .id_token()
        .unwrap()
        .claims(&client.id_token_verifier(), &nonce)
        .unwrap();
    assert_eq!(id.issuer().as_str(), "http://localhost:9000/auth0/");
    assert_eq!(id.subject().as_str(), "auth0|alice");
    assert_eq!(id.email().unwrap().as_str(), "alice@example.com");
    assert_eq!(id.nonce().unwrap().secret(), nonce.secret());

    // 8. /userinfo with the access token.
    let ui: CoreUserInfoClaims = client
        .user_info(tokens.access_token().clone(), None)
        .unwrap()
        .request_async(&http_client)
        .await
        .unwrap();
    assert_eq!(ui.subject().as_str(), "auth0|alice");
    assert_eq!(ui.email().unwrap().as_str(), "alice@example.com");

    // 9. Refresh: a new access token and a new (rotated) refresh token.
    let refresh_token = tokens.refresh_token().unwrap().clone();
    let refreshed = client
        .exchange_refresh_token(&refresh_token)
        .unwrap()
        .request_async(&http_client)
        .await
        .unwrap();
    assert_ne!(
        refreshed.access_token().secret(),
        tokens.access_token().secret()
    );
    assert_ne!(
        refreshed.refresh_token().unwrap().secret(),
        refresh_token.secret()
    );

    srv.shutdown().await.unwrap();
}
