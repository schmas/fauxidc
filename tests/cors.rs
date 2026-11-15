mod common;
use common::*;

fn options(uri: &str, origin: &str, req_headers: &str) -> Request<Body> {
    Request::builder()
        .method("OPTIONS")
        .uri(uri)
        .header("host", "localhost:9000")
        .header("origin", origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", req_headers)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn preflight_mirrors_requested_headers() {
    let (s, h, _) = send(
        &app(STRICT),
        options(
            "/auth0/token",
            "http://localhost:5173",
            "auth0-client, content-type",
        ),
    )
    .await;
    assert!(s.is_success());
    assert_eq!(h["access-control-allow-origin"], "http://localhost:5173");
    let allow = h["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .to_ascii_lowercase();
    assert!(
        allow.contains("auth0-client") && allow.contains("content-type"),
        "{allow}"
    );
    assert!(h.get("access-control-allow-credentials").is_none());
    assert_eq!(h["access-control-max-age"], "600");
}

#[tokio::test]
async fn unknown_origin_gets_no_cors_headers() {
    let (_, h, _) = send(
        &app(STRICT),
        options("/auth0/token", "http://evil.example.com", "content-type"),
    )
    .await;
    assert!(h.get("access-control-allow-origin").is_none());
    let (s, h, _) = send(
        &app(STRICT),
        post_form(
            "/auth0/token",
            &[("grant_type", "password")],
            &[("origin", "http://evil.example.com")],
        ),
    )
    .await;
    assert_eq!(s, 400); // still served
    assert!(h.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn userinfo_and_revoke_have_cors_introspect_does_not() {
    let app = app(STRICT);
    let origin = "http://localhost:5173";
    let (_, h, _) = send(&app, get_with("/auth0/userinfo", &[("origin", origin)])).await;
    assert_eq!(h["access-control-allow-origin"], origin);
    let (_, h, _) = send(
        &app,
        post_form("/auth0/revoke", &[("token", "x")], &[("origin", origin)]),
    )
    .await;
    assert_eq!(h["access-control-allow-origin"], origin);
    let (_, h, _) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[("token", "x")],
            &[("origin", origin)],
        ),
    )
    .await;
    assert!(h.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn empty_web_origins_allow_no_origin() {
    let toml = format!(
        "{STRICT}\n[client.other]\nredirect_uris=[\"http://localhost:4000/cb\"]\nweb_origins=[]\n"
    );
    let app = app(&toml);
    let (_, h, _) = send(
        &app,
        get_with("/auth0/userinfo", &[("origin", "http://localhost:4000")]),
    )
    .await;
    assert!(h.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn lenient_reflects_any_origin() {
    let toml = AUTH0.replace(
        "issuer_url = \"http://localhost:9000/auth0/\"\n",
        "issuer_url = \"http://localhost:9000/auth0/\"\nlenient = true\n",
    );
    let (_, h, _) = send(
        &app(&toml),
        options(
            "/auth0/token",
            "http://anything.example.com",
            "content-type",
        ),
    )
    .await;
    assert_eq!(
        h["access-control-allow-origin"],
        "http://anything.example.com"
    );
}

#[tokio::test]
async fn path_override_keeps_cors() {
    let toml = format!("{STRICT}\n[issuer.auth0.paths]\ntoken = \"/oauth/token\"\n");
    let (s, h, _) = send(
        &app(&toml),
        options(
            "/auth0/oauth/token",
            "http://localhost:5173",
            "content-type",
        ),
    )
    .await;
    assert!(s.is_success());
    assert_eq!(h["access-control-allow-origin"], "http://localhost:5173");
}

#[tokio::test]
async fn web_origins_replace_redirect_origin() {
    let toml = format!(
        "{STRICT}\n[client.other]\nredirect_uris=[\"http://localhost:4000/cb\"]\nweb_origins=[\"http://localhost:5000\"]\n"
    );
    let app = app(&toml);
    let (_, h, _) = send(
        &app,
        get_with("/auth0/userinfo", &[("origin", "http://localhost:5000")]),
    )
    .await;
    assert_eq!(h["access-control-allow-origin"], "http://localhost:5000");
    let (_, h, _) = send(
        &app,
        get_with("/auth0/userinfo", &[("origin", "http://localhost:4000")]),
    )
    .await;
    assert!(h.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn default_port_origin_matches_browser_origin() {
    let toml =
        format!("{STRICT}\n[client.tls]\nredirect_uris=[\"https://app.example.com:443/cb\"]\n");
    let (_, h, _) = send(
        &app(&toml),
        get_with("/auth0/userinfo", &[("origin", "https://app.example.com")]),
    )
    .await;
    assert_eq!(h["access-control-allow-origin"], "https://app.example.com");
}
