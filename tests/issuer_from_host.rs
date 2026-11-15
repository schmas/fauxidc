//! `issuer.<id>.issuer_from_host = true`: `iss` and the discovery `issuer` follow the request
//! host (ADR 0006). fauxidc checks its own tokens against the issuer of the current request.

mod common;
use common::*;

const HOST_A: &str = "localhost:49153";
const HOST_B: &str = "fauxidc:9000";

fn cfg() -> String {
    format!(
        "{}\n[client.backend]\nclient_secret = \"s\"\n\
         grant_types = [\"client_credentials\", \"urn:ietf:params:oauth:grant-type:token-exchange\"]\n\
         scopes = [\"api\"]\n",
        STRICT.replacen(
            "[issuer.auth0]\n",
            "[issuer.auth0]\nissuer_from_host = true\n",
            1
        )
    )
}

async fn discovery(app: &Router, headers: &[(&str, &str)]) -> Value {
    let (s, _, b) = send(
        app,
        get_with("/auth0/.well-known/openid-configuration", headers),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    json(&b)
}

/// A `client_credentials` access token minted through `host`.
async fn cc_token(app: &Router, host: &str) -> String {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/token",
            &[("grant_type", "client_credentials"), ("scope", "api")],
            &[("authorization", &basic("backend", "s")), ("host", host)],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    json(&b)["access_token"].as_str().unwrap().to_owned()
}

async fn introspect(app: &Router, host: &str, token: &str) -> Value {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/introspect",
            &[("token", token)],
            &[
                ("authorization", &basic("example-app", "local")),
                ("host", host),
            ],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    json(&b)
}

#[tokio::test]
async fn discovery_issuer_follows_the_host_and_keeps_the_trailing_slash() {
    let app = app(&cfg());
    let a = discovery(&app, &[("host", HOST_A)]).await;
    assert_eq!(a["issuer"], format!("http://{HOST_A}/auth0/"));
    assert_eq!(a["token_endpoint"], format!("http://{HOST_A}/auth0/token"));
    let b = discovery(&app, &[("host", HOST_B)]).await;
    assert_eq!(b["issuer"], format!("http://{HOST_B}/auth0/"));
}

#[tokio::test]
async fn off_by_default() {
    let d = discovery(&app(AUTH0), &[("host", HOST_A)]).await;
    assert_eq!(d["issuer"], "http://localhost:9000/auth0/");
}

#[tokio::test]
async fn forwarded_headers_only_when_trusted() {
    let fwd = [
        ("host", HOST_A),
        ("x-forwarded-host", "id.example.test"),
        ("x-forwarded-proto", "https"),
    ];
    let d = discovery(&app(&cfg()), &fwd).await;
    assert_eq!(d["issuer"], format!("http://{HOST_A}/auth0/"));
    let trusted = format!("[server]\ntrust_forwarded_headers = true\n{}", cfg());
    let d = discovery(&app(&trusted), &fwd).await;
    assert_eq!(d["issuer"], "https://id.example.test/auth0/");
}

#[tokio::test]
async fn tokens_carry_the_issuer_of_the_request() {
    let app = app(&cfg());
    let at = cc_token(&app, HOST_A).await;
    assert_eq!(claims_of(&at)["iss"], format!("http://{HOST_A}/auth0/"));

    let code = {
        let (s, h, b) = send(
            &app,
            post_form(
                "/auth0/authorize",
                &login_fields(&[("scope", "openid offline_access")]),
                &[("host", HOST_A)],
            ),
        )
        .await;
        assert_eq!(s, 302, "{b}");
        query_param(&location(&h), "code").unwrap()
    };
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                (
                    "redirect_uri",
                    "http://localhost:3000/api/auth/callback/auth0",
                ),
            ],
            &[
                ("authorization", &basic("example-app", "local")),
                ("host", HOST_A),
            ],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let tokens = json(&b);
    for t in ["access_token", "id_token", "refresh_token"] {
        assert_eq!(
            claims_of(tokens[t].as_str().unwrap())["iss"],
            format!("http://{HOST_A}/auth0/"),
            "{t}"
        );
    }
}

#[tokio::test]
async fn test_api_tokens_follow_the_host() {
    let app = app(&cfg());
    let req = Request::builder()
        .method("POST")
        .uri("/_mock/auth0/token")
        .header("content-type", "application/json")
        .header("host", HOST_A)
        .body(Body::from(json!({ "user": "alice" }).to_string()))
        .unwrap();
    let (s, _, b) = send(&app, req).await;
    assert_eq!(s, 200, "{b}");
    let at = json(&b)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims_of(&at)["iss"], format!("http://{HOST_A}/auth0/"));
}

#[tokio::test]
async fn own_checks_accept_the_same_host_and_reject_another_host() {
    let app = app(&cfg());
    let at = cc_token(&app, HOST_A).await;
    assert_eq!(introspect(&app, HOST_A, &at).await["active"], true);
    assert_eq!(introspect(&app, HOST_B, &at).await["active"], false);
}

#[tokio::test]
async fn userinfo_rejects_a_token_of_another_host() {
    let app = app(&cfg());
    let at = {
        let (s, h, b) = send(
            &app,
            post_form("/auth0/authorize", &login_fields(&[]), &[("host", HOST_A)]),
        )
        .await;
        assert_eq!(s, 302, "{b}");
        let code = query_param(&location(&h), "code").unwrap();
        let (s, _, b) = send(
            &app,
            post_form(
                "/auth0/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    (
                        "redirect_uri",
                        "http://localhost:3000/api/auth/callback/auth0",
                    ),
                ],
                &[
                    ("authorization", &basic("example-app", "local")),
                    ("host", HOST_A),
                ],
            ),
        )
        .await;
        assert_eq!(s, 200, "{b}");
        json(&b)["access_token"].as_str().unwrap().to_owned()
    };
    let bearer = format!("Bearer {at}");
    let ok = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &bearer), ("host", HOST_A)],
        ),
    )
    .await;
    assert_eq!(ok.0, 200, "{}", ok.2);
    let other = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &bearer), ("host", HOST_B)],
        ),
    )
    .await;
    assert_eq!(other.0, 401, "{}", other.2);
}

#[tokio::test]
async fn token_exchange_accepts_a_subject_token_of_the_same_host() {
    let app = app(&cfg());
    let at = cc_token(&app, HOST_A).await;
    let exchange = |host: &'static str| {
        post_form(
            "/auth0/token",
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("subject_token", &at),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
            ],
            &[("authorization", &basic("backend", "s")), ("host", host)],
        )
    };
    let (s, _, b) = send(&app, exchange(HOST_A)).await;
    assert_eq!(s, 200, "{b}");
    let new = json(&b)["access_token"].as_str().unwrap().to_owned();
    assert_eq!(claims_of(&new)["iss"], format!("http://{HOST_A}/auth0/"));
    let (s, _, b) = send(&app, exchange(HOST_B)).await;
    assert_eq!(s, 400, "{b}");
}

#[tokio::test]
async fn zero_config_flag_env_turns_it_on_and_keeps_zero_config() {
    let inputs = fauxidc::config::LoadInputs {
        config_files: vec![],
        env: vec![("FAUXIDC_ISSUER_FROM_HOST".into(), "true".into())],
        flags: fauxidc::config::CliOverrides::default(),
        cwd: tmp_dir(),
    };
    let loaded = fauxidc::config::load(&inputs).unwrap();
    assert!(loaded.zero_config);
    assert!(loaded.config.issuer["default"].issuer_from_host);
    let (s, _, b) = send(
        &app_from_config(loaded.config),
        get_with(
            "/default/.well-known/openid-configuration",
            &[("host", HOST_A)],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(json(&b)["issuer"], format!("http://{HOST_A}/default"));
}
