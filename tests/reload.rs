mod common;
use common::*;

use fauxidc::config::load_str;
use fauxidc::reload::ReloadError;

#[tokio::test]
async fn reload_changes_routes_and_discovery() {
    let (app, handle) = live_app(STRICT);
    assert_eq!(
        send(&app, post_form("/auth0/oauth/token", &[], &[]))
            .await
            .0,
        404
    );
    let next = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\npaths = { token = \"/oauth/token\" }\n",
    );
    let warnings = handle.apply(load_str(&next).unwrap().config).unwrap();
    assert_eq!(warnings, Vec::<String>::new());
    let d = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(
        d["token_endpoint"],
        "http://localhost:9000/auth0/oauth/token"
    );
    assert_eq!(send(&app, post_form("/auth0/token", &[], &[])).await.0, 404);
}

#[tokio::test]
async fn code_and_session_survive_reload() {
    let (app, handle) = live_app(STRICT);
    let (s, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    assert_eq!(s, 302);
    let code = query_param(&location(&h), "code").unwrap();
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    handle
        .apply(
            load_str(&format!("{STRICT}\n[user.carol]\nlabel = \"Carol\"\n"))
                .unwrap()
                .config,
        )
        .unwrap();
    assert!(exchange_code_for(&app, &code).await["id_token"].is_string());
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(query_param(&location(&h), "code").is_some());
}

#[tokio::test]
async fn session_for_removed_user_fails() {
    let (app, handle) = live_app(STRICT);
    let (_, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    let without_alice = STRICT.replace("[user.alice]", "[user.alice_old]");
    handle
        .apply(load_str(&without_alice).unwrap().config)
        .unwrap();
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert_eq!(
        query_param(&location(&h), "error").as_deref(),
        Some("login_required")
    );
}

#[tokio::test]
async fn refresh_token_survives_reload() {
    let (app, handle) = live_app(STRICT);
    let rt = token_response_for(&app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    handle.apply(load_str(STRICT).unwrap().config).unwrap();
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn failed_reload_keeps_old_config() {
    let (app, handle) = live_app(STRICT);
    let mut bad = load_str(STRICT).unwrap().config;
    bad.issuer.get_mut("auth0").unwrap().login_template = "/nonexistent/login.html".into();
    assert!(matches!(handle.apply(bad), Err(ReloadError::Templates(_))));
    assert_eq!(send(&app, get(&authorize_url(&[]))).await.0, 200);
}

#[tokio::test]
async fn invalid_config_is_rejected_by_apply() {
    let (app, handle) = live_app(STRICT);
    let mut bad = load_str(STRICT).unwrap().config;
    bad.issuer.get_mut("auth0").unwrap().issuer_url = "not a url".into();
    assert!(matches!(handle.apply(bad), Err(ReloadError::Config(_))));
    assert_eq!(send(&app, get(&authorize_url(&[]))).await.0, 200);
}

#[tokio::test]
async fn key_change_warns_and_keeps_keys() {
    let (app, handle) = live_app(STRICT);
    let before = json(&send(&app, get("/auth0/jwks")).await.2);
    let next = STRICT.replace(
        "[issuer.auth0]\n",
        "[issuer.auth0]\nsigning_alg = \"ES256\"\n",
    );
    let warnings = handle.apply(load_str(&next).unwrap().config).unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("issuer.auth0.signing_alg") && w.contains("needs a restart")),
        "{warnings:?}"
    );
    assert_eq!(json(&send(&app, get("/auth0/jwks")).await.2), before);
    // Discovery keeps the running algorithm too.
    let d = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(d["id_token_signing_alg_values_supported"], json!(["RS256"]));
}

#[tokio::test]
async fn new_issuer_gets_a_key_on_reload() {
    let (app, handle) = live_app(STRICT);
    handle
        .apply(
            load_str(&format!(
                "{STRICT}\n[issuer.es]\nissuer_url = \"http://localhost:9000/es\"\nsigning_alg = \"ES256\"\n"
            ))
            .unwrap()
            .config,
        )
        .unwrap();
    assert_eq!(
        json(&send(&app, get("/es/jwks")).await.2)["keys"][0]["alg"],
        "ES256"
    );
}

#[tokio::test]
async fn cors_origins_follow_reload() {
    let (app, handle) = live_app(STRICT);
    let preflight = || {
        Request::builder()
            .method("OPTIONS")
            .uri("/auth0/token")
            .header("host", "localhost:9000")
            .header("origin", "http://localhost:4200")
            .header("access-control-request-method", "POST")
            .body(Body::empty())
            .unwrap()
    };
    let (_, h, _) = send(&app, preflight()).await;
    assert!(h.get("access-control-allow-origin").is_none());
    let next = STRICT.replace(
        "redirect_uris = [\"http://localhost:5173/cb\"]",
        "redirect_uris = [\"http://localhost:5173/cb\"]\nweb_origins = [\"http://localhost:4200\"]",
    );
    handle.apply(load_str(&next).unwrap().config).unwrap();
    let (_, h, _) = send(&app, preflight()).await;
    assert_eq!(h["access-control-allow-origin"], "http://localhost:4200");
}
