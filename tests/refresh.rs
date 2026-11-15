mod common;
use common::*;

#[tokio::test]
async fn offline_access_gives_refresh_token() {
    let app = app(STRICT);
    let j = token_response_for(&app, &[("scope", "openid profile email offline_access")]).await;
    let rt = j["refresh_token"].as_str().unwrap();
    let (h, c) = (header_of(rt), claims_of(rt));
    assert_eq!(h["typ"], "rt+jwt");
    assert_eq!(c["client_id"], "example-app");
    assert_eq!(c["aud"], "example-app");
    assert_eq!(c["iss"], "http://localhost:9000/auth0/");
    assert_eq!(c["sub"], "auth0|alice");
    assert_eq!(c["scope"], "openid profile email offline_access");
    assert_eq!(c["subject"]["kind"], "user");
    assert_eq!(c["subject"]["id"], "alice");
    assert_eq!(
        c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(),
        86400
    );
}

#[tokio::test]
async fn no_refresh_token_without_offline_access_or_grant() {
    assert!(
        token_response_for(&app(STRICT), &[])
            .await
            .get("refresh_token")
            .is_none()
    );
    let cfg = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\ngrant_types = [\"authorization_code\"]\n",
    );
    let j = token_response_for(&app(&cfg), &[("scope", "openid offline_access")]).await;
    assert!(j.get("refresh_token").is_none());
}

#[tokio::test]
async fn lenient_always_issues_refresh_token() {
    let cfg = STRICT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    assert!(token_response_for(&app(&cfg), &[]).await["refresh_token"].is_string());
}

#[tokio::test]
async fn refresh_lifetime_follows_client_override() {
    let cfg = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\nlifetimes = { refresh_token = 120 }\n",
    );
    let j = token_response_for(&app(&cfg), &[("scope", "openid offline_access")]).await;
    let c = claims_of(j["refresh_token"].as_str().unwrap());
    assert_eq!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap(), 120);
}

#[tokio::test]
async fn overrides_travel_in_refresh_token() {
    let j = token_response_for(
        &app(STRICT),
        &[
            ("scope", "openid offline_access"),
            ("override_claims", r#"{"roles":["x"]}"#),
        ],
    )
    .await;
    assert_eq!(
        claims_of(j["refresh_token"].as_str().unwrap())["subject"]["overrides"]["roles"],
        json!(["x"])
    );
}

#[tokio::test]
async fn refresh_token_is_not_an_access_token() {
    let app = app(STRICT);
    let j = token_response_for(&app, &[("scope", "openid offline_access")]).await;
    let rt = j["refresh_token"].as_str().unwrap();
    let (s, _, _) = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &format!("Bearer {rt}"))],
        ),
    )
    .await;
    assert_eq!(s, 401);
}

const SPA_CB: &str = "http://localhost:5173/cb";

/// Posts `grant_type=refresh_token` with `headers` (no default authentication).
async fn refresh_with(
    app: &Router,
    rt: &str,
    extra: &[(&str, &str)],
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut form = vec![("grant_type", "refresh_token"), ("refresh_token", rt)];
    form.extend_from_slice(extra);
    let (s, h, b) = send(app, post_form("/auth0/token", &form, headers)).await;
    if s == 200 {
        assert_eq!(h["cache-control"], "no-store");
    }
    (s, json(&b))
}

/// Posts `grant_type=refresh_token` with Basic `example-app:local`.
async fn refresh(app: &Router, rt: &str, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    refresh_with(
        app,
        rt,
        extra,
        &[("authorization", &basic("example-app", "local"))],
    )
    .await
}

async fn offline_rt(app: &Router, extra: &[(&str, &str)]) -> String {
    let mut fields = vec![("scope", "openid profile email offline_access")];
    fields.extend_from_slice(extra);
    token_response_for(app, &fields).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn with_client_line(line: &str) -> String {
    STRICT.replace(
        "client_secret = \"local\"\n",
        &format!("client_secret = \"local\"\n{line}\n"),
    )
}

#[tokio::test]
async fn refresh_returns_new_tokens_and_rotates() {
    let app = app(STRICT);
    let j = token_response_for(
        &app,
        &[
            ("scope", "openid profile email offline_access"),
            ("nonce", "n1"),
        ],
    )
    .await;
    let rt = j["refresh_token"].as_str().unwrap();
    let (s, r) = refresh(&app, rt, &[]).await;
    assert_eq!(s, 200, "{r}");
    assert_ne!(r["refresh_token"], j["refresh_token"]);
    assert_eq!(r["token_type"], "Bearer");
    assert_eq!(r["scope"], "openid profile email offline_access");
    let id = claims_of(r["id_token"].as_str().unwrap());
    assert_eq!(id["sub"], "auth0|alice");
    assert!(id.get("nonce").is_none());
    assert_eq!(
        id["auth_time"],
        claims_of(j["id_token"].as_str().unwrap())["auth_time"]
    );
    let at = claims_of(r["access_token"].as_str().unwrap());
    assert_eq!(at["aud"], "example-app");
}

#[tokio::test]
async fn reused_refresh_token_is_invalid_grant() {
    let app = app(STRICT);
    let rt = offline_rt(&app, &[]).await;
    assert_eq!(refresh(&app, &rt, &[]).await.0, 200);
    let (s, r) = refresh(&app, &rt, &[]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn parallel_reuse_gives_one_success() {
    let app = app(STRICT);
    let rt = offline_rt(&app, &[]).await;
    let (a, b) = tokio::join!(refresh(&app, &rt, &[]), refresh(&app, &rt, &[]));
    let mut codes = [a.0.as_u16(), b.0.as_u16()];
    codes.sort_unstable();
    assert_eq!(codes, [200, 400]);
}

#[tokio::test]
async fn reuse_within_leeway_succeeds() {
    let app = app(&with_client_line("refresh_reuse_leeway_secs = 30"));
    let rt = offline_rt(&app, &[]).await;
    assert_eq!(refresh(&app, &rt, &[]).await.0, 200);
    let (s, r) = refresh(&app, &rt, &[]).await;
    assert_eq!(s, 200, "{r}");
}

#[tokio::test]
async fn no_rotation_echoes_token_and_allows_reuse() {
    let app = app(&with_client_line("rotate_refresh_tokens = false"));
    let rt = offline_rt(&app, &[]).await;
    for _ in 0..3 {
        let (s, r) = refresh(&app, &rt, &[]).await;
        assert_eq!(s, 200, "{r}");
        assert_eq!(r["refresh_token"], rt.as_str());
    }
}

#[tokio::test]
async fn refresh_works_on_new_router_and_remerges_config() {
    let rt = token_response_for(&app(STRICT), &[("scope", "openid email offline_access")]).await
        ["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let changed = app(&STRICT.replace("alice@example.com", "alice2@example.com"));
    let (s, r) = refresh(&changed, &rt, &[]).await;
    assert_eq!(s, 200, "{r}");
    assert_eq!(
        claims_of(r["id_token"].as_str().unwrap())["email"],
        "alice2@example.com"
    );
}

#[tokio::test]
async fn overrides_survive_refresh() {
    let app = app(STRICT);
    let rt = offline_rt(&app, &[("override_claims", r#"{"roles":["x"]}"#)]).await;
    let (s, r) = refresh(&app, &rt, &[]).await;
    assert_eq!(s, 200, "{r}");
    assert_eq!(
        claims_of(r["id_token"].as_str().unwrap())["roles"],
        json!(["x"])
    );
}

#[tokio::test]
async fn scope_can_narrow_but_not_widen() {
    let app = app(STRICT);
    let rt = offline_rt(&app, &[]).await;
    let (s, r) = refresh(&app, &rt, &[("scope", "openid")]).await;
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["scope"], "openid");
    assert_eq!(
        claims_of(r["access_token"].as_str().unwrap())["scope"],
        "openid"
    );
    // RFC 6749 section 6: the new refresh token keeps the original scope.
    let rt2 = r["refresh_token"].as_str().unwrap().to_owned();
    let full = "openid profile email offline_access";
    assert_eq!(claims_of(&rt2)["scope"], full);
    let (s, r) = refresh(&app, &rt2, &[]).await;
    assert_eq!(s, 200, "{r}");
    assert_eq!(r["scope"], full);
    let rt3 = r["refresh_token"].as_str().unwrap();
    let (s, r) = refresh(&app, rt3, &[("scope", "openid admin")]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("invalid_scope"))
    );
}

#[tokio::test]
async fn removed_user_is_invalid_grant() {
    let rt = offline_rt(&app(STRICT), &[("user", "bob")]).await;
    let without_bob = STRICT.split("[user.bob]").next().unwrap();
    let (s, r) = refresh(&app(without_bob), &rt, &[]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn other_client_cannot_use_refresh_token() {
    let cfg = format!(
        "{STRICT}\n[client.other]\nclient_secret = \"s2\"\nredirect_uris = [\"http://localhost:4000/cb\"]\n"
    );
    let app = app(&cfg);
    let rt = offline_rt(&app, &[]).await;
    let (s, r) = refresh_with(&app, &rt, &[], &[("authorization", &basic("other", "s2"))]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn access_token_is_not_a_refresh_token() {
    let app = app(STRICT);
    let at = access_token_for(&app, &[("scope", "openid offline_access")]).await;
    let (s, r) = refresh(&app, &at, &[]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("invalid_grant"))
    );
}

#[tokio::test]
async fn missing_refresh_token_is_invalid_request() {
    let (s, r) = refresh(&app(STRICT), "", &[]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn client_without_refresh_grant_is_unauthorized_client() {
    let rt = offline_rt(&app(STRICT), &[]).await;
    let no_grant = app(&with_client_line("grant_types = [\"authorization_code\"]"));
    let (s, r) = refresh(&no_grant, &rt, &[]).await;
    assert_eq!(
        (s.as_u16(), r["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
}

#[tokio::test]
async fn custom_user_refreshes() {
    let app = app(STRICT);
    let rt = offline_rt(
        &app,
        &[
            ("user", "__custom__"),
            ("custom_sub", "c-1"),
            ("custom_claims", r#"{"email":"carol@example.com"}"#),
        ],
    )
    .await;
    let (s, r) = refresh(&app, &rt, &[]).await;
    assert_eq!(s, 200, "{r}");
    let id = claims_of(r["id_token"].as_str().unwrap());
    assert_eq!(
        (id["sub"].as_str(), id["email"].as_str()),
        (Some("c-1"), Some("carol@example.com"))
    );
}

#[tokio::test]
async fn public_client_refreshes_with_client_id_only() {
    let app = app(STRICT);
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let code = login_code(
        &app,
        &[
            ("client_id", "spa"),
            ("redirect_uri", SPA_CB),
            ("scope", "openid offline_access"),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", SPA_CB),
                ("client_id", "spa"),
                ("code_verifier", verifier),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let rt = json(&b)["refresh_token"].as_str().unwrap().to_owned();
    let (s, r) = refresh_with(&app, &rt, &[("client_id", "spa")], &[]).await;
    assert_eq!(s, 200, "{r}");
    assert!(r["refresh_token"].is_string());
}
