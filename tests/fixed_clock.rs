//! `server.fixed_time`: one fixed clock for the issued times and for every time check (ADR 0007).

mod common;
use common::*;

use fauxidc::config::{CliOverrides, LoadInputs, load, load_str};
use fauxidc::reload::reload_from;

const FIXED: &str = "2020-01-21T00:00:00Z";
const FIXED_SECS: u64 = 1_579_564_800;
/// A fixed time far after any real clock of a test run: 2100-01-01T00:00:00Z.
const FUTURE: &str = "2100-01-01T00:00:00Z";
const FUTURE_SECS: u64 = 4_102_444_800;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

static CLIENT_KEY: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::generate_for(SigningAlg::ES256).unwrap());

/// `STRICT` plus a `private_key_jwt` Client and a jwt-bearer Client, at the fixed time `at`.
fn cfg(at: Option<&str>) -> String {
    let server = at.map_or(String::new(), |t| {
        format!("[server]\nfixed_time = \"{t}\"\n")
    });
    let jwk: Vec<String> = CLIENT_KEY
        .jwk
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect();
    format!(
        "{server}{STRICT}
[client.backend]
client_id = \"backend\"
grant_types = [\"client_credentials\"]
scopes = [\"api\"]
jwks = {{ keys = [ {{ {} }} ] }}

[client.obo]
client_id = \"obo\"
client_secret = \"s\"
grant_types = [\"{JWT_BEARER}\"]
audience = \"https://api.example.com\"
",
        jwk.join(", ")
    )
}

fn claim(token: &Value, name: &str, claim: &str) -> u64 {
    claims_of(token[name].as_str().unwrap())[claim]
        .as_u64()
        .unwrap()
}

#[tokio::test]
async fn token_times_equal_the_fixed_time() {
    let app = app(&cfg(Some(FIXED)));
    let j = token_response_for(&app, &[("scope", "openid offline_access")]).await;
    assert_eq!(j["expires_in"], 3600);
    assert_eq!(claim(&j, "id_token", "iat"), FIXED_SECS);
    assert_eq!(claim(&j, "id_token", "exp"), FIXED_SECS + 3600);
    assert_eq!(claim(&j, "id_token", "auth_time"), FIXED_SECS);
    assert_eq!(claim(&j, "access_token", "iat"), FIXED_SECS);
    assert_eq!(claim(&j, "access_token", "exp"), FIXED_SECS + 3600);
    assert_eq!(claim(&j, "access_token", "auth_time"), FIXED_SECS);
    assert_eq!(claim(&j, "refresh_token", "iat"), FIXED_SECS);
    assert_eq!(claim(&j, "refresh_token", "exp"), FIXED_SECS + 86400);
}

/// The code expires 60 s after the fixed time, in the real past. The exchange works only when
/// the code check uses the same clock.
#[tokio::test]
async fn code_exchange_works_with_a_fixed_time_in_the_past() {
    let app = app(&cfg(Some(FIXED)));
    let code = login_code(&app, &[]).await;
    assert!(exchange_code_for(&app, &code).await["id_token"].is_string());
}

#[tokio::test]
async fn refresh_works_with_a_fixed_time_in_the_past() {
    let app = app(&cfg(Some(FIXED)));
    let rt = token_response_for(&app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
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
    assert_eq!(claim(&json(&b), "access_token", "iat"), FIXED_SECS);
}

#[tokio::test]
async fn introspect_and_userinfo_accept_a_token_of_the_fixed_clock() {
    let app = app(&cfg(Some(FIXED)));
    let at = access_token_for(&app, &[]).await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[("token", &at)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    let j = json(&b);
    assert_eq!(j["active"], true, "{j}");
    assert_eq!(j["iat"], FIXED_SECS);
    let (s, _, b) = send(
        &app,
        get_with(
            "/auth0/userinfo",
            &[("authorization", &format!("Bearer {at}"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

/// The revocation list keeps a `jti` until its `exp`, in the real past here.
#[tokio::test]
async fn revoked_token_stays_inactive_with_a_fixed_time_in_the_past() {
    let app = app(&cfg(Some(FIXED)));
    let at = access_token_for(&app, &[]).await;
    let auth = basic("example-app", "local");
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &at)],
            &[("authorization", &auth)],
        ),
    )
    .await;
    assert_eq!(s, 200);
    let (_, _, b) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[("token", &at)],
            &[("authorization", &auth)],
        ),
    )
    .await;
    assert_eq!(json(&b)["active"], false, "{b}");
}

#[tokio::test]
async fn test_api_tokens_use_the_fixed_clock() {
    let app = app(&cfg(Some(FIXED)));
    let j = test_token(&app, "auth0", json!({ "user": "alice", "expires_in": -60 })).await;
    assert_eq!(j["expires_in"], -60);
    assert_eq!(claim(&j, "access_token", "iat"), FIXED_SECS);
    assert_eq!(claim(&j, "access_token", "exp"), FIXED_SECS - 60);
    assert_eq!(claim(&j, "id_token", "auth_time"), FIXED_SECS);
}

/// The session is 2 s old on the real clock; on the fixed clock it is 0 s old.
#[tokio::test]
async fn max_age_uses_the_fixed_clock() {
    let app = app(&cfg(Some(FIXED)));
    let (_, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("max_age", "1")]),
            &[("cookie", &cookie)],
        ),
    )
    .await;
    assert!(query_param(&location(&h), "code").is_some(), "{h:?}");
}

fn client_assertion(claims: &Value) -> String {
    let mut h = jsonwebtoken::Header::new(SigningAlg::ES256.jwt());
    h.kid = Some(CLIENT_KEY.kid.clone());
    jsonwebtoken::encode(&h, claims, &CLIENT_KEY.encoding).unwrap()
}

fn assertion_claims(iat: u64) -> Value {
    json!({
        "iss": "backend",
        "sub": "backend",
        "aud": "http://localhost:9000/auth0/token",
        "iat": iat,
        "nbf": iat,
        "exp": iat + 60,
        "jti": uuid::Uuid::new_v4().to_string(),
    })
}

async fn client_credentials(app: &Router, assertion: &str) -> (StatusCode, String) {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", assertion),
            ],
            &[],
        ),
    )
    .await;
    (s, b)
}

#[tokio::test]
async fn client_assertion_is_checked_against_the_fixed_clock() {
    let past = app(&cfg(Some(FIXED)));
    let (s, b) = client_credentials(&past, &client_assertion(&assertion_claims(FIXED_SECS))).await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(claim(&json(&b), "access_token", "iat"), FIXED_SECS);
    // Valid on the real clock only: `nbf` is after the fixed time.
    let (s, b) = client_credentials(&past, &client_assertion(&assertion_claims(now()))).await;
    assert_eq!(s, 401, "{b}");

    let future = app(&cfg(Some(FUTURE)));
    let (s, b) =
        client_credentials(&future, &client_assertion(&assertion_claims(FUTURE_SECS))).await;
    assert_eq!(s, 200, "{b}");
    // Valid on the real clock only: `exp` is before the fixed time.
    let (s, b) = client_credentials(&future, &client_assertion(&assertion_claims(now()))).await;
    assert_eq!(s, 401, "{b}");
}

#[tokio::test]
async fn jwt_bearer_assertion_is_checked_against_the_fixed_clock() {
    let app = app(&cfg(Some(FIXED)));
    let at = test_token(&app, "auth0", json!({ "user": "alice" })).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", JWT_BEARER), ("assertion", &at)],
            &[("authorization", &basic("obo", "s"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(claim(&json(&b), "access_token", "iat"), FIXED_SECS);
}

#[tokio::test]
async fn unset_uses_the_system_clock() {
    let app = app(&cfg(None));
    let before = now();
    let j = token_response_for(&app, &[]).await;
    let iat = claim(&j, "id_token", "iat");
    assert!(iat >= before && iat <= now(), "{iat}");
}

async fn iat_now(app: &Router) -> u64 {
    claim(
        &test_token(app, "auth0", json!({ "user": "alice" })).await,
        "access_token",
        "iat",
    )
}

#[tokio::test]
async fn reload_sets_changes_and_removes_the_fixed_time() {
    let (app, handle) = live_app(&cfg(None));
    assert!(iat_now(&app).await >= now() - 5);
    handle
        .apply(load_str(&cfg(Some(FIXED))).unwrap().config)
        .unwrap();
    assert_eq!(iat_now(&app).await, FIXED_SECS);
    handle
        .apply(load_str(&cfg(Some("2020-01-21T00:01:40Z"))).unwrap().config)
        .unwrap();
    assert_eq!(iat_now(&app).await, FIXED_SECS + 100);
    handle.apply(load_str(&cfg(None)).unwrap().config).unwrap();
    assert!(iat_now(&app).await >= now() - 5);
}

/// A session made at the fixed time is 100 s old after a reload moves the clock 100 s on.
#[tokio::test]
async fn max_age_follows_a_reloaded_clock() {
    let (app, handle) = live_app(&cfg(Some(FIXED)));
    let (_, h, _) = send(&app, post_form("/auth0/authorize", &login_fields(&[]), &[])).await;
    let cookie = set_cookie(&h, "fauxidc_session_auth0").unwrap();
    handle
        .apply(load_str(&cfg(Some("2020-01-21T00:01:40Z"))).unwrap().config)
        .unwrap();
    let (_, h, _) = send(
        &app,
        get_with(
            &authorize_url(&[("prompt", "none"), ("max_age", "10")]),
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
async fn file_reload_applies_the_fixed_time() {
    let dir = tmp_dir();
    let file = dir.join("fauxidc.toml");
    std::fs::write(&file, cfg(None)).unwrap();
    let inputs = LoadInputs {
        config_files: vec![file.clone()],
        env: vec![],
        flags: CliOverrides::default(),
        cwd: dir,
    };
    let (app, handle) = live_app_from(load(&inputs).unwrap().config);
    std::fs::write(&file, cfg(Some(FIXED))).unwrap();
    assert!(reload_from(&handle, &inputs));
    assert_eq!(iat_now(&app).await, FIXED_SECS);
    std::fs::write(&file, cfg(None)).unwrap();
    assert!(reload_from(&handle, &inputs));
    assert!(iat_now(&app).await >= now() - 5);
}

#[test]
fn env_var_sets_the_fixed_time() {
    let inputs = LoadInputs {
        config_files: vec![],
        env: vec![
            ("FAUXIDC__SERVER__FIXED_TIME".into(), FIXED.into()),
            (
                "FAUXIDC__ISSUER__AUTH0__ISSUER_URL".into(),
                "http://localhost:9000/auth0/".into(),
            ),
        ],
        flags: CliOverrides::default(),
        cwd: tmp_dir(),
    };
    assert_eq!(load(&inputs).unwrap().config.server.fixed_time, FIXED);
}

#[test]
fn offsets_and_fractions_are_accepted() {
    for t in ["2020-01-21T01:00:00+01:00", "2020-01-21T00:00:00.999Z"] {
        assert!(load_str(&cfg(Some(t))).is_ok(), "{t}");
    }
}

#[tokio::test]
async fn offset_gives_the_same_instant() {
    let app = app(&cfg(Some("2020-01-20T21:00:00-03:00")));
    assert_eq!(iat_now(&app).await, FIXED_SECS);
}

#[tokio::test]
async fn invalid_fixed_time_is_a_config_error() {
    for bad in [
        "yesterday",
        "2020-01-21",
        "2020-13-01T00:00:00Z",
        "1969-12-31T23:59:59Z",
    ] {
        let err = load_str(&cfg(Some(bad))).unwrap_err().to_string();
        assert!(err.contains("server.fixed_time"), "{bad}: {err}");
        assert!(err.contains("RFC 3339"), "{bad}: {err}");
    }
    let (app, handle) = live_app(&cfg(None));
    let mut bad = load_str(&cfg(None)).unwrap().config;
    bad.server.fixed_time = "yesterday".into();
    assert!(handle.apply(bad).is_err());
    assert!(iat_now(&app).await >= now() - 5);
}
