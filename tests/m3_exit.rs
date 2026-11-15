//! M3 exit test (plan Ruling 16; see docs/testing/m3-exit-test.md): a real server on loopback
//! with a watched config file, per-Issuer ES256 and PS256 keys, `private_key_jwt`, token exchange
//! across Issuers, `prompt=none` with a Session, key rotation, an Injected failure and hot reload.

mod common;
use common::*;

use std::net::SocketAddr;

use fauxidc::config::{CliOverrides, LoadInputs, SigningAlg};
use fauxidc::reload::watch_files;
use fauxidc::{Server, StartOptions};

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

static CLIENT_KEY: LazyLock<SigningKey> =
    LazyLock::new(|| SigningKey::generate_for(SigningAlg::ES256).unwrap());

/// A JWK as a TOML inline table.
fn jwk_toml(jwk: &Value) -> String {
    let fields: Vec<String> = jwk
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{k} = {v}"))
        .collect();
    format!("{{ {} }}", fields.join(", "))
}

fn config_text() -> String {
    format!(
        r#"[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"
sub_template = "auth0|{{user_id}}"

[issuer.es]
issuer_url = "http://localhost:9000/es/"
signing_alg = "ES256"

[issuer.ps]
issuer_url = "http://localhost:9000/ps/"
signing_alg = "PS256"

[client.example_app]
client_id = "example-app"
client_secret = "local"
redirect_uris = ["http://localhost:3000/api/auth/callback/*"]

[client.backend]
client_id = "backend"
grant_types = ["client_credentials", "{TOKEN_EXCHANGE}"]
scopes = ["api"]
jwks = {{ keys = [ {jwk} ] }}

[user.alice]
label = "Alice Admin"
claims = {{ email = "alice@example.com", name = "Alice Admin" }}

[user.bob]
label = "Bobby Viewer"
claims = {{ email = "bob@example.com", name = "Bobby Viewer" }}
"#,
        jwk = jwk_toml(&CLIENT_KEY.jwk)
    )
}

/// A `private_key_jwt` assertion of `backend` for the endpoint URL `aud`.
fn assertion(aud: &str) -> String {
    let mut header = jsonwebtoken::Header::new(SigningAlg::ES256.jwt());
    header.kid = Some(CLIENT_KEY.kid.clone());
    let claims = json!({
        "iss": "backend",
        "sub": "backend",
        "aud": aud,
        "exp": now() + 60,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    jsonwebtoken::encode(&header, &claims, &CLIENT_KEY.encoding).unwrap()
}

/// A reqwest client for the server at `addr`; every request sends `Host: localhost:9000`.
struct Mock {
    addr: SocketAddr,
    http: reqwest::Client,
}

impl Mock {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> reqwest::Response {
        let mut req = self
            .http
            .get(self.url(path))
            .header("host", "localhost:9000");
        if let Some(cookie) = cookie {
            req = req.header("cookie", cookie);
        }
        req.send().await.unwrap()
    }

    async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> reqwest::Response {
        self.http
            .post(self.url(path))
            .header("host", "localhost:9000")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(serde_urlencoded::to_string(form).unwrap())
            .send()
            .await
            .unwrap()
    }

    async fn post_json(&self, path: &str, body: &Value) -> reqwest::Response {
        self.http
            .post(self.url(path))
            .header("host", "localhost:9000")
            .json(body)
            .send()
            .await
            .unwrap()
    }

    async fn test_api_status(&self, user: &str) -> u16 {
        self.post_json("/_mock/auth0/token", &json!({ "user": user }))
            .await
            .status()
            .as_u16()
    }

    /// `/es/introspect` as `backend`; returns `active`.
    async fn introspect_es(&self, token: &str) -> Value {
        let a = assertion("http://localhost:9000/es/introspect");
        let r = self
            .post_form(
                "/es/introspect",
                &[
                    ("token", token),
                    ("client_assertion_type", ASSERTION_TYPE),
                    ("client_assertion", &a),
                ],
            )
            .await;
        assert_eq!(r.status(), 200);
        r.json::<Value>().await.unwrap()["active"].clone()
    }

    /// `prompt=none` at `/auth0/authorize` with an optional cookie; returns the `Location`.
    async fn prompt_none(&self, cookie: Option<&str>) -> String {
        let r = self
            .get(&authorize_url(&[("prompt", "none")]), cookie)
            .await;
        assert_eq!(r.status(), 302);
        r.headers()["location"].to_str().unwrap().to_owned()
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one ordered scenario, as in the runbook
async fn m3_exit() {
    // Setup: a watched config file in a temp dir and a real server on port 0.
    let dir = tmp_dir();
    let file = dir.join("fauxidc.toml");
    std::fs::write(&file, config_text()).unwrap();
    let inputs = LoadInputs {
        config_files: vec![file.clone()],
        env: vec![],
        flags: CliOverrides::default(),
        cwd: dir,
    };
    let loaded = fauxidc::config::load(&inputs).unwrap();
    let mut config = loaded.config.clone();
    config.server.bind = "127.0.0.1".into();
    config.server.port = 0;
    let server = Server::start_with(
        config,
        StartOptions {
            key_pem: Some(KEY.to_pem().into()),
        },
    )
    .await
    .unwrap();
    let addr = server.local_addr();
    let _watcher = watch_files(
        server.reload_handle(),
        inputs,
        loaded.files.clone(),
        Duration::from_millis(50),
    );
    let mock = Mock {
        addr,
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    };

    // 1. Per-Issuer keys: ES256 and PS256.
    let es_jwks: Value = mock.get("/es/jwks", None).await.json().await.unwrap();
    assert_eq!(es_jwks["keys"][0]["kty"], "EC", "{es_jwks}");
    let ps_jwks: Value = mock.get("/ps/jwks", None).await.json().await.unwrap();
    assert_eq!(ps_jwks["keys"][0]["alg"], "PS256", "{ps_jwks}");

    // 2. client_credentials with private_key_jwt at the ES256 Issuer.
    let a = assertion("http://localhost:9000/es/token");
    let r = mock
        .post_form(
            "/es/token",
            &[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &a),
            ],
        )
        .await;
    assert_eq!(r.status(), 200);
    let es_token = r.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(header_of(&es_token)["alg"], "ES256");

    // 3. Token exchange across Issuers: the ES256 token becomes an auth0 token.
    let a = assertion("http://localhost:9000/auth0/token");
    let r = mock
        .post_form(
            "/auth0/token",
            &[
                ("grant_type", TOKEN_EXCHANGE),
                ("subject_token", &es_token),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &a),
            ],
        )
        .await;
    assert_eq!(r.status(), 200);
    let exchanged = r.json::<Value>().await.unwrap();
    let c = claims_of(exchanged["access_token"].as_str().unwrap());
    assert_eq!(c["iss"], "http://localhost:9000/auth0/");
    assert_eq!(c["sub"], "backend");

    // 4. Login creates a Session; prompt=none uses it, and fails without it.
    let r = mock.post_form("/auth0/authorize", &login_fields(&[])).await;
    assert_eq!(r.status(), 302);
    let cookie = set_cookie(r.headers(), "fauxidc_session_auth0").unwrap();
    let loc = mock.prompt_none(Some(&cookie)).await;
    assert!(query_param(&loc, "code").is_some(), "{loc}");
    let loc = mock.prompt_none(None).await;
    assert_eq!(
        query_param(&loc, "error").as_deref(),
        Some("login_required")
    );

    // 5. Rotation keeps the old key; retire removes it.
    let r = mock.post_json("/_mock/es/rotate-key", &json!({})).await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.json::<Value>().await.unwrap()["keys"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(mock.introspect_es(&es_token).await, true);
    let r = mock
        .post_json("/_mock/es/rotate-key?retire=true", &json!({}))
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(mock.introspect_es(&es_token).await, false);

    // 6. An Injected failure hits the next request only.
    let r = mock
        .post_json(
            "/_mock/auth0/fail-next",
            &json!({ "endpoint": "jwks", "status": 503 }),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(mock.get("/auth0/jwks", None).await.status(), 503);
    assert_eq!(mock.get("/auth0/jwks", None).await.status(), 200);

    // 7. A config edit applies without a restart; the Session stays valid.
    assert_eq!(mock.test_api_status("carol").await, 400);
    std::fs::write(
        &file,
        format!("{}\n[user.carol]\nlabel = \"Carol\"\n", config_text()),
    )
    .unwrap();
    wait_until(Duration::from_secs(3), || async {
        mock.test_api_status("carol").await == 200
    })
    .await;
    assert_eq!(server.local_addr(), addr);
    let loc = mock.prompt_none(Some(&cookie)).await;
    assert!(query_param(&loc, "code").is_some(), "{loc}");

    // 8. An invalid file keeps the running config.
    std::fs::write(&file, "[issuer.auth0\nnot toml").unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(mock.test_api_status("carol").await, 200);

    server.shutdown().await.unwrap();
}
