//! `private_key_jwt` client authentication (RFC 7523) with a Client `jwks` or `jwks_uri`.

mod common;
use common::*;

use fauxidc::config::SigningAlg;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const TOKEN_URL: &str = "http://localhost:9000/auth0/token";

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

fn cfg_with(jwk: &Value) -> String {
    format!(
        "{STRICT}\n[client.backend]\nclient_id = \"backend\"\ngrant_types = [\"client_credentials\"]\n\
         scopes = [\"api\"]\njwks = {{ keys = [ {} ] }}\n",
        jwk_toml(jwk)
    )
}

fn cfg() -> String {
    cfg_with(&CLIENT_KEY.jwk)
}

#[allow(clippy::needless_pass_by_value)] // call sites build the claims inline
fn assertion(claims: Value, alg: SigningAlg, key: &SigningKey) -> String {
    let mut h = jsonwebtoken::Header::new(alg.jwt());
    h.kid = Some(key.kid.clone());
    jsonwebtoken::encode(&h, &claims, &key.encoding).unwrap()
}

fn claims(aud: &str) -> Value {
    json!({
        "iss": "backend",
        "sub": "backend",
        "aud": aud,
        "exp": now() + 60,
        "jti": uuid::Uuid::new_v4().to_string(),
    })
}

async fn cc(app: &Router, assertion: &str) -> (StatusCode, Value) {
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
    (s, serde_json::from_str(&b).unwrap_or(Value::Null))
}

#[tokio::test]
async fn client_credentials_with_private_key_jwt() {
    let (s, j) = cc(
        &app(&cfg()),
        &assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY),
    )
    .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(
        claims_of(j["access_token"].as_str().unwrap())["client_id"],
        "backend"
    );
}

#[tokio::test]
async fn issuer_url_is_an_accepted_audience() {
    let (s, _) = cc(
        &app(&cfg()),
        &assertion(
            claims("http://localhost:9000/auth0/"),
            SigningAlg::ES256,
            &CLIENT_KEY,
        ),
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn assertion_jti_is_single_use() {
    let app = app(&cfg());
    let a = assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY);
    assert_eq!(cc(&app, &a).await.0, 200);
    let (s, j) = cc(&app, &a).await;
    assert_eq!(
        (s.as_u16(), j["error"].as_str()),
        (401, Some("invalid_client"))
    );
}

#[tokio::test]
async fn assertion_for_other_audience_is_rejected() {
    assert_eq!(
        cc(
            &app(&cfg()),
            &assertion(
                claims("http://localhost:9000/okta/token"),
                SigningAlg::ES256,
                &CLIENT_KEY
            )
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn expired_or_wrong_key_assertion_is_rejected() {
    let mut c = claims(TOKEN_URL);
    c["exp"] = json!(now() - 1);
    assert_eq!(
        cc(&app(&cfg()), &assertion(c, SigningAlg::ES256, &CLIENT_KEY))
            .await
            .0,
        401
    );
    let other = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    assert_eq!(
        cc(
            &app(&cfg()),
            &assertion(claims(TOKEN_URL), SigningAlg::ES256, &other)
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn assertion_with_hs256_or_none_is_rejected() {
    // HS256 with the public JWK JSON as the secret.
    let secret = serde_json::to_vec(&CLIENT_KEY.jwk).unwrap();
    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    h.kid = Some(CLIENT_KEY.kid.clone());
    let hs = jsonwebtoken::encode(
        &h,
        &claims(TOKEN_URL),
        &jsonwebtoken::EncodingKey::from_secret(&secret).unwrap(),
    )
    .unwrap();
    assert_eq!(cc(&app(&cfg()), &hs).await.0, 401);
    let none = unsigned_jwt(&json!({"alg": "none"}), &claims(TOKEN_URL));
    assert_eq!(cc(&app(&cfg()), &none).await.0, 401);
}

#[tokio::test]
async fn assertion_plus_secret_is_invalid_request() {
    let cfg = cfg().replace(
        "[client.backend]\n",
        "[client.backend]\nclient_secret = \"s\"\n",
    );
    let a = assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY);
    let (s, _, b) = send(
        &app(&cfg),
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &a),
            ],
            &[("authorization", &basic("backend", "s"))],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn client_with_secret_and_jwks_may_use_either() {
    let cfg = cfg().replace(
        "[client.backend]\n",
        "[client.backend]\nclient_secret = \"s\"\n",
    );
    let app = app(&cfg);
    assert_eq!(
        cc(
            &app,
            &assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY)
        )
        .await
        .0,
        200
    );
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "client_credentials"), ("scope", "api")],
            &[("authorization", &basic("backend", "s"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn jwks_only_client_without_assertion_fails() {
    let (s, _, b) = send(
        &app(&cfg()),
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_id", "backend"),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (401, Some("invalid_client"))
    );
}

#[tokio::test]
async fn form_client_id_must_match_sub() {
    let a = assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY);
    let (s, _, _) = send(
        &app(&cfg()),
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_id", "example-app"),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &a),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn wrong_assertion_type_is_rejected() {
    let a = assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY);
    let (s, _, _) = send(
        &app(&cfg()),
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "client_credentials"),
                ("scope", "api"),
                ("client_assertion_type", "urn:example:other"),
                ("client_assertion", &a),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn lenient_accepts_a_bad_assertion_with_a_warning() {
    let cfg = cfg().replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let other = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    assert_eq!(
        cc(
            &app(&cfg),
            &assertion(claims(TOKEN_URL), SigningAlg::ES256, &other)
        )
        .await
        .0,
        200
    );
}

#[tokio::test]
async fn introspect_accepts_private_key_jwt_with_introspect_audience() {
    let app = app(&cfg());
    let (_, j) = cc(
        &app,
        &assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY),
    )
    .await;
    let at = j["access_token"].as_str().unwrap();
    let a = assertion(
        claims("http://localhost:9000/auth0/introspect"),
        SigningAlg::ES256,
        &CLIENT_KEY,
    );
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/introspect",
            &[
                ("token", at),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &a),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(json(&b)["active"], true);
}

#[tokio::test]
async fn revoke_accepts_private_key_jwt() {
    let app = app(&cfg());
    let (_, j) = cc(
        &app,
        &assertion(claims(TOKEN_URL), SigningAlg::ES256, &CLIENT_KEY),
    )
    .await;
    let at = j["access_token"].as_str().unwrap();
    let a = assertion(
        claims("http://localhost:9000/auth0/revoke"),
        SigningAlg::ES256,
        &CLIENT_KEY,
    );
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[
                ("token", at),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &a),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}

#[tokio::test]
async fn rs256_and_ps256_client_keys_work() {
    for alg in [SigningAlg::RS256, SigningAlg::PS256] {
        let key = SigningKey::from_pem_for(KEY.to_pem(), alg).unwrap();
        let (s, j) = cc(
            &app(&cfg_with(&key.jwk)),
            &assertion(claims(TOKEN_URL), alg, &key),
        )
        .await;
        assert_eq!(s, 200, "{alg:?}: {j}");
    }
}
