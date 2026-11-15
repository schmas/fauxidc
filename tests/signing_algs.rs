//! Every `issuer.<id>.signing_alg` (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384):
//! token headers, JWKS, discovery, key rotation, key files and client assertions.

mod common;
use common::*;

use fauxidc::state::AppState;

const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const TOKEN_URL: &str = "http://localhost:9000/auth0/token";

const ALL: [SigningAlg; 8] = [
    SigningAlg::RS256,
    SigningAlg::RS384,
    SigningAlg::RS512,
    SigningAlg::PS256,
    SigningAlg::PS384,
    SigningAlg::PS512,
    SigningAlg::ES256,
    SigningAlg::ES384,
];

fn is_ec(alg: SigningAlg) -> bool {
    matches!(alg, SigningAlg::ES256 | SigningAlg::ES384)
}

/// A key for `alg`. RSA algorithms reuse the shared test key, so no slow RSA generation.
fn key_for(alg: SigningAlg) -> SigningKey {
    if is_ec(alg) {
        SigningKey::generate_for(alg).unwrap()
    } else {
        SigningKey::from_pem_for(KEY.to_pem(), alg).unwrap()
    }
}

/// `STRICT` plus the Issuer `x` with `signing_alg = alg` and a `key_file` that holds a key for
/// `alg`, so the Issuer does not generate a key.
fn cfg_for(alg: SigningAlg) -> String {
    let file = tmp_dir().join("x.pem");
    std::fs::write(&file, key_for(alg).to_pem()).unwrap();
    format!(
        "{STRICT}\n[issuer.x]\nissuer_url = \"http://localhost:9000/x\"\nsigning_alg = \"{}\"\nkey_file = \"{}\"\n",
        alg.as_str(),
        file.display()
    )
}

/// Verifies `token` with the JWKS key of its `kid`; returns the claims.
fn verify_with_jwks(token: &str, jwks: &Value) -> Value {
    let header = jsonwebtoken::decode_header(token).unwrap();
    let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(jwks.clone()).unwrap();
    let jwk = set.find(header.kid.as_deref().unwrap()).unwrap();
    let key = jsonwebtoken::DecodingKey::from_jwk(jwk).unwrap();
    let mut v = jsonwebtoken::Validation::new(header.alg);
    v.validate_aud = false;
    jsonwebtoken::decode::<Value>(token, &key, &v)
        .unwrap_or_else(|e| panic!("{:?}: {e}", header.alg))
        .claims
}

#[tokio::test]
async fn every_alg_signs_tokens_that_verify_against_the_jwks() {
    for alg in ALL {
        let app = app(&cfg_for(alg));
        let name = alg.as_str();
        let jwks = json(&send(&app, get("/x/jwks")).await.2);
        let jwk = &jwks["keys"][0];
        assert_eq!(jwk["alg"], name, "{jwks}");
        assert_eq!(jwk["use"], "sig", "{jwks}");
        if is_ec(alg) {
            let crv = if alg == SigningAlg::ES256 {
                "P-256"
            } else {
                "P-384"
            };
            assert_eq!(
                (jwk["kty"].as_str(), jwk["crv"].as_str()),
                (Some("EC"), Some(crv))
            );
        } else {
            assert_eq!(jwk["kty"], "RSA", "{jwks}");
        }
        let t = test_token(&app, "x", json!({"user": "alice"})).await;
        for field in ["access_token", "id_token"] {
            let token = t[field].as_str().unwrap();
            assert_eq!(header_of(token)["alg"], name, "{field}");
            assert_eq!(header_of(token)["kid"], jwk["kid"], "{field}");
            let claims = verify_with_jwks(token, &jwks);
            assert_eq!(claims["iss"], "http://localhost:9000/x", "{name} {field}");
        }
        // The server verifies its own tokens: /userinfo accepts the access token.
        let at = t["access_token"].as_str().unwrap();
        let (s, _, b) = send(
            &app,
            get_with("/x/userinfo", &[("authorization", &format!("Bearer {at}"))]),
        )
        .await;
        assert_eq!(s, 200, "{name}: {b}");
        let d = json(
            &send(&app, get("/x/.well-known/openid-configuration"))
                .await
                .2,
        );
        assert_eq!(d["id_token_signing_alg_values_supported"], json!([name]));
    }
}

#[tokio::test]
async fn es384_key_has_p384_coordinates() {
    let k = SigningKey::generate_for(SigningAlg::ES384).unwrap();
    assert_eq!(k.alg, SigningAlg::ES384);
    assert_eq!(k.jwk["crv"], "P-384");
    for c in ["x", "y"] {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(k.jwk[c].as_str().unwrap())
            .unwrap();
        assert_eq!(bytes.len(), 48, "{c}");
    }
    // PEM round trip keeps the key and the kid.
    let k2 = SigningKey::from_pem_for(k.to_pem(), SigningAlg::ES384).unwrap();
    assert_eq!(k.kid, k2.kid);
}

#[tokio::test]
async fn generated_keys_of_new_algs_are_saved_and_reused() {
    for alg in [SigningAlg::ES384, SigningAlg::RS512] {
        let file = tmp_dir().join("k.pem");
        let cfg = format!(
            "{AUTH0}\n[issuer.x]\nissuer_url = \"http://localhost:9000/x\"\nsigning_alg = \"{}\"\nkey_file = \"{}\"\n",
            alg.as_str(),
            file.display()
        );
        let first = json(&send(&app(&cfg), get("/x/jwks")).await.2)["keys"][0].clone();
        assert_eq!(first["alg"], alg.as_str());
        wait_until(Duration::from_secs(10), || {
            let ok =
                SigningKey::from_pem_for(&std::fs::read_to_string(&file).unwrap_or_default(), alg)
                    .is_ok();
            async move { ok }
        })
        .await;
        let again = json(&send(&app(&cfg), get("/x/jwks")).await.2)["keys"][0].clone();
        assert_eq!(first["kid"], again["kid"], "{alg:?}");
    }
}

#[tokio::test]
async fn rotation_keeps_the_alg() {
    for alg in [SigningAlg::RS384, SigningAlg::PS512, SigningAlg::ES384] {
        let app = app(&cfg_for(alg));
        let (s, _, b) = send(&app, post_json("/_mock/x/rotate-key", &json!({}))).await;
        assert_eq!(s, 200, "{b}");
        let jwks = json(&send(&app, get("/x/jwks")).await.2);
        let keys = jwks["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "{jwks}");
        for k in keys {
            assert_eq!(k["alg"], alg.as_str(), "{jwks}");
        }
        if alg == SigningAlg::ES384 {
            assert_eq!(keys[0]["crv"], "P-384", "{jwks}");
        }
        let at = test_token(&app, "x", json!({"user": "alice"})).await["access_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(header_of(&at)["alg"], alg.as_str());
        assert_eq!(header_of(&at)["kid"], json(&b)["kid"]);
        verify_with_jwks(&at, &jwks);
    }
}

/// A SEC1 (`BEGIN EC PRIVATE KEY`) P-256 test key.
const SEC1_P256: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM5t9oh+5YV6JQHtLrSrdV6aAArXBPKDYZsfwBu9aFH7oAoGCCqGSM49
AwEHoUQDQgAErAcWM9GmJWKfdhCbBtUyOzvFt2pXQ35b3vnUtyAL+6FXd0lI4c0L
NPkSDng5nhdKYEllvttqx8drUbMvsdmzZA==
-----END EC PRIVATE KEY-----
";

/// `(signing_alg, PEM, text the error names)`: key files that do not fit the algorithm.
fn mismatches() -> Vec<(SigningAlg, String, &'static str)> {
    let p256 = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let p384 = SigningKey::generate_for(SigningAlg::ES384).unwrap();
    vec![
        (SigningAlg::ES384, p256.to_pem().to_owned(), "P-384"),
        (SigningAlg::ES384, SEC1_P256.to_owned(), "P-384"),
        (SigningAlg::ES384, KEY.to_pem().to_owned(), "P-384"),
        (SigningAlg::ES256, p384.to_pem().to_owned(), "P-256"),
        (SigningAlg::RS384, p384.to_pem().to_owned(), "RSA"),
        (SigningAlg::PS512, p256.to_pem().to_owned(), "RSA"),
    ]
}

fn mismatch_cfg(alg: SigningAlg, pem: &str) -> (String, PathBuf) {
    let file = tmp_dir().join("bad.pem");
    std::fs::write(&file, pem).unwrap();
    let cfg = format!(
        "{STRICT}\n[issuer.x]\nissuer_url = \"http://localhost:9000/x\"\nsigning_alg = \"{}\"\nkey_file = \"{}\"\n",
        alg.as_str(),
        file.display()
    );
    (cfg, file)
}

#[tokio::test]
async fn a_key_file_of_the_wrong_type_fails_startup() {
    for (alg, pem, expected) in mismatches() {
        let (cfg, file) = mismatch_cfg(alg, &pem);
        let config = fauxidc::config::load_str(&cfg).unwrap().config;
        let Err(e) = AppState::new(config, KeyHandle::ready(KEY.clone()), true) else {
            panic!("{alg:?} accepted a wrong key: {pem}");
        };
        let text = e.to_string();
        assert!(
            text.contains(&file.display().to_string())
                && text.contains(expected)
                && text.contains(alg.as_str()),
            "{alg:?}: {text}"
        );
        // The file is not replaced.
        assert_eq!(std::fs::read_to_string(&file).unwrap(), pem);
    }
}

#[tokio::test]
async fn a_key_file_of_the_wrong_type_fails_reload() {
    for (alg, pem, expected) in mismatches() {
        let (app, handle) = live_app(STRICT);
        let (cfg, _) = mismatch_cfg(alg, &pem);
        let Err(e) = handle.apply(fauxidc::config::load_str(&cfg).unwrap().config) else {
            panic!("{alg:?} accepted a wrong key on reload");
        };
        assert!(
            matches!(e, fauxidc::reload::ReloadError::Start(_)),
            "{alg:?}: {e}"
        );
        assert!(e.to_string().contains(expected), "{alg:?}: {e}");
        // The old config stays: the Issuer x does not exist.
        assert_eq!(send(&app, get("/x/jwks")).await.0, 404);
    }
}

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

fn client_cfg(jwk: &Value) -> String {
    format!(
        "{STRICT}\n[client.backend]\nclient_id = \"backend\"\ngrant_types = [\"client_credentials\"]\n\
         scopes = [\"api\"]\njwks = {{ keys = [ {} ] }}\n",
        jwk_toml(jwk)
    )
}

fn assertion(key: &SigningKey, alg: SigningAlg) -> String {
    let mut h = jsonwebtoken::Header::new(alg.jwt());
    h.kid = Some(key.kid.clone());
    let claims = json!({
        "iss": "backend",
        "sub": "backend",
        "aud": TOKEN_URL,
        "exp": now() + 60,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    jsonwebtoken::encode(&h, &claims, &key.encoding).unwrap()
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
async fn client_assertions_of_every_alg_are_accepted() {
    for alg in ALL {
        let key = key_for(alg);
        let app = app(&client_cfg(&key.jwk));
        let (s, b) = client_credentials(&app, &assertion(&key, alg)).await;
        assert_eq!(s, 200, "{alg:?}: {b}");
    }
}

#[tokio::test]
async fn client_assertion_alg_must_fit_the_key() {
    // A P-256 JWK cannot verify an ES384 assertion; a P-384 JWK cannot verify ES256.
    let p256 = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let p384 = SigningKey::generate_for(SigningAlg::ES384).unwrap();
    let mut jwk = p256.jwk.clone();
    jwk.as_object_mut().unwrap().remove("alg");
    let ec_app = app(&client_cfg(&jwk));
    let (s, b) = client_credentials(&ec_app, &assertion(&p384, SigningAlg::ES384)).await;
    assert_eq!(s, 401, "{b}");
    // An RS384 JWK does not verify an RS512 assertion of the same RSA key.
    let rs384 = key_for(SigningAlg::RS384);
    let rsa_app = app(&client_cfg(&rs384.jwk));
    let (s, b) = client_credentials(&rsa_app, &assertion(&rs384, SigningAlg::RS512)).await;
    assert_eq!(s, 401, "{b}");
}

#[tokio::test]
async fn discovery_lists_every_assertion_alg() {
    let d = json(
        &send(&app(STRICT), get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    let algs: Vec<&str> = ALL.iter().map(|a| a.as_str()).collect();
    for key in [
        "token_endpoint_auth_signing_alg_values_supported",
        "introspection_endpoint_auth_signing_alg_values_supported",
        "revocation_endpoint_auth_signing_alg_values_supported",
    ] {
        assert_eq!(d[key], json!(algs), "{key}");
    }
}

#[tokio::test]
async fn es384_tokens_work_for_token_exchange_subjects() {
    // A token of the ES384 Issuer is a valid subject token at another Issuer (Strict mode).
    let cfg = format!(
        "{}\n[client.backend]\nclient_id = \"backend\"\nclient_secret = \"s\"\n\
         grant_types = [\"urn:ietf:params:oauth:grant-type:token-exchange\"]\n\
         audience = \"https://api.example.com\"\n",
        cfg_for(SigningAlg::ES384)
    );
    let app = app(&cfg);
    let at = test_token(&app, "x", json!({"user": "alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, _, b) = send(
        &app,
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
            &[("authorization", &basic("backend", "s"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
}
