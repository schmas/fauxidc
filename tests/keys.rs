mod common;
use common::*;

static TWO: LazyLock<String> = LazyLock::new(|| {
    format!(
        "{STRICT}
[issuer.es]
issuer_url = \"http://localhost:9000/es\"
signing_alg = \"ES256\"

[issuer.ps]
issuer_url = \"http://localhost:9000/ps\"
signing_alg = \"PS256\"
"
    )
});

fn bearer(at: &str) -> String {
    format!("Bearer {at}")
}

#[tokio::test]
async fn es256_issuer_signs_with_its_own_key() {
    let app = app(&TWO);
    let j = json(&send(&app, get("/es/jwks")).await.2);
    let jwk = &j["keys"][0];
    assert_eq!(
        (jwk["kty"].as_str(), jwk["alg"].as_str()),
        (Some("EC"), Some("ES256"))
    );
    let t = test_token(&app, "es", json!({"user":"alice"})).await;
    let at = t["access_token"].as_str().unwrap();
    assert_eq!(header_of(at)["alg"], "ES256");
    assert_eq!(header_of(at)["kid"], jwk["kid"]);
    assert_eq!(header_of(t["id_token"].as_str().unwrap())["alg"], "ES256");
    let (s, _, _) = send(
        &app,
        get_with("/es/userinfo", &[("authorization", &bearer(at))]),
    )
    .await;
    assert_eq!(s, 200);
    let d = json(
        &send(&app, get("/es/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(d["id_token_signing_alg_values_supported"], json!(["ES256"]));
}

#[tokio::test]
async fn ps256_issuer_signs_with_ps256() {
    let app = app(&TWO);
    let at = test_token(&app, "ps", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(header_of(&at)["alg"], "PS256");
    assert_eq!(
        json(&send(&app, get("/ps/jwks")).await.2)["keys"][0]["alg"],
        "PS256"
    );
    let (s, _, _) = send(
        &app,
        get_with("/ps/userinfo", &[("authorization", &bearer(&at))]),
    )
    .await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn issuers_with_own_keys_reject_each_others_tokens() {
    let app = app(&TWO);
    let at = test_token(&app, "es", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, _, _) = send(
        &app,
        get_with("/auth0/userinfo", &[("authorization", &bearer(&at))]),
    )
    .await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn rs256_issuers_share_the_server_key() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    let a = json(&send(&app, get("/auth0/jwks")).await.2);
    let b = json(&send(&app, get("/okta/jwks")).await.2);
    assert_eq!(a, b);
    assert_eq!(a["keys"].as_array().unwrap().len(), 1);
    assert_eq!(a["keys"][0]["kid"], KEY.kid.as_str());
    assert_eq!(a["keys"][0]["alg"], "RS256");
    let d = json(
        &send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert_eq!(d["id_token_signing_alg_values_supported"], json!(["RS256"]));
}

#[tokio::test]
async fn issuer_key_file_is_saved_and_reused() {
    let dir = tmp_dir();
    let file = dir.join("es.pem");
    let cfg = format!(
        "{AUTH0}\n[issuer.es]\nissuer_url = \"http://localhost:9000/es\"\nsigning_alg = \"ES256\"\nkey_file = \"{}\"\n",
        file.display()
    );
    let kid1 = json(&send(&app(&cfg), get("/es/jwks")).await.2)["keys"][0]["kid"].clone();
    for _ in 0..200 {
        if file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let kid2 = json(&send(&app(&cfg), get("/es/jwks")).await.2)["keys"][0]["kid"].clone();
    assert!(kid1.is_string());
    assert_eq!(kid1, kid2);
}

async fn introspect_active(app: &Router, issuer: &str, token: &str) -> bool {
    let (s, _, b) = send(
        app,
        post_form(
            &format!("/{issuer}/introspect"),
            &[("token", token)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    json(&b)["active"] == true
}

#[tokio::test]
async fn rotate_adds_active_key_and_keeps_old() {
    let app = app(&TWO);
    let old = json(&send(&app, get("/es/jwks")).await.2)["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, _, b) = send(&app, post_json("/_mock/es/rotate-key", &json!({}))).await;
    assert_eq!(s, 200, "{b}");
    let r = json(&b);
    let new = r["kid"].as_str().unwrap().to_owned();
    assert_ne!(new, old);
    assert_eq!(r["keys"], json!([new, old]));
    assert_eq!(r["retired"], json!([]));
    let jwks = json(&send(&app, get("/es/jwks")).await.2);
    let kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids, vec![new.as_str(), old.as_str()]);
    assert_eq!(jwks["keys"][0]["alg"], "ES256");
    let at = test_token(&app, "es", json!({"user":"alice"})).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(header_of(&at)["kid"], new.as_str());
    assert_eq!(header_of(&at)["alg"], "ES256");
}

#[tokio::test]
async fn old_token_works_after_rotate_and_fails_after_retire() {
    let app = app(&TWO);
    let t = test_token(&app, "es", json!({"user":"alice"})).await;
    let at = t["access_token"].as_str().unwrap().to_owned();
    let auth = bearer(&at);
    send(&app, post_json("/_mock/es/rotate-key", &json!({}))).await;
    assert_eq!(
        send(&app, get_with("/es/userinfo", &[("authorization", &auth)]))
            .await
            .0,
        200
    );
    assert!(introspect_active(&app, "es", &at).await);
    let (_, _, b) = send(
        &app,
        post_json("/_mock/es/rotate-key?retire=true", &json!({})),
    )
    .await;
    assert_eq!(json(&b)["keys"].as_array().unwrap().len(), 1);
    assert_eq!(json(&b)["retired"].as_array().unwrap().len(), 2);
    assert_eq!(
        send(&app, get_with("/es/userinfo", &[("authorization", &auth)]))
            .await
            .0,
        401
    );
    assert!(!introspect_active(&app, "es", &at).await);
}

async fn refresh(app: &Router, rt: &str) -> (StatusCode, Value) {
    let (s, _, b) = send(
        app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", rt)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    (s, json(&b))
}

#[tokio::test]
async fn refresh_token_survives_rotation() {
    let app = app(STRICT);
    let t = token_response_for(&app, &[("scope", "openid offline_access")]).await;
    let rt = t["refresh_token"].as_str().unwrap().to_owned();
    send(&app, post_json("/_mock/auth0/rotate-key", &json!({}))).await;
    let (s, r) = refresh(&app, &rt).await;
    assert_eq!(s, 200, "{r}");
    // The refresh token issued after the rotation is signed with the new key; retire removes it.
    let rt2 = r["refresh_token"].as_str().unwrap().to_owned();
    send(
        &app,
        post_json("/_mock/auth0/rotate-key?retire=true", &json!({})),
    )
    .await;
    let (s, r) = refresh(&app, &rt2).await;
    assert_eq!(s, 400, "{r}");
    assert_eq!(r["error"], "invalid_grant");
}

#[tokio::test]
async fn rotating_one_issuer_leaves_the_shared_key_of_others() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let app = app(&cfg);
    send(&app, post_json("/_mock/auth0/rotate-key", &json!({}))).await;
    let okta = json(&send(&app, get("/okta/jwks")).await.2);
    assert_eq!(okta["keys"].as_array().unwrap().len(), 1);
    assert_eq!(okta["keys"][0]["kid"], KEY.kid.as_str());
    let auth0 = json(&send(&app, get("/auth0/jwks")).await.2);
    assert_eq!(auth0["keys"].as_array().unwrap().len(), 2);
    assert_eq!(auth0["keys"][0]["alg"], "RS256");
}

#[tokio::test]
async fn rotate_unknown_issuer_is_404() {
    let (s, _, b) = send(&app(&TWO), post_json("/_mock/nope/rotate-key", &json!({}))).await;
    assert_eq!(s, 404);
    assert_eq!(json(&b)["error"], "not_found");
}

#[tokio::test]
async fn rotate_rejects_a_bad_retire_value() {
    let (s, _, b) = send(
        &app(&TWO),
        post_json("/_mock/es/rotate-key?retire=1", &json!({})),
    )
    .await;
    assert_eq!(s, 400);
    assert_eq!(json(&b)["error"], "invalid_request");
}

fn rotate_request(origin: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/_mock/auth0/rotate-key?retire=true")
        .header("host", "localhost:9000");
    if let Some(origin) = origin {
        b = b.header("origin", origin);
    }
    b.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn cross_origin_rotate_key_is_rejected() {
    let app = app(AUTH0);
    let before = json(&send(&app, get("/auth0/jwks")).await.2);
    let (s, h, b) = send(&app, rotate_request(Some("http://evil.example.com"))).await;
    assert_eq!(s, 403, "{b}");
    assert_eq!(
        json(&b),
        json!({"error":"access_denied","error_description":"cross-origin Test API request"})
    );
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(json(&send(&app, get("/auth0/jwks")).await.2), before);
    assert_eq!(
        send(&app, rotate_request(Some("http://localhost:9000")))
            .await
            .0,
        200
    );
    assert_eq!(send(&app, rotate_request(None)).await.0, 200);
}

#[tokio::test]
async fn cross_origin_check_runs_before_the_issuer_lookup() {
    let req = Request::builder()
        .method("POST")
        .uri("/_mock/nope/rotate-key")
        .header("host", "localhost:9000")
        .header("origin", "http://evil.example.com")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app(AUTH0), req).await.0, 403);
}

#[tokio::test]
async fn rotation_keeps_at_most_ten_keys() {
    let app = app(AUTH0);
    let first = json(&send(&app, get("/auth0/jwks")).await.2)["keys"][0]["kid"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut last = Value::Null;
    for _ in 0..12 {
        let (s, _, b) = send(&app, post_json("/_mock/auth0/rotate-key", &json!({}))).await;
        assert_eq!(s, 200, "{b}");
        last = json(&b);
    }
    assert_eq!(last["keys"].as_array().unwrap().len(), 10, "{last}");
    assert_eq!(last["retired"].as_array().unwrap().len(), 1, "{last}");
    let jwks = json(&send(&app, get("/auth0/jwks")).await.2);
    let kids: Vec<&str> = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids.len(), 10);
    assert!(!kids.contains(&first.as_str()), "the startup key is gone");
    assert!(!kids.contains(&last["retired"][0].as_str().unwrap()));
}

#[tokio::test]
async fn revoke_and_endsession_accept_tokens_signed_before_a_rotation() {
    let cfg = STRICT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\npost_logout_redirect_uris = [\"http://localhost:3000/\"]\n",
    );
    let app = app(&cfg);
    let tokens = token_response_for(&app, &[("scope", "openid offline_access")]).await;
    let rt = tokens["refresh_token"].as_str().unwrap().to_owned();
    let idt = tokens["id_token"].as_str().unwrap().to_owned();
    let (s, _, b) = send(&app, post_json("/_mock/auth0/rotate-key", &json!({}))).await;
    assert_eq!(s, 200, "{b}");
    // /revoke verifies the old token by kid: the refresh token stops working.
    let auth = basic("example-app", "local");
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &rt)],
            &[("authorization", &auth)],
        ),
    )
    .await;
    assert_eq!(s, 200);
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "refresh_token"), ("refresh_token", &rt)],
            &[("authorization", &auth)],
        ),
    )
    .await;
    assert_eq!(json(&b)["error"], "invalid_grant", "{s} {b}");
    // /endsession finds the Client from the old id_token_hint.
    let url = format!(
        "/auth0/endsession?id_token_hint={idt}&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2F"
    );
    let (s, h, b) = send(&app, get(&url)).await;
    assert_eq!(s, 302, "{b}");
    assert_eq!(location(&h), "http://localhost:3000/");
}

/// A SEC1 (`BEGIN EC PRIVATE KEY`) P-256 test key.
const SEC1_P256: &str = "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM5t9oh+5YV6JQHtLrSrdV6aAArXBPKDYZsfwBu9aFH7oAoGCCqGSM49
AwEHoUQDQgAErAcWM9GmJWKfdhCbBtUyOzvFt2pXQ35b3vnUtyAL+6FXd0lI4c0L
NPkSDng5nhdKYEllvttqx8drUbMvsdmzZA==
-----END EC PRIVATE KEY-----
";

#[test]
fn sec1_ec_pem_loads() {
    let key = SigningKey::from_pem_for(SEC1_P256, SigningAlg::ES256).unwrap();
    assert_eq!(key.alg, SigningAlg::ES256);
    assert_eq!(key.jwk["crv"], "P-256");
}
