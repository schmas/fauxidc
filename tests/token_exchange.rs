mod common;
use common::*;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

fn cfg() -> String {
    format!(
        "{STRICT}
[issuer.es]
issuer_url = \"http://localhost:9000/es\"
signing_alg = \"ES256\"

[client.gateway]
client_id = \"gateway\"
client_secret = \"gw\"
grant_types = [\"{GRANT}\"]
audience = \"https://api.example.com\"
"
    )
}

/// Posts a token exchange to `/{issuer}/token` as `gateway`. `extra` adds or replaces fields.
async fn exchange(app: &Router, issuer: &str, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut form: Vec<(&str, &str)> = vec![("grant_type", GRANT), ("subject_token_type", AT_TYPE)];
    for &(k, v) in extra {
        form.retain(|&(a, _)| a != k);
        form.push((k, v));
    }
    let (s, _, b) = send(
        app,
        post_form(
            &format!("/{issuer}/token"),
            &form,
            &[("authorization", &basic("gateway", "gw"))],
        ),
    )
    .await;
    (s, json(&b))
}

/// The access token of a Test API response.
async fn test_at(app: &Router, issuer: &str, body: Value) -> String {
    test_token(app, issuer, body).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn at_of(j: &Value) -> Value {
    claims_of(j["access_token"].as_str().unwrap())
}

#[tokio::test]
async fn exchanges_an_access_token_of_another_issuer() {
    let app = app(&cfg());
    let at = test_at(&app, "es", json!({"user":"alice","claims":{"roles":["x"]}})).await;
    let (s, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &at),
            ("audience", "https://orders.example.com"),
        ],
    )
    .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(
        j["issued_token_type"],
        "urn:ietf:params:oauth:token-type:access_token"
    );
    assert_eq!(j["token_type"], "Bearer");
    assert!(j["expires_in"].as_u64().unwrap() > 0);
    let c = at_of(&j);
    assert_eq!(c["iss"], "http://localhost:9000/auth0/");
    assert_eq!(c["sub"], claims_of(&at)["sub"]);
    assert_eq!(c["roles"], json!(["x"]));
    assert_eq!(c["aud"], "https://orders.example.com");
    assert_eq!(c["client_id"], "gateway");
    assert_eq!(c["scope"], claims_of(&at)["scope"]);
    assert_eq!(j["scope"], claims_of(&at)["scope"]);
    assert_eq!(c["auth_time"], claims_of(&at)["auth_time"]);
    assert!(c.get("act").is_none());
    assert!(j.get("refresh_token").is_none() && j.get("id_token").is_none());
    assert_eq!(
        header_of(j["access_token"].as_str().unwrap())["typ"],
        "at+jwt"
    );
}

#[tokio::test]
async fn audience_falls_back_to_resource_then_client_audience() {
    let app = app(&cfg());
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let (_, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &at),
            ("resource", "https://r.example.com"),
        ],
    )
    .await;
    assert_eq!(at_of(&j)["aud"], "https://r.example.com");
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let (_, j) = exchange(&app, "auth0", &[("subject_token", &at)]).await;
    assert_eq!(at_of(&j)["aud"], "https://api.example.com");
}

#[tokio::test]
async fn scope_parameter_replaces_the_subject_scope() {
    let app = app(&cfg());
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let (s, j) = exchange(
        &app,
        "auth0",
        &[("subject_token", &at), ("scope", "orders:read")],
    )
    .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(at_of(&j)["scope"], "orders:read");
    assert_eq!(j["scope"], "orders:read");
}

#[tokio::test]
async fn protocol_claims_are_replaced() {
    let app = app(&cfg());
    let idt = test_token(&app, "auth0", json!({"user":"alice"})).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &idt),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
        ],
    )
    .await;
    assert_eq!(s, 200, "{j}");
    let c = at_of(&j);
    let old = claims_of(&idt);
    assert_ne!(c["jti"], old["jti"]);
    assert_eq!(c["client_id"], "gateway");
    assert_eq!(c["aud"], "https://api.example.com");
    assert!(c.get("azp").is_none() && c.get("nonce").is_none() && c.get("sid").is_none());
    // An id_token has no scope claim: the new token has none either.
    assert!(c.get("scope").is_none() && j.get("scope").is_none());
}

#[tokio::test]
async fn expired_subject_token_is_rejected() {
    let app = app(&cfg());
    let at = test_at(&app, "auth0", json!({"user":"alice","expires_in":-10})).await;
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &at)]).await;
    assert_eq!(
        (s.as_u16(), j["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn subject_token_with_forged_iss_is_rejected() {
    // Claims iss of `auth0`, signed by a key that is not in auth0's key set.
    let app = app(&cfg());
    let stranger = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let t = sign_with(
        &stranger,
        &json!({"iss":"http://localhost:9000/auth0/","sub":"x","exp":now()+60}),
    );
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", &t)]).await.0,
        400
    );
    // A real `es` token with its payload iss rewritten to auth0 keeps es's kid: no key in
    // auth0's set, so it is rejected.
    let es = test_at(&app, "es", json!({"user":"alice"})).await;
    let mut parts: Vec<String> = es.split('.').map(str::to_owned).collect();
    let mut c = claims_of(&es);
    c["iss"] = json!("http://localhost:9000/auth0/");
    parts[1] = b64url(&serde_json::to_vec(&c).unwrap());
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", &parts.join("."))])
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn refresh_token_is_not_a_subject_token() {
    let app = app(&cfg());
    let rt = token_response_for(&app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", &rt)]).await.0,
        400
    );
}

#[tokio::test]
async fn revoked_subject_token_is_rejected() {
    let app = app(&cfg());
    let at = access_token_for(&app, &[]).await;
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", &at)]).await.0,
        200
    );
    send(
        &app,
        post_form(
            "/auth0/revoke",
            &[("token", &at)],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", &at)]).await.0,
        400
    );
}

#[tokio::test]
async fn lenient_accepts_an_unverified_jwt_but_not_garbage() {
    let cfg = cfg().replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&cfg);
    let t = unsigned_jwt(
        &json!({"alg":"none"}),
        &json!({"iss":"https://idp.example.com/","sub":"ext-1","email":"x@example.com"}),
    );
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &t)]).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(at_of(&j)["sub"], "ext-1");
    assert_eq!(at_of(&j)["email"], "x@example.com");
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", "opaque-value")])
            .await
            .0,
        400
    );
}

#[tokio::test]
async fn strict_rejects_a_foreign_jwt_and_a_client_without_the_grant() {
    let app = app(&cfg());
    let t = unsigned_jwt(
        &json!({"alg":"none"}),
        &json!({"iss":"https://idp.example.com/","sub":"ext-1"}),
    );
    assert_eq!(
        exchange(&app, "auth0", &[("subject_token", &t)]).await.0,
        400
    );
    let at = access_token_for(&app, &[]).await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", GRANT),
                ("subject_token", &at),
                ("subject_token_type", AT_TYPE),
            ],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
}

#[tokio::test]
async fn missing_subject_token_is_invalid_request() {
    let app = app(&cfg());
    let (s, j) = exchange(&app, "auth0", &[]).await;
    assert_eq!(
        (s.as_u16(), j["error"].as_str()),
        (400, Some("invalid_request"))
    );
    let at = access_token_for(&app, &[]).await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", GRANT), ("subject_token", &at)],
            &[("authorization", &basic("gateway", "gw"))],
        ),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_request"))
    );
}

#[tokio::test]
async fn bad_token_types_are_invalid_request() {
    let app = app(&cfg());
    let at = access_token_for(&app, &[]).await;
    assert_eq!(
        exchange(
            &app,
            "auth0",
            &[
                ("subject_token", &at),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:refresh_token"
                )
            ]
        )
        .await
        .0,
        400
    );
    assert_eq!(
        exchange(
            &app,
            "auth0",
            &[
                ("subject_token", &at),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:id_token"
                )
            ]
        )
        .await
        .0,
        400
    );
    let (s, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &at),
            ("subject_token_type", "urn:ietf:params:oauth:token-type:jwt"),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:jwt",
            ),
        ],
    )
    .await;
    assert_eq!(s, 200, "{j}");
}

#[tokio::test]
async fn discovery_lists_the_token_exchange_grant() {
    let d = json(
        &send(&app(&cfg()), get("/auth0/.well-known/openid-configuration"))
            .await
            .2,
    );
    assert!(
        d["grant_types_supported"]
            .as_array()
            .unwrap()
            .contains(&json!(GRANT))
    );
}
