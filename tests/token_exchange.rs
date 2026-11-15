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
async fn expired_subject_token_is_invalid_request() {
    let app = app(&cfg());
    let at = test_at(&app, "auth0", json!({"user":"alice","expires_in":-10})).await;
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &at)]).await;
    assert_rejected(s, &j, "subject_token is invalid");
}

#[tokio::test]
async fn subject_token_with_forged_iss_is_invalid_request() {
    // Claims iss of `auth0`, signed by a key that is not in auth0's key set.
    let app = app(&cfg());
    let stranger = SigningKey::generate_for(SigningAlg::ES256).unwrap();
    let t = sign_with(
        &stranger,
        &json!({"iss":"http://localhost:9000/auth0/","sub":"x","exp":now()+60}),
    );
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &t)]).await;
    assert_rejected(s, &j, "subject_token is invalid");
    // A real `es` token with its payload iss rewritten to auth0 keeps es's kid: no key in
    // auth0's set, so it is rejected.
    let es = test_at(&app, "es", json!({"user":"alice"})).await;
    let mut parts: Vec<String> = es.split('.').map(str::to_owned).collect();
    let mut c = claims_of(&es);
    c["iss"] = json!("http://localhost:9000/auth0/");
    parts[1] = b64url(&serde_json::to_vec(&c).unwrap());
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &parts.join("."))]).await;
    assert_rejected(s, &j, "subject_token is invalid");
}

#[tokio::test]
async fn refresh_token_as_subject_token_is_invalid_request() {
    let app = app(&cfg());
    let rt = token_response_for(&app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &rt)]).await;
    assert_rejected(s, &j, "a refresh token cannot be exchanged");
}

#[tokio::test]
async fn revoked_subject_token_is_invalid_request() {
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
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &at)]).await;
    assert_rejected(s, &j, "revoked");
}

#[tokio::test]
async fn lenient_accepts_an_unverified_jwt_but_rejects_a_non_jwt() {
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
    let (s, j) = exchange(&app, "auth0", &[("subject_token", "opaque-value")]).await;
    assert_rejected(s, &j, "subject_token is not a JWT");
}

#[tokio::test]
async fn strict_rejects_a_foreign_jwt_and_a_client_without_the_grant_type() {
    let app = app(&cfg());
    let t = unsigned_jwt(
        &json!({"alg":"none"}),
        &json!({"iss":"https://idp.example.com/","sub":"ext-1"}),
    );
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &t)]).await;
    assert_rejected(s, &j, "is not a fauxidc Issuer");
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
    assert!(
        json(&b)["error_description"]
            .as_str()
            .unwrap()
            .contains("token-exchange"),
        "{b}"
    );
}

#[tokio::test]
async fn missing_subject_token_or_type_is_invalid_request() {
    let app = app(&cfg());
    let (s, j) = exchange(&app, "auth0", &[]).await;
    assert_rejected(s, &j, "subject_token is missing");
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
    assert_rejected(s, &json(&b), "subject_token_type is missing");
}

#[tokio::test]
async fn unsupported_token_types_are_invalid_request_and_jwt_is_accepted() {
    let app = app(&cfg());
    let at = access_token_for(&app, &[]).await;
    let (s, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &at),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:refresh_token",
            ),
        ],
    )
    .await;
    assert_rejected(s, &j, "unsupported subject_token_type");
    let (s, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &at),
            (
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:id_token",
            ),
        ],
    )
    .await;
    assert_rejected(s, &j, "unsupported requested_token_type");
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

/// Exchanges `subject` with `actor` as an access token actor on `auth0`.
async fn exchange_as(app: &Router, subject: &str, actor: &str) -> (StatusCode, Value) {
    exchange(
        app,
        "auth0",
        &[
            ("subject_token", subject),
            ("actor_token", actor),
            ("actor_token_type", AT_TYPE),
        ],
    )
    .await
}

#[tokio::test]
async fn actor_token_adds_act() {
    let app = app(&cfg());
    let subject = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let actor = test_at(&app, "es", json!({"sub":"svc-orders"})).await;
    let (s, j) = exchange_as(&app, &subject, &actor).await;
    assert_eq!(s, 200, "{j}");
    let c = at_of(&j);
    assert_eq!(c["act"], json!({"sub":"svc-orders"}));
    assert_eq!(c["sub"], claims_of(&subject)["sub"]);
}

#[tokio::test]
async fn prior_act_nests_inside_the_new_act() {
    let app = app(&cfg());
    let subject = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let a1 = test_at(&app, "auth0", json!({"sub":"svc-a"})).await;
    let a2 = test_at(&app, "auth0", json!({"sub":"svc-b"})).await;
    let (_, j1) = exchange_as(&app, &subject, &a1).await;
    let first = j1["access_token"].as_str().unwrap().to_owned();
    let (s, j2) = exchange_as(&app, &first, &a2).await;
    assert_eq!(s, 200, "{j2}");
    assert_eq!(
        at_of(&j2)["act"],
        json!({"sub":"svc-b","act":{"sub":"svc-a"}})
    );
}

#[tokio::test]
async fn subject_act_is_dropped_without_actor_token() {
    let app = app(&cfg());
    let subject = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let a1 = test_at(&app, "auth0", json!({"sub":"svc-a"})).await;
    let (_, j1) = exchange_as(&app, &subject, &a1).await;
    let first = j1["access_token"].as_str().unwrap().to_owned();
    assert!(claims_of(&first).get("act").is_some());
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &first)]).await;
    assert_eq!(s, 200, "{j}");
    assert!(at_of(&j).get("act").is_none());
}

#[tokio::test]
async fn unsigned_actor_token_is_invalid_request_in_strict_mode() {
    let app = app(&cfg());
    let subject = access_token_for(&app, &[]).await;
    let bad = unsigned_jwt(
        &json!({"alg":"none"}),
        &json!({"iss":"http://localhost:9000/auth0/","sub":"svc"}),
    );
    let (s, j) = exchange_as(&app, &subject, &bad).await;
    assert_rejected(s, &j, "actor_token is invalid");
}

#[tokio::test]
async fn actor_token_and_actor_token_type_must_come_together_and_be_supported() {
    let app = app(&cfg());
    let subject = access_token_for(&app, &[]).await;
    let actor = test_at(&app, "auth0", json!({"sub":"svc"})).await;
    let (s, j) = exchange(
        &app,
        "auth0",
        &[("subject_token", &subject), ("actor_token_type", AT_TYPE)],
    )
    .await;
    assert_rejected(s, &j, "actor_token_type was sent without actor_token");
    let (s, j) = exchange(
        &app,
        "auth0",
        &[("subject_token", &subject), ("actor_token", &actor)],
    )
    .await;
    assert_rejected(s, &j, "actor_token_type is missing");
    let (s, j) = exchange(
        &app,
        "auth0",
        &[
            ("subject_token", &subject),
            ("actor_token", &actor),
            (
                "actor_token_type",
                "urn:ietf:params:oauth:token-type:refresh_token",
            ),
        ],
    )
    .await;
    assert_rejected(s, &j, "unsupported actor_token_type");
}

#[tokio::test]
async fn lenient_accepts_an_unverified_actor_token() {
    let cfg = cfg().replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let app = app(&cfg);
    let subject = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let actor = unsigned_jwt(
        &json!({"alg":"none"}),
        &json!({"iss":"https://idp.example.com/","sub":"ext-svc"}),
    );
    let (s, j) = exchange_as(&app, &subject, &actor).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(at_of(&j)["act"], json!({"sub":"ext-svc"}));
}

#[tokio::test]
async fn public_client_can_exchange() {
    let cfg = format!(
        "{STRICT}\n[client.public_gw]\nclient_id = \"public-gw\"\ngrant_types = [\"{GRANT}\"]\n"
    );
    let app = app(&cfg);
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", GRANT),
                ("client_id", "public-gw"),
                ("subject_token", &at),
                ("subject_token_type", AT_TYPE),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(at_of(&json(&b))["sub"], "auth0|alice");
}

#[tokio::test]
async fn scope_is_not_checked_against_the_client_scopes() {
    let cfg = cfg().replace(
        "audience = \"https://api.example.com\"\n",
        "audience = \"https://api.example.com\"\nscopes = [\"api\"]\n",
    );
    let app = app(&cfg);
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let (s, j) = exchange(
        &app,
        "auth0",
        &[("subject_token", &at), ("scope", "orders:write")],
    )
    .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(at_of(&j)["scope"], "orders:write");
}

#[tokio::test]
async fn access_token_sent_as_id_token_type_is_rejected_in_strict_mode() {
    let as_id_token = |at: &str| -> Vec<(&str, String)> {
        vec![
            ("subject_token", at.to_owned()),
            (
                "subject_token_type",
                "urn:ietf:params:oauth:token-type:id_token".to_owned(),
            ),
        ]
    };
    let app = app(&cfg());
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    let form = as_id_token(&at);
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (s, j) = exchange(&app, "auth0", &form).await;
    assert_rejected(s, &j, "subject_token_type");
    let lenient = app_lenient();
    let at = test_at(&lenient, "auth0", json!({"user":"alice"})).await;
    let form = as_id_token(&at);
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (s, j) = exchange(&lenient, "auth0", &form).await;
    assert_eq!(s, 200, "{j}");
}

#[tokio::test]
async fn id_token_sent_as_access_token_type_is_rejected_in_strict_mode() {
    let app = app(&cfg());
    let idt = test_token(&app, "auth0", json!({"user":"alice"})).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, j) = exchange(&app, "auth0", &[("subject_token", &idt)]).await;
    assert_rejected(s, &j, "subject_token_type");
}

#[tokio::test]
async fn repeated_audience_is_invalid_request() {
    let app = app(&cfg());
    let at = test_at(&app, "auth0", json!({"user":"alice"})).await;
    for name in ["audience", "resource"] {
        // Not `exchange`: it replaces a repeated field.
        let (s, _, b) = send(
            &app,
            post_form(
                "/auth0/token",
                &[
                    ("grant_type", GRANT),
                    ("subject_token_type", AT_TYPE),
                    ("subject_token", &at),
                    (name, "a"),
                    (name, "b"),
                ],
                &[("authorization", &basic("gateway", "gw"))],
            ),
        )
        .await;
        let j = json(&b);
        assert_eq!(s, 400, "{j}");
        assert_eq!(j["error"], "invalid_request");
        assert_eq!(
            j["error_description"], "multiple audience values are not supported",
            "{name}"
        );
    }
    // Every grant type: client_credentials too.
    let (s, _, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &[
                ("grant_type", "client_credentials"),
                ("audience", "a"),
                ("audience", "b"),
            ],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 400);
    assert_eq!(
        json(&b)["error_description"],
        "multiple audience values are not supported"
    );
}

#[tokio::test]
async fn actor_must_match_may_act() {
    let app = app(&cfg());
    let subject = test_at(
        &app,
        "auth0",
        json!({"user":"alice","claims":{"may_act":{"sub":"bob"}}}),
    )
    .await;
    let alice = test_at(&app, "auth0", json!({"sub":"alice"})).await;
    let (s, j) = exchange_as(&app, &subject, &alice).await;
    assert_rejected(s, &j, "may_act");
    let bob = test_at(&app, "auth0", json!({"sub":"bob"})).await;
    let (s, j) = exchange_as(&app, &subject, &bob).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(at_of(&j)["act"]["sub"], "bob");
    assert!(at_of(&j).get("may_act").is_none());
}

/// `cfg()` with a Lenient `auth0` Issuer.
fn app_lenient() -> Router {
    app(&cfg().replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n"))
}

/// 400 `invalid_request` with an `error_description` that contains `fragment`.
#[track_caller]
fn assert_rejected(s: StatusCode, j: &Value, fragment: &str) {
    assert_eq!(
        (s.as_u16(), j["error"].as_str()),
        (400, Some("invalid_request")),
        "{j}"
    );
    let d = j["error_description"].as_str().unwrap_or_default();
    assert!(d.contains(fragment), "{fragment:?} not in {d:?}");
}
