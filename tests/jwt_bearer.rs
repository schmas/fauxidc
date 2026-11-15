//! The jwt-bearer grant (RFC 7523 section 2.1): a fauxidc JWT as `assertion` gives a new
//! access token of this Issuer (On-Behalf-Of).

mod common;
use common::*;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

fn cfg() -> String {
    format!(
        "{STRICT}
[issuer.lax]
issuer_url = \"http://localhost:9000/lax\"
lenient = true

[client.obo]
client_id = \"obo\"
client_secret = \"s\"
grant_types = [\"{GRANT}\"]
audience = \"https://api.example.com\"

[client.other]
client_id = \"other\"
client_secret = \"s\"
grant_types = [\"client_credentials\"]
"
    )
}

/// Posts a jwt-bearer request to `/{issuer}/token` as `client`. `extra` adds form fields.
async fn obo_as(
    app: &Router,
    issuer: &str,
    client: &str,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut form = vec![("grant_type", GRANT)];
    form.extend_from_slice(extra);
    let (s, _, b) = send(
        app,
        post_form(
            &format!("/{issuer}/token"),
            &form,
            &[("authorization", &basic(client, "s"))],
        ),
    )
    .await;
    (s, json(&b))
}

async fn obo(app: &Router, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    obo_as(app, "auth0", "obo", extra).await
}

/// The access token of alice from the Test API of `issuer`.
async fn alice_at(app: &Router, issuer: &str, extra: Value) -> String {
    let mut body = json!({ "user": "alice" });
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    test_token(app, issuer, body).await["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn assert_error(s: StatusCode, j: &Value, error: &str) {
    assert_eq!((s.as_u16(), j["error"].as_str()), (400, Some(error)), "{j}");
}

#[tokio::test]
async fn issues_an_access_token_for_the_assertion_subject() {
    let app = app(&cfg());
    let at = alice_at(&app, "auth0", json!({})).await;
    let (s, j) = obo(&app, &[("assertion", &at), ("scope", "api:read")]).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(j["token_type"], "Bearer");
    assert_eq!(j["scope"], "api:read");
    assert!(j["expires_in"].as_u64().unwrap() > 0);
    assert!(
        j.get("id_token").is_none() && j.get("refresh_token").is_none(),
        "{j}"
    );
    assert!(j.get("issued_token_type").is_none(), "{j}");
    let c = claims_of(j["access_token"].as_str().unwrap());
    assert_eq!(c["iss"], "http://localhost:9000/auth0/");
    assert_eq!(c["sub"], "auth0|alice");
    assert_eq!(c["email"], "alice@example.com");
    assert_eq!(c["aud"], "https://api.example.com");
    assert_eq!(c["client_id"], "obo");
    assert_eq!(c["scope"], "api:read");
    assert_ne!(c["jti"], claims_of(&at)["jti"]);
    assert!(c.get("act").is_none());
}

#[tokio::test]
async fn audience_parameter_wins_and_two_audiences_are_rejected() {
    let app = app(&cfg());
    let at = alice_at(&app, "auth0", json!({})).await;
    let (s, j) = obo(
        &app,
        &[
            ("assertion", &at),
            ("scope", "api"),
            ("audience", "https://other.example.test"),
        ],
    )
    .await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(
        claims_of(j["access_token"].as_str().unwrap())["aud"],
        "https://other.example.test"
    );
    let (s, j) = obo(
        &app,
        &[
            ("assertion", &at),
            ("scope", "api"),
            ("audience", "https://a.example.test"),
            ("audience", "https://b.example.test"),
        ],
    )
    .await;
    assert_error(s, &j, "invalid_request");
}

#[tokio::test]
async fn scope_falls_back_to_the_assertion_scope() {
    let app = app(&cfg());
    let at = alice_at(&app, "auth0", json!({ "scope": "openid email" })).await;
    let (s, j) = obo(&app, &[("assertion", &at)]).await;
    assert_eq!(s, 200, "{j}");
    assert_eq!(j["scope"], "openid email");
}

#[tokio::test]
async fn missing_scope_is_invalid_scope_in_both_modes() {
    let app = app(&cfg());
    // An id_token has no scope claim.
    let idt = test_token(&app, "auth0", json!({ "user": "alice" })).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, j) = obo(&app, &[("assertion", &idt)]).await;
    assert_error(s, &j, "invalid_scope");
    let idt = test_token(&app, "lax", json!({ "user": "alice" })).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, j) = obo_as(&app, "lax", "obo", &[("assertion", &idt)]).await;
    assert_error(s, &j, "invalid_scope");
}

#[tokio::test]
async fn missing_assertion_is_invalid_request() {
    let (s, j) = obo(&app(&cfg()), &[("scope", "api")]).await;
    assert_error(s, &j, "invalid_request");
}

#[tokio::test]
async fn client_without_the_grant_is_unauthorized_client() {
    let app = app(&cfg());
    let at = alice_at(&app, "auth0", json!({})).await;
    let (s, j) = obo_as(
        &app,
        "auth0",
        "other",
        &[("assertion", &at), ("scope", "api")],
    )
    .await;
    assert_error(s, &j, "unauthorized_client");
}

#[tokio::test]
async fn expired_assertion_is_invalid_grant() {
    let app = app(&cfg());
    let at = alice_at(&app, "auth0", json!({ "expires_in": -10 })).await;
    let (s, j) = obo(&app, &[("assertion", &at), ("scope", "api")]).await;
    assert_error(s, &j, "invalid_grant");
}

#[tokio::test]
async fn foreign_assertion_is_invalid_grant_in_strict_mode() {
    let app = app(&cfg());
    let stranger = SigningKey::generate().unwrap();
    let t = sign_with(
        &stranger,
        &json!({"iss":"http://localhost:9000/auth0/","sub":"mallory","exp":now()+60}),
    );
    let (s, j) = obo(&app, &[("assertion", &t), ("scope", "api")]).await;
    assert_error(s, &j, "invalid_grant");
    let (s, j) = obo(&app, &[("assertion", "opaque"), ("scope", "api")]).await;
    assert_error(s, &j, "invalid_grant");
}

#[tokio::test]
async fn refresh_token_as_assertion_is_invalid_grant() {
    let app = app(&cfg());
    let rt = token_response_for(&app, &[("scope", "openid offline_access")]).await["refresh_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (s, j) = obo(&app, &[("assertion", &rt), ("scope", "api")]).await;
    assert_error(s, &j, "invalid_grant");
}

#[tokio::test]
async fn lenient_mode_accepts_a_foreign_assertion_unverified() {
    let app = app(&cfg());
    let stranger = SigningKey::generate().unwrap();
    let t = sign_with(
        &stranger,
        &json!({"iss":"https://idp.example.test","sub":"mallory","exp":now()+60}),
    );
    let (s, j) = obo_as(&app, "lax", "obo", &[("assertion", &t), ("scope", "api")]).await;
    assert_eq!(s, 200, "{j}");
    let c = claims_of(j["access_token"].as_str().unwrap());
    assert_eq!(c["sub"], "mallory");
    assert_eq!(c["iss"], "http://localhost:9000/lax");
}

#[tokio::test]
async fn discovery_lists_the_grant() {
    let (_, _, b) = send(&app(&cfg()), get("/auth0/.well-known/openid-configuration")).await;
    let grants = json(&b)["grant_types_supported"].clone();
    assert!(
        grants.as_array().unwrap().contains(&json!(GRANT)),
        "{grants}"
    );
}
