mod common;
use common::*;

const CC: &str = r#"[issuer.auth0]
issuer_url = "http://localhost:9000/auth0/"

[client.backend]
client_secret = "s"
grant_types = ["client_credentials"]
scopes = ["read:all", "write:all"]
audience = "https://api.example.com"
access_claims = { tier = "gold", aud = "x", sub = "y" }

[client.spa]
redirect_uris = ["http://localhost:5173/cb"]
grant_types = ["client_credentials"]
"#;

/// `POST /auth0/token` with `grant_type=client_credentials`, `form` and an optional
/// `Authorization` header.
fn cc(form: &[(&str, &str)], auth: Option<&str>) -> Request<Body> {
    let mut f = vec![("grant_type", "client_credentials")];
    f.extend_from_slice(form);
    match auth {
        Some(a) => post_form("/auth0/token", &f, &[("authorization", a)]),
        None => post_form("/auth0/token", &f, &[]),
    }
}

async fn ok_body(app: &Router, req: Request<Body>) -> Value {
    let (s, _, b) = send(app, req).await;
    assert_eq!(s, 200, "{b}");
    json(&b)
}

#[tokio::test]
async fn issues_access_token_only() {
    let (s, h, b) = send(
        &app(CC),
        cc(&[("scope", "read:all")], Some(&basic("backend", "s"))),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["pragma"], "no-cache");
    let j = json(&b);
    assert!(j.get("id_token").is_none() && j.get("refresh_token").is_none());
    assert_eq!(j["scope"], "read:all");
    assert_eq!(j["token_type"], "Bearer");
    assert_eq!(j["expires_in"], 3600);
    let at = claims_of(j["access_token"].as_str().unwrap());
    assert_eq!(
        header_of(j["access_token"].as_str().unwrap())["typ"],
        "at+jwt"
    );
    assert_eq!(
        (at["sub"].as_str(), at["client_id"].as_str()),
        (Some("backend"), Some("backend"))
    );
    assert_eq!(at["aud"], "https://api.example.com");
    assert_eq!(at["tier"], "gold");
    assert_eq!(at["scope"], "read:all");
    assert!(at.get("auth_time").is_none());
}

#[tokio::test]
async fn client_secret_post_works() {
    let j = ok_body(
        &app(CC),
        cc(&[("client_id", "backend"), ("client_secret", "s")], None),
    )
    .await;
    assert!(j["access_token"].is_string());
}

#[tokio::test]
async fn wrong_secret_is_invalid_client() {
    let (s, _, b) = send(&app(CC), cc(&[], Some(&basic("backend", "nope")))).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (401, Some("invalid_client"))
    );
}

#[tokio::test]
async fn unknown_scope_is_invalid_scope_in_strict_only() {
    let (s, _, b) = send(
        &app(CC),
        cc(&[("scope", "read:all admin")], Some(&basic("backend", "s"))),
    )
    .await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("invalid_scope"))
    );
    let lenient = CC.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let j = ok_body(
        &app(&lenient),
        cc(&[("scope", "admin")], Some(&basic("backend", "s"))),
    )
    .await;
    assert_eq!(j["scope"], "admin");
}

#[tokio::test]
async fn public_client_is_unauthorized_client() {
    let (s, _, b) = send(&app(CC), cc(&[("client_id", "spa")], None)).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
}

#[tokio::test]
async fn client_without_grant_is_unauthorized_client() {
    let (s, _, b) = send(&app(STRICT), cc(&[], Some(&basic("example-app", "local")))).await;
    assert_eq!(
        (s.as_u16(), json(&b)["error"].as_str()),
        (400, Some("unauthorized_client"))
    );
}

#[tokio::test]
async fn audience_param_wins() {
    let j = ok_body(
        &app(CC),
        cc(
            &[
                ("audience", "https://other.example.com"),
                ("resource", "https://third.example.com"),
            ],
            Some(&basic("backend", "s")),
        ),
    )
    .await;
    assert_eq!(
        claims_of(j["access_token"].as_str().unwrap())["aud"],
        "https://other.example.com"
    );
}

#[tokio::test]
async fn resource_param_is_used_without_audience() {
    let j = ok_body(
        &app(CC),
        cc(
            &[("resource", "https://third.example.com")],
            Some(&basic("backend", "s")),
        ),
    )
    .await;
    assert_eq!(
        claims_of(j["access_token"].as_str().unwrap())["aud"],
        "https://third.example.com"
    );
}

#[tokio::test]
async fn audience_falls_back_to_client_id() {
    let cfg = CC.replace("audience = \"https://api.example.com\"\n", "");
    let j = ok_body(&app(&cfg), cc(&[], Some(&basic("backend", "s")))).await;
    assert_eq!(
        claims_of(j["access_token"].as_str().unwrap())["aud"],
        "backend"
    );
}

#[tokio::test]
async fn no_scope_means_no_scope_field() {
    let j = ok_body(&app(CC), cc(&[], Some(&basic("backend", "s")))).await;
    assert!(j.get("scope").is_none());
    assert!(
        claims_of(j["access_token"].as_str().unwrap())
            .get("scope")
            .is_none()
    );
}

#[tokio::test]
async fn issuer_default_claims_are_not_applied() {
    let cfg = CC.replace(
        "issuer_url = \"http://localhost:9000/auth0/\"\n",
        "issuer_url = \"http://localhost:9000/auth0/\"\ndefault_claims = { tenant = \"t1\" }\n",
    );
    let j = ok_body(&app(&cfg), cc(&[], Some(&basic("backend", "s")))).await;
    assert!(
        claims_of(j["access_token"].as_str().unwrap())
            .get("tenant")
            .is_none()
    );
}
