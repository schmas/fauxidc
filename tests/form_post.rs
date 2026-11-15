//! `response_mode=form_post` at `/authorize` (OAuth 2.0 Form Post Response Mode).

mod common;
use common::*;

const CB: &str = "http://localhost:3000/api/auth/callback/auth0";

/// Decodes the HTML escapes that the template autoescape writes.
fn unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#x2f;", "/")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The decoded `value` of the hidden input `name` on a `form_post` page.
fn field(body: &str, name: &str) -> Option<String> {
    let marker = format!("type=\"hidden\" name=\"{name}\" value=\"");
    let start = body.find(&marker)? + marker.len();
    let end = body[start..].find('"')? + start;
    Some(unescape(&body[start..end]))
}

/// Asserts a `form_post` page: 200, HTML, no-store, no redirect, a POST form to `CB` with
/// a submit button and the auto-submit script.
fn assert_form_post_page(s: StatusCode, h: &HeaderMap, b: &str) {
    assert_eq!(s, 200, "{b}");
    assert!(h.get("location").is_none());
    assert_eq!(h["cache-control"], "no-store");
    assert!(
        h["content-type"].to_str().unwrap().starts_with("text/html"),
        "{:?}",
        h["content-type"]
    );
    assert!(
        b.contains(&format!("<form method=\"post\" action=\"{CB}\"")),
        "{b}"
    );
    assert!(b.contains("<button type=\"submit\""), "{b}");
    assert!(b.contains("<script>"), "{b}");
    assert!(
        !b.contains("https://"),
        "the page loads nothing from the network"
    );
}

#[tokio::test]
async fn login_with_form_post_returns_an_auto_post_form() {
    let app = app(STRICT);
    let (s, h, b) = send(
        &app,
        post_form(
            "/auth0/authorize",
            &login_fields(&[("response_mode", "form_post")]),
            &[],
        ),
    )
    .await;
    assert_form_post_page(s, &h, &b);
    assert_eq!(field(&b, "state").as_deref(), Some("st"));
    assert!(field(&b, "error").is_none());
    assert!(set_cookie(&h, "fauxidc_session_auth0").is_some());
    let code = field(&b, "code").expect("code field");
    let tokens = exchange_code_for(&app, &code).await;
    assert!(tokens["id_token"].is_string());
}

#[tokio::test]
async fn hostile_state_is_escaped() {
    let state = "\"><script>alert(1)</script>";
    let (s, h, b) = send(
        &app(STRICT),
        post_form(
            "/auth0/authorize",
            &login_fields(&[("response_mode", "form_post"), ("state", state)]),
            &[],
        ),
    )
    .await;
    assert_form_post_page(s, &h, &b);
    assert!(!b.contains(state), "{b}");
    assert!(b.contains("&quot;&gt;&lt;script&gt;"), "{b}");
    assert_eq!(field(&b, "state").as_deref(), Some(state));
}

#[tokio::test]
async fn login_page_keeps_response_mode() {
    let (s, _, b) = send(
        &app(STRICT),
        get(&authorize_url(&[("response_mode", "form_post")])),
    )
    .await;
    assert_eq!(s, 200);
    assert!(
        b.contains(r#"name="response_mode" value="form_post""#),
        "{b}"
    );
}

#[tokio::test]
async fn post_validation_error_is_delivered_by_form() {
    let app = app(STRICT);
    let (s, h, b) = send(
        &app,
        get(&authorize_url(&[
            ("response_mode", "form_post"),
            ("response_type", "token"),
        ])),
    )
    .await;
    assert_form_post_page(s, &h, &b);
    assert_eq!(
        field(&b, "error").as_deref(),
        Some("unsupported_response_type")
    );
    assert_eq!(
        field(&b, "error_description").as_deref(),
        Some("unsupported response_type: token")
    );
    assert_eq!(field(&b, "state").as_deref(), Some("st"));
    assert!(field(&b, "code").is_none());

    // A Session error after validation (`prompt=none`) uses the form too.
    let (s, h, b) = send(
        &app,
        get(&authorize_url(&[
            ("response_mode", "form_post"),
            ("prompt", "none"),
        ])),
    )
    .await;
    assert_form_post_page(s, &h, &b);
    assert_eq!(field(&b, "error").as_deref(), Some("login_required"));
}

#[tokio::test]
async fn error_before_redirect_uri_is_trusted_stays_a_page() {
    let app = app(STRICT);
    let (s, h, b) = send(
        &app,
        get(&authorize_url(&[
            ("response_mode", "form_post"),
            ("client_id", "nope"),
        ])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none() && !b.contains("<form"));
    assert!(b.contains("unknown client_id: nope"));
    let (s, _, b) = send(
        &app,
        get(&authorize_url(&[
            ("response_mode", "form_post"),
            ("redirect_uri", "http://localhost:3001/cb"),
        ])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(!b.contains("<form") && b.contains("redirect_uri not registered"));
}

/// A configured Client accepts only `http` and `https` redirect URIs, so a custom scheme
/// reaches the `form_post` check only in Lenient mode.
#[tokio::test]
async fn form_post_needs_an_http_redirect_uri() {
    let native = [
        ("client_id", "native"),
        ("redirect_uri", "com.example.app:/cb"),
    ];
    let mut form_post = native.to_vec();
    form_post.push(("response_mode", "form_post"));
    let lenient = app(LENIENT);
    let (s, h, b) = send(&lenient, get(&authorize_url(&form_post))).await;
    assert_eq!(s, 400, "{b}");
    assert!(h.get("location").is_none() && !b.contains("<form"));
    assert!(b.contains("invalid_request"), "{b}");
    // The query mode accepts the same redirect_uri in Lenient mode.
    assert_eq!(send(&lenient, get(&authorize_url(&native))).await.0, 200);

    // Strict mode: the redirect_uri is not registered, so the page comes first.
    let (s, _, b) = send(
        &app(STRICT),
        get(&authorize_url(&[
            ("redirect_uri", "com.example.app:/cb"),
            ("response_mode", "form_post"),
        ])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("redirect_uri not registered"), "{b}");
}

const LENIENT: &str =
    "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\nlenient = true\n[user.alice]\n";

#[tokio::test]
async fn unknown_response_mode_is_invalid_request_in_both_modes() {
    for toml in [STRICT, LENIENT] {
        let app = app(toml);
        for mode in ["fragment", "bogus", ""] {
            let (s, h, b) = send(&app, get(&authorize_url(&[("response_mode", mode)]))).await;
            if mode.is_empty() {
                // An empty value counts as absent.
                assert_eq!(s, 200, "{b}");
                continue;
            }
            assert_eq!(s, 302, "{mode}: {b}");
            let loc = location(&h);
            assert!(loc.starts_with(CB), "{loc}");
            assert_eq!(query_param(&loc, "error").unwrap(), "invalid_request");
            assert_eq!(
                query_param(&loc, "error_description").unwrap(),
                format!("unsupported response_mode: {mode}")
            );
            assert_eq!(query_param(&loc, "state").unwrap(), "st");
        }
    }
}

#[tokio::test]
async fn query_mode_and_absent_mode_are_unchanged() {
    let app = app(STRICT);
    for extra in [vec![], vec![("response_mode", "query")]] {
        let code = login_code(&app, &extra).await;
        exchange_code_for(&app, &code).await;
    }
    let (s, h, _) = send(
        &app,
        get(&authorize_url(&[
            ("response_mode", "query"),
            ("response_type", "token"),
        ])),
    )
    .await;
    assert_eq!(s, 302);
    assert_eq!(
        query_param(&location(&h), "error").unwrap(),
        "unsupported_response_type"
    );
}

#[tokio::test]
async fn discovery_lists_form_post() {
    let (_, _, b) = send(&app(AUTH0), get("/auth0/.well-known/openid-configuration")).await;
    assert_eq!(
        json(&b)["response_modes_supported"],
        json!(["query", "form_post"])
    );
}
