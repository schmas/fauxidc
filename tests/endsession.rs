mod common;
use common::*;

use fauxidc::tokens::{IdTokenInput, sign_id_token};

static LOGOUT: LazyLock<String> = LazyLock::new(|| logout_config(STRICT));

fn logout_config(base: &str) -> String {
    base.replace(
        "sub_template = \"auth0|{user_id}\"\n",
        "sub_template = \"auth0|{user_id}\"\npaths = { endsession = \"/v2/logout\" }\nlogout_param_aliases = { returnTo = \"post_logout_redirect_uri\" }\n",
    )
    .replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\npost_logout_redirect_uris = [\"http://localhost:3000/\"]\n",
    )
}

fn clears_auto_select(h: &HeaderMap) {
    let cookie = h
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .find(|c| c.starts_with("fauxidc_user_auth0="))
        .unwrap();
    assert!(
        cookie.starts_with("fauxidc_user_auth0=;") && cookie.contains("Max-Age=0"),
        "{cookie}"
    );
    assert_eq!(h["cache-control"], "no-store");
}

async fn id_token(app: &Router) -> String {
    token_response_for(app, &[]).await["id_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn logout_url(pairs: &[(&str, &str)]) -> String {
    format!(
        "/auth0/v2/logout?{}",
        serde_urlencoded::to_string(pairs).unwrap()
    )
}

#[tokio::test]
async fn redirects_with_state_and_clears_auto_select() {
    let app = app(&LOGOUT);
    let (s, h, _) = send(
        &app,
        get("/auth0/v2/logout?client_id=example-app&returnTo=http%3A%2F%2Flocalhost%3A3000%2F&state=s1"),
    )
    .await;
    assert_eq!(s, 302);
    assert_eq!(location(&h), "http://localhost:3000/?state=s1");
    clears_auto_select(&h);
}

#[tokio::test]
async fn id_token_hint_identifies_client() {
    let app = app(&LOGOUT);
    let hint = id_token(&app).await;
    let (s, h, b) = send(
        &app,
        get(&logout_url(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", "http://localhost:3000/"),
        ])),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    assert_eq!(location(&h), "http://localhost:3000/");
}

#[tokio::test]
async fn expired_id_token_hint_is_accepted() {
    let cfg = LOGOUT.replace(
        "client_secret = \"local\"\n",
        "client_secret = \"local\"\nlifetimes = { id_token = 0 }\n",
    );
    let app = app(&cfg);
    let hint = id_token(&app).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (s, h, b) = send(
        &app,
        get(&logout_url(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", "http://localhost:3000/"),
        ])),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    assert_eq!(location(&h), "http://localhost:3000/");
}

#[tokio::test]
async fn unregistered_post_logout_redirect_shows_error_page() {
    let (s, h, b) = send(
        &app(&LOGOUT),
        get("/auth0/v2/logout?client_id=example-app&post_logout_redirect_uri=http%3A%2F%2Fevil.example.com%2F"),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none() && b.contains("post_logout_redirect_uri not registered"));
    assert!(h.get("set-cookie").is_none());
}

#[tokio::test]
async fn unregistered_redirect_with_valid_hint_shows_error_page() {
    let app = app(&LOGOUT);
    let hint = id_token(&app).await;
    let (s, h, b) = send(
        &app,
        get(&logout_url(&[
            ("id_token_hint", &hint),
            ("post_logout_redirect_uri", "http://evil.example.com/"),
        ])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none() && b.contains("post_logout_redirect_uri not registered"));
}

#[tokio::test]
async fn redirect_without_client_is_rejected_in_strict_but_followed_in_lenient() {
    let url = logout_url(&[("post_logout_redirect_uri", "http://localhost:3000/")]);
    let (s, h, b) = send(&app(&LOGOUT), get(&url)).await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none());
    assert!(
        b.contains("post_logout_redirect_uri needs client_id or id_token_hint"),
        "{b}"
    );
    let lenient = LOGOUT.replace("[issuer.auth0]\n", "[issuer.auth0]\nlenient = true\n");
    let (s, h, _) = send(&app(&lenient), get(&url)).await;
    assert_eq!(s, 302);
    assert_eq!(location(&h), "http://localhost:3000/");
}

#[tokio::test]
async fn unknown_client_is_rejected_in_strict() {
    let (s, h, b) = send(
        &app(&LOGOUT),
        get(&logout_url(&[
            ("client_id", "nope"),
            ("post_logout_redirect_uri", "http://localhost:3000/"),
        ])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(h.get("location").is_none() && b.contains("unknown client_id: nope"));
}

#[tokio::test]
async fn no_redirect_shows_signed_out_page() {
    let (s, h, b) = send(&app(&LOGOUT), get("/auth0/v2/logout?client_id=example-app")).await;
    assert_eq!(s, 200);
    assert!(b.contains("Signed out") && b.contains("auth0"), "{b}");
    assert!(b.contains("example-app"), "{b}");
    clears_auto_select(&h);
}

#[tokio::test]
async fn post_form_works() {
    let (s, h, b) = send(
        &app(&LOGOUT),
        post_form(
            "/auth0/v2/logout",
            &[
                ("client_id", "example-app"),
                ("post_logout_redirect_uri", "http://localhost:3000/"),
            ],
            &[],
        ),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    assert_eq!(location(&h), "http://localhost:3000/");
    clears_auto_select(&h);
}

#[tokio::test]
async fn bad_id_token_hint_is_error_page() {
    let other = SigningKey::generate().unwrap();
    let hint = sign_id_token(
        &other,
        IdTokenInput {
            issuer_url: "http://localhost:9000/auth0/",
            client_id: "example-app",
            claims: serde_json::Map::new(),
            auth_time: 1,
            nonce: None,
            lifetime: 60,
            sid: None,
        },
    )
    .unwrap();
    let (s, h, b) = send(&app(&LOGOUT), get(&logout_url(&[("id_token_hint", &hint)]))).await;
    assert_eq!(s, 400);
    assert!(b.contains("id_token_hint is invalid"), "{b}");
    assert!(h.get("set-cookie").is_none());
}

#[tokio::test]
async fn client_id_must_match_hint_in_strict() {
    let app = app(&LOGOUT);
    let hint = id_token(&app).await;
    let (s, _, b) = send(
        &app,
        get(&logout_url(&[
            ("id_token_hint", &hint),
            ("client_id", "spa"),
        ])),
    )
    .await;
    assert_eq!(s, 400);
    assert!(b.contains("client_id does not match id_token_hint"), "{b}");
}

#[tokio::test]
async fn standard_param_wins_over_alias() {
    let (s, h, b) = send(
        &app(&LOGOUT),
        get(&logout_url(&[
            ("client_id", "example-app"),
            ("returnTo", "http://evil.example.com/"),
            ("post_logout_redirect_uri", "http://localhost:3000/"),
        ])),
    )
    .await;
    assert_eq!(s, 302, "{b}");
    assert_eq!(location(&h), "http://localhost:3000/");
}

#[tokio::test]
async fn default_path_is_endsession() {
    let (s, _, b) = send(&app(STRICT), get("/auth0/endsession")).await;
    assert_eq!(s, 200);
    assert!(b.contains("Signed out"));
}

#[tokio::test]
async fn discovery_lists_end_session_endpoint() {
    let (_, _, b) = send(
        &app(&LOGOUT),
        get("/auth0/.well-known/openid-configuration"),
    )
    .await;
    assert_eq!(
        json(&b)["end_session_endpoint"],
        "http://localhost:9000/auth0/v2/logout"
    );
}
