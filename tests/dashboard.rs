//! The admin dashboard at `/_mock/` (issue #31).

mod common;
use common::*;

const TWO_ISSUERS: &str = "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\n\
     [issuer.okta]\nissuer_url = \"http://localhost:9000/oauth2/default\"\nlenient = true\n\
     paths = { debugger = \"/v1/debug\", endsession = \"/v1/logout\" }\n";

fn request(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost:9000")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn dashboard_page_has_html_headers_and_no_framing() {
    let (s, h, b) = send(&app(TWO_ISSUERS), get("/_mock/")).await;
    assert_eq!(s, 200);
    assert!(h["content-type"].to_str().unwrap().starts_with("text/html"));
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["content-security-policy"], "frame-ancestors 'none'");
    assert!(b.contains("<title>Dashboard · fauxidc</title>"));
    assert!(b.contains("src=\"/_mock/static/dashboard.js\""));
    assert!(b.contains("href=\"/_mock/static/halo.css\""));
    assert!(b.contains("href=\"/_mock/static/dashboard.css\""));
    // The halo base comes first; the dashboard shell builds on it.
    assert!(b.find("halo.css") < b.find("dashboard.css"));
}

#[tokio::test]
async fn dashboard_lists_each_issuer_with_its_links() {
    let (_, _, b) = send(&app(TWO_ISSUERS), get("/_mock/")).await;
    for needle in [
        "data-issuer-row=\"auth0\"",
        "http:&#x2f;&#x2f;localhost:9000&#x2f;auth0&#x2f;",
        "href=\"/auth0/.well-known/openid-configuration\"",
        "href=\"/auth0/jwks\"",
        "href=\"/auth0/debugger\"",
        "href=\"/auth0/endsession\"",
        "data-issuer-row=\"okta\"",
        "href=\"/oauth2/default/.well-known/openid-configuration\"",
        "href=\"/oauth2/default/v1/debug\"",
        "href=\"/oauth2/default/v1/logout\"",
        ">Sign out</a>",
        ">Lenient</span>",
    ] {
        assert!(b.contains(needle), "{needle}");
    }
}

/// A smoke test per section: each Test API operation has its control on the page.
#[tokio::test]
async fn dashboard_has_a_control_for_each_operation() {
    let (_, _, b) = send(&app(TWO_ISSUERS), get("/_mock/")).await;
    for needle in [
        "id=\"issuers\"",
        "id=\"keys\"",
        "data-action=\"rotate\" data-issuer=\"auth0\"",
        "data-action=\"retire\" data-issuer=\"auth0\"",
        "data-jwks-href=\"/auth0/jwks\"",
        "data-action=\"reset-issuer\" data-issuer=\"okta\"",
        "id=\"reset-form\"",
        "id=\"editor\"",
        "id=\"users-list\"",
        "data-action=\"new\" data-kind=\"users\"",
        "id=\"clients-list\"",
        "data-action=\"new\" data-kind=\"clients\"",
        "id=\"token-form\"",
        "id=\"fail-form\"",
        "data-action=\"fail-clear\"",
        "id=\"log-form\"",
        "data-action=\"log-clear\"",
        "data-action=\"config-json\"",
        "data-action=\"config-toml\"",
        "data-action=\"reload\"",
    ] {
        assert!(b.contains(needle), "{needle}");
    }
    assert!(!b.contains("The Request log is off"));
}

#[tokio::test]
async fn dashboard_script_uses_the_test_api_routes() {
    let (s, h, js) = send(&app(AUTH0), get("/_mock/static/dashboard.js")).await;
    assert_eq!(s, 200);
    assert_eq!(h["content-type"], "text/javascript");
    for route in [
        "`/_mock/${kind}`",
        "`/_mock/${kind}/${encodeURIComponent(id)}`",
        "/token`",
        "/rotate-key",
        "/fail-next`",
        "/_mock/requests",
        "/_mock/state",
        "/_mock/reload",
        "/_mock/config",
        "?format=toml",
    ] {
        assert!(js.contains(route), "{route}");
    }
    // Values from the server never become HTML.
    assert!(!js.contains("innerHTML"));
}

#[tokio::test]
async fn dashboard_says_when_the_request_log_is_off() {
    let toml = format!("[server]\nrequest_log_size = 0\n{AUTH0}");
    let (_, _, b) = send(&app(&toml), get("/_mock/")).await;
    assert!(b.contains("The Request log is off"));
}

#[tokio::test]
async fn root_and_mock_redirect_to_the_dashboard() {
    let app = app(AUTH0);
    let (s, h, _) = send(&app, get("/")).await;
    assert_eq!(s, 303);
    assert_eq!(h["location"], "/_mock/");
    let (s, _, _) = send(&app, request("HEAD", "/")).await;
    assert_eq!(s, 303);
    let (s, h, _) = send(&app, get("/_mock")).await;
    assert_eq!(s, 308);
    assert_eq!(h["location"], "/_mock/");
    let (s, _, _) = send(&app, request("POST", "/")).await;
    assert_eq!(s, 404);
    let (s, _, _) = send(&app, get("/nothing/here")).await;
    assert_eq!(s, 404);
}

#[tokio::test]
async fn root_issuer_keeps_its_routes_and_root_still_redirects() {
    let app = app("[issuer.root]\nissuer_url = \"http://localhost:9000/\"\n");
    let (s, _, b) = send(&app, get("/.well-known/openid-configuration")).await;
    assert_eq!(s, 200, "{b}");
    let (s, h, _) = send(&app, get("/")).await;
    assert_eq!(s, 303);
    assert_eq!(h["location"], "/_mock/");
    let (_, _, b) = send(&app, get("/_mock/")).await;
    assert!(b.contains("href=\"/.well-known/openid-configuration\""));
    assert!(b.contains("href=\"/endsession\""));
}

#[tokio::test]
async fn other_mock_routes_stay_the_same() {
    let app = app(AUTH0);
    for uri in [
        "/_mock/health",
        "/_mock/static/fauxidc.css",
        "/_mock/users",
        "/_mock/clients",
        "/_mock/config",
        "/_mock/requests",
    ] {
        let (s, _, _) = send(&app, get(uri)).await;
        assert_eq!(s, 200, "{uri}");
    }
}

#[tokio::test]
async fn dashboard_requests_are_not_logged() {
    let app = app(AUTH0);
    send(&app, get("/_mock/")).await;
    let (_, _, b) = send(&app, get("/_mock/requests")).await;
    assert_eq!(b, "[]");
}

#[tokio::test]
async fn dashboard_template_can_be_overridden() {
    let dir = std::env::temp_dir().join(format!("fauxidc-dash-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("dashboard.html"),
        "own {% for i in issuers %}{{ i.id }} {{ i.endsession_href }}{% endfor %}",
    )
    .unwrap();
    let toml = format!("[server]\ntemplates_dir = \"{}\"\n{AUTH0}", dir.display());
    let (_, _, b) = send(&app(&toml), get("/_mock/")).await;
    std::fs::remove_dir_all(dir).unwrap();
    assert_eq!(b, "own auth0 &#x2f;auth0&#x2f;endsession");
}

#[tokio::test]
async fn signed_out_page_links_the_dashboard() {
    let (s, _, b) = send(&app(AUTH0), get("/auth0/endsession")).await;
    assert_eq!(s, 200);
    assert!(b.contains("href=\"/_mock/\""));
}

#[tokio::test]
async fn dashboard_stylesheet_has_both_themes_and_no_external_urls() {
    let (s, h, halo) = send(&app(AUTH0), get("/_mock/static/halo.css")).await;
    assert_eq!(s, 200);
    assert_eq!(h["content-type"], "text/css");
    assert!(halo.contains("@media (prefers-color-scheme: dark)"));
    assert!(halo.contains("--overlay:"));
    let (s, _, shell) = send(&app(AUTH0), get("/_mock/static/dashboard.css")).await;
    assert_eq!(s, 200);
    // One copy of the tokens: the dashboard shell only uses them.
    assert!(!shell.contains("--primary:"));
    for css in [&halo, &shell] {
        for bad in ["http://", "https://", "url(//", "@import"] {
            assert!(!css.contains(bad), "{bad}");
        }
    }
}

/// The sidebar has a Debugger item. Its view has an Issuer select and a frame for the
/// debugger page of the chosen Issuer (the page is framed, not copied).
#[tokio::test]
async fn dashboard_sidebar_has_the_debugger() {
    let (_, _, b) = send(&app(TWO_ISSUERS), get("/_mock/")).await;
    for needle in [
        "class=\"nav-item\" href=\"#debugger\" data-view=\"debugger\"",
        "<option value=\"debugger\">Debugger</option>",
        "<section id=\"debugger\" class=\"view\">",
        "<select id=\"debugger-issuer\" class=\"select\">",
        "<option value=\"auth0\" data-debugger-href=\"/auth0/debugger\">auth0</option>",
        "<option value=\"okta\" data-debugger-href=\"/oauth2/default/v1/debug\">okta</option>",
        "<iframe id=\"debugger-frame\" name=\"debugger-frame\"",
        ">Open in new tab</a>",
    ] {
        assert!(b.contains(needle), "{needle}");
    }
    // The frame gets its src from the script, with ?embed=1.
    assert!(!b.contains("?embed=1"));
    let (_, _, js) = send(&app(AUTH0), get("/_mock/static/dashboard.js")).await;
    assert!(js.contains("?embed=1"));
    assert!(js.contains("#debugger/${encodeURIComponent(id)}"));
}

/// The icon of a sidebar item comes after its label, as in the halo Sidebar Item.
#[tokio::test]
async fn dashboard_sidebar_item_has_label_then_icon() {
    let (_, _, b) = send(&app(TWO_ISSUERS), get("/_mock/")).await;
    assert!(b.contains(
        "data-view=\"issuers\"><span>Issuers</span><svg class=\"ic ic-lg\" aria-hidden=\"true\"><use href=\"#i-server\"/></svg></a>"
    ));
}
