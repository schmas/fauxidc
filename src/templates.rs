//! Login and error page templates, and the static files they use.
//!
//! The template context is a versioned contract. See `docs/templates.md`.

use std::path::Path as FsPath;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use minijinja::{AutoEscape, Environment};
use rust_embed::RustEmbed;
use serde::Serialize;

use crate::config::Config;
use crate::state::AppState;

/// The URL prefix of the static files.
pub const STATIC_BASE: &str = "/_mock/static";

/// Adds the framing headers of the HTML pages of an Issuer (login, error, `form_post`,
/// signed out and debugger) to `res`: `X-Frame-Options: SAMEORIGIN` and
/// `Content-Security-Policy: frame-ancestors 'self'`. Only a page of this origin (the
/// dashboard Debugger frame) can show them in a frame. A page of another origin cannot.
pub(crate) fn frame_same_origin(res: &mut Response) {
    let h = res.headers_mut();
    h.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("SAMEORIGIN"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'self'"),
    );
}

/// An HTML page of an Issuer with `status` and the framing headers of [`frame_same_origin`].
pub(crate) fn issuer_page(status: StatusCode, html: String) -> Response {
    let mut res = (status, Html(html)).into_response();
    frame_same_origin(&mut res);
    res
}

/// The current template context version.
pub const CONTEXT_VERSION: u32 = 2;

const LOGIN: &str = "login.html";
const ERROR: &str = "error.html";
const SIGNED_OUT: &str = "signed_out.html";
const DEBUGGER: &str = "debugger.html";
const FORM_POST: &str = "form_post.html";
const DASHBOARD: &str = "dashboard.html";

#[derive(RustEmbed)]
#[folder = "assets/templates"]
struct EmbeddedTemplates;

#[derive(RustEmbed)]
#[folder = "assets/static"]
struct EmbeddedStatic;

/// One entry of the user picker on the login page.
#[derive(Debug, Clone, Serialize)]
pub struct UserOption {
    pub id: String,
    /// The user label, or the id when the user has no label.
    pub label: String,
}

/// The context of `login.html`. Version 2.
#[derive(Debug, Clone, Serialize)]
pub struct LoginContext {
    pub context_version: u32,
    pub issuer_id: String,
    pub client_id: String,
    pub action: String,
    pub users: Vec<UserOption>,
    pub selected: Option<String>,
    pub params: Vec<(String, String)>,
    pub error: Option<String>,
    /// The form field that `error` is about: `user`, `username`, `custom_sub`,
    /// `custom_claims` or `override_claims`. None when no single field failed.
    pub error_field: Option<String>,
    pub custom_sub: String,
    pub custom_claims: String,
    pub override_claims: String,
    /// `true` to render the remember box checked.
    pub remember: bool,
    pub static_base: String,
    /// The text of the Custom user option: `custom_user.label`, else "Custom…".
    pub custom_label: String,
    /// `true` when the Issuer has `custom_user`: the page shows one `username` field
    /// instead of `custom_sub` and `custom_claims`.
    pub custom_username: bool,
    /// Prefilled text for the `username` field, for example after an error.
    pub username: String,
}

/// The context of `error.html`. Version 2.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorContext {
    pub context_version: u32,
    pub issuer_id: String,
    pub message: String,
    pub static_base: String,
}

/// The context of `signed_out.html`. Version 2.
#[derive(Debug, Clone, Serialize)]
pub struct SignedOutContext {
    pub context_version: u32,
    pub issuer_id: String,
    /// The Client of the logout request, when known.
    pub client_id: Option<String>,
    /// The label of the Auto-select User of the request, when the cookie names a configured User.
    pub signed_in_as: Option<String>,
    /// The debugger `?forget=1` URL of the Issuer, which clears the Auto-select cookie.
    pub change_href: Option<String>,
    pub static_base: String,
}

/// The context of `form_post.html`: the `/authorize` response for `response_mode=form_post`.
/// Version 2.
#[derive(Debug, Clone, Serialize)]
pub struct FormPostContext {
    pub context_version: u32,
    pub issuer_id: String,
    /// The validated `redirect_uri` of the request; the form posts here.
    pub redirect_uri: String,
    /// The response parameters, in order: `code` and `state`, or `error`, `error_description`
    /// and `state`. `state` is present only when the request sent it.
    pub fields: Vec<(String, String)>,
    pub static_base: String,
}

/// One decoded JWT on the debugger page.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedJwt {
    /// The header as pretty JSON.
    pub header: String,
    /// The payload as pretty JSON.
    pub payload: String,
    pub signature_valid: bool,
    /// `valid (kid …, ES256)`, or the reason the check failed.
    pub signature_note: String,
    /// `exp 1700000000: expires in 3599 s`, `exp …: expired 12 s ago`, or `no exp`.
    pub expiry_note: String,
    /// `iss matches this Issuer`, `iss <value> is not this Issuer (<issuer_url>)`, or `no iss`.
    /// The comparison is the exact string.
    pub issuer_note: String,
}

/// The context of `debugger.html`. Version 2.
#[derive(Debug, Clone, Serialize)]
pub struct DebuggerContext {
    pub context_version: u32,
    pub issuer_id: String,
    /// The debugger path of the Issuer; the decode form posts here.
    pub action: String,
    /// `action` + `/start`: starts the login flow with the built-in `debugger` Client.
    pub start_href: String,
    /// The pasted value, kept in the textarea.
    pub token: String,
    pub decoded: Option<DecodedJwt>,
    /// The tokens of a finished login flow, by name (`id_token`, `access_token`, `refresh_token`).
    pub flow: Vec<(String, DecodedJwt)>,
    /// The token response of a finished login flow, as pretty JSON.
    pub flow_raw: Option<String>,
    pub error: Option<String>,
    /// The label of the Auto-select User, when the cookie names a configured User.
    pub signed_in_as: Option<String>,
    /// `action` + `?forget=1`.
    pub change_href: String,
    pub static_base: String,
    /// `true` when the page shows inside the dashboard (`?embed=1`): no brand row and no
    /// footer. Then `action`, `start_href` and `change_href` carry `embed=1` too.
    pub embed: bool,
}

/// One Issuer on the dashboard. The hrefs are paths on this server.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardIssuer {
    pub id: String,
    /// The `iss` of the Issuer for this request.
    pub issuer_url: String,
    pub lenient: bool,
    pub discovery_href: String,
    pub jwks_href: String,
    pub debugger_href: String,
    /// The `/endsession` path. A browser visit signs out: it clears the Session and the
    /// Auto-select cookie.
    pub endsession_href: String,
}

/// The context of `dashboard.html`. Version 2.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardContext {
    pub context_version: u32,
    pub issuers: Vec<DashboardIssuer>,
    /// `false` when `server.request_log_size` is 0.
    pub request_log: bool,
    pub static_base: String,
}

/// The compiled templates: embedded defaults, `templates_dir` overrides and per-issuer login pages.
pub struct Templates {
    env: Environment<'static>,
}

impl Templates {
    /// Compiles all templates. A missing `login_template` file or a syntax error is an error.
    pub fn load(config: &Config) -> Result<Templates, String> {
        let mut env = Environment::new();
        env.set_auto_escape_callback(|_| AutoEscape::Html);
        env.add_filter("href", href);
        let dir = &config.server.templates_dir;
        for name in [LOGIN, ERROR, SIGNED_OUT, DEBUGGER, FORM_POST, DASHBOARD] {
            let source = if dir.is_empty() {
                None
            } else {
                let path = FsPath::new(dir).join(name);
                path.is_file().then(|| read_template(&path)).transpose()?
            };
            let source = match source {
                Some(source) => source,
                None => embedded_template(name)?,
            };
            env.add_template_owned(name, source)
                .map_err(|e| format!("{name}: {e:#}"))?;
        }
        for (id, issuer) in &config.issuer {
            if issuer.login_template.is_empty() {
                continue;
            }
            let source = read_template(FsPath::new(&issuer.login_template))?;
            env.add_template_owned(format!("login:{id}"), source)
                .map_err(|e| format!("issuer.{id}.login_template: {e:#}"))?;
        }
        Ok(Templates { env })
    }

    /// Renders the login page, using the issuer's own template when it has one.
    pub fn render_login(&self, issuer_id: &str, ctx: &LoginContext) -> Result<String, String> {
        let own = format!("login:{issuer_id}");
        let name = if self.env.get_template(&own).is_ok() {
            own.as_str()
        } else {
            LOGIN
        };
        self.render(name, ctx)
    }

    /// Renders the error page.
    pub fn render_error(&self, ctx: &ErrorContext) -> Result<String, String> {
        self.render(ERROR, ctx)
    }

    /// Renders the signed-out page of `/endsession`.
    pub fn render_signed_out(&self, ctx: &SignedOutContext) -> Result<String, String> {
        self.render(SIGNED_OUT, ctx)
    }

    /// Renders the debugger page.
    pub fn render_debugger(&self, ctx: &DebuggerContext) -> Result<String, String> {
        self.render(DEBUGGER, ctx)
    }

    /// Renders the auto-submit page of `response_mode=form_post`.
    pub fn render_form_post(&self, ctx: &FormPostContext) -> Result<String, String> {
        self.render(FORM_POST, ctx)
    }

    /// Renders the dashboard page.
    pub fn render_dashboard(&self, ctx: &DashboardContext) -> Result<String, String> {
        self.render(DASHBOARD, ctx)
    }

    fn render(&self, name: &str, ctx: &impl Serialize) -> Result<String, String> {
        self.env
            .get_template(name)
            .and_then(|t| t.render(minijinja::value::Serde(ctx)))
            .map_err(|e| format!("{name}: {e:#}"))
    }
}

/// The `href` filter: HTML-escapes `&`, `<`, `>`, `"` and `'` but keeps `/`, so a link
/// stays readable in the page source. The default escaping writes `/` as `&#x2f;`.
fn href(value: &str) -> minijinja::Value {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    minijinja::Value::from_safe_string(out)
}

fn read_template(path: &FsPath) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn embedded_template(name: &str) -> Result<String, String> {
    let file = EmbeddedTemplates::get(name).ok_or_else(|| format!("embedded {name} is missing"))?;
    String::from_utf8(file.data.into_owned()).map_err(|e| format!("embedded {name}: {e}"))
}

/// `GET /_mock/static/{*path}`: a file from `static_dir`, else the embedded file, else 404.
pub async fn static_file(Path(path): Path<String>, State(state): State<Arc<AppState>>) -> Response {
    // axum has already percent-decoded `path`.
    if path.contains('\\') || path.split('/').any(|s| matches!(s, "" | "." | "..")) {
        tracing::warn!("static path rejected: {path:?}");
        return StatusCode::NOT_FOUND.into_response();
    }
    let dir = &state.config.server.static_dir;
    let from_dir = if dir.is_empty() {
        None
    } else {
        std::fs::read(FsPath::new(dir).join(&path)).ok()
    };
    let body = match from_dir {
        Some(bytes) => bytes,
        None => match EmbeddedStatic::get(&path) {
            Some(file) => file.data.into_owned(),
            None => return StatusCode::NOT_FOUND.into_response(),
        },
    };
    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(content_type(&path)),
        )],
        body,
    )
        .into_response()
}

fn content_type(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("css") => "text/css",
        Some("js") => "text/javascript",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("html") => "text/html",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(extra: &str) -> Config {
        let toml =
            format!("[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\n{extra}");
        crate::config::load_str(&toml).expect("config loads").config
    }

    fn login_ctx() -> LoginContext {
        LoginContext {
            context_version: CONTEXT_VERSION,
            issuer_id: "auth0".into(),
            client_id: "example-app".into(),
            action: "/auth0/authorize".into(),
            users: vec![
                UserOption {
                    id: "alice".into(),
                    label: "Alice Admin".into(),
                },
                UserOption {
                    id: "bob".into(),
                    label: "bob".into(),
                },
            ],
            selected: Some("bob".into()),
            params: vec![("state".into(), "a\"b<c".into())],
            error: Some("bad <input>".into()),
            error_field: None,
            custom_sub: String::new(),
            custom_claims: String::new(),
            override_claims: String::new(),
            remember: false,
            static_base: STATIC_BASE.into(),
            custom_label: "Custom…".into(),
            custom_username: false,
            username: String::new(),
        }
    }

    #[test]
    fn login_page_renders_form_and_escapes() {
        let templates = Templates::load(&config("")).unwrap();
        let html = templates.render_login("auth0", &login_ctx()).unwrap();
        assert!(
            html.contains("<form method=\"post\" action=\"&#x2f;auth0&#x2f;authorize\" class=")
        );
        assert!(html.contains("name=\"state\" value=\"a&quot;b&lt;c\""));
        assert!(html.contains("<option value=\"bob\" selected>bob</option>"));
        assert!(html.contains("href=\"/_mock/static/halo.css\""));
        assert!(html.contains("<option value=\"alice\">Alice Admin</option>"));
        assert!(html.contains("value=\"__custom__\""));
        assert!(html.contains(
            "<span class=\"label label-pair\"><span>Client</span><span>example-app</span></span>"
        ));
        assert!(html.contains(
            "<span class=\"label label-pair\"><span>Issuer</span><span>auth0</span></span>"
        ));
        assert!(html.contains("bad &lt;input&gt;"));
        assert!(html.contains("name=\"remember\""));
    }

    #[test]
    fn issuer_login_template_is_preferred_and_escaped() {
        let path = std::env::temp_dir().join(format!("fauxidc-unit-{}.txt", std::process::id()));
        std::fs::write(&path, "own {{ client_id }} {{ error }}").unwrap();
        let cfg = config(&format!("login_template = \"{}\"\n", path.display()));
        let templates = Templates::load(&cfg).unwrap();
        let html = templates.render_login("auth0", &login_ctx()).unwrap();
        assert_eq!(html, "own example-app bad &lt;input&gt;");
        // An issuer without its own template uses the default.
        assert!(
            templates
                .render_login("other", &login_ctx())
                .unwrap()
                .contains("<form")
        );
        std::fs::remove_file(path).unwrap();
    }

    fn debugger_ctx() -> DebuggerContext {
        DebuggerContext {
            context_version: CONTEXT_VERSION,
            issuer_id: "auth0".into(),
            action: "/auth0/debugger".into(),
            start_href: "/auth0/debugger/start".into(),
            token: "a<b".into(),
            decoded: Some(DecodedJwt {
                header: "{\"alg\": \"RS256\"}".into(),
                payload: "{\"name\": \"<i>x</i>\"}".into(),
                signature_valid: true,
                signature_note: "valid (kid k1, RS256)".into(),
                expiry_note: "no exp".into(),
                issuer_note: "no iss".into(),
            }),
            flow: Vec::new(),
            flow_raw: None,
            error: None,
            signed_in_as: Some("Alice <Admin>".into()),
            change_href: "/auth0/debugger?forget=1&x=\"".into(),
            static_base: STATIC_BASE.into(),
            embed: false,
        }
    }

    #[test]
    fn debugger_page_renders_and_escapes() {
        let templates = Templates::load(&config("")).unwrap();
        let html = templates.render_debugger(&debugger_ctx()).unwrap();
        assert!(html.contains("name=\"token\""));
        assert!(html.contains(">a&lt;b</textarea>"));
        assert!(html.contains("href=\"/auth0/debugger/start\""));
        assert!(html.contains("&lt;i&gt;x&lt;&#x2f;i&gt;"));
        assert!(html.contains("valid (kid k1, RS256)"));
        assert!(html.contains("Signed in as Alice &lt;Admin&gt;"));
        assert!(html.contains("href=\"/auth0/debugger?forget=1&amp;x=&quot;\""));
    }

    #[test]
    fn debugger_template_can_be_overridden() {
        let dir = std::env::temp_dir().join(format!("fauxidc-unit-dbg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("debugger.html"), "own {{ issuer_id }}").unwrap();
        let cfg = config(&format!(
            "[server]\ntemplates_dir = \"{}\"\n",
            dir.display()
        ));
        let html = Templates::load(&cfg)
            .unwrap()
            .render_debugger(&debugger_ctx())
            .unwrap();
        assert_eq!(html, "own auth0");
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn form_post_ctx() -> FormPostContext {
        FormPostContext {
            context_version: CONTEXT_VERSION,
            issuer_id: "auth0".into(),
            redirect_uri: "http://localhost:3000/cb?a=1&b=\"".into(),
            fields: vec![
                ("code".into(), "c1".into()),
                ("state".into(), "\"><script>x</script>".into()),
            ],
            static_base: STATIC_BASE.into(),
        }
    }

    #[test]
    fn form_post_page_renders_and_escapes() {
        let templates = Templates::load(&config("")).unwrap();
        let html = templates.render_form_post(&form_post_ctx()).unwrap();
        assert!(html.contains(
            "<form method=\"post\" action=\"http://localhost:3000/cb?a=1&amp;b=&quot;\" class="
        ));
        assert!(html.contains("<input type=\"hidden\" name=\"code\" value=\"c1\">"));
        assert!(
            html.contains("name=\"state\" value=\"&quot;&gt;&lt;script&gt;x&lt;&#x2f;script&gt;\"")
        );
        assert!(!html.contains("<script>x"));
        assert!(html.contains("<button type=\"submit\""));
        assert!(html.contains("href=\"/_mock/static/halo.css\""));
    }

    #[test]
    fn form_post_template_can_be_overridden() {
        let dir = std::env::temp_dir().join(format!("fauxidc-unit-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("form_post.html"), "own {{ redirect_uri }}").unwrap();
        let cfg = config(&format!(
            "[server]\ntemplates_dir = \"{}\"\n",
            dir.display()
        ));
        let html = Templates::load(&cfg)
            .unwrap()
            .render_form_post(&form_post_ctx())
            .unwrap();
        assert!(html.starts_with("own http:"), "{html}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn error_page_renders() {
        let templates = Templates::load(&config("")).unwrap();
        let html = templates
            .render_error(&ErrorContext {
                context_version: CONTEXT_VERSION,
                issuer_id: "auth0".into(),
                message: "no <client>".into(),
                static_base: STATIC_BASE.into(),
            })
            .unwrap();
        assert!(html.contains("no &lt;client&gt;"));
    }
}
