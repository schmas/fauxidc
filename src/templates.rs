//! Login and error page templates, and the static files they use.
//!
//! The template context is a versioned contract. See `docs/templates.md`.

use std::path::Path as FsPath;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use minijinja::{AutoEscape, Environment};
use rust_embed::RustEmbed;
use serde::Serialize;

use crate::config::Config;
use crate::state::AppState;

/// The URL prefix of the static files.
pub const STATIC_BASE: &str = "/_mock/static";

/// The current template context version.
pub const CONTEXT_VERSION: u32 = 1;

const LOGIN: &str = "login.html";
const ERROR: &str = "error.html";
const SIGNED_OUT: &str = "signed_out.html";

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

/// The context of `login.html`. Version 1.
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
    pub custom_sub: String,
    pub custom_claims: String,
    pub override_claims: String,
    /// `true` to render the remember box checked.
    pub remember: bool,
    pub static_base: String,
}

/// The context of `error.html`. Version 1.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorContext {
    pub context_version: u32,
    pub issuer_id: String,
    pub message: String,
    pub static_base: String,
}

/// The context of `signed_out.html`. Version 1.
#[derive(Debug, Clone, Serialize)]
pub struct SignedOutContext {
    pub context_version: u32,
    pub issuer_id: String,
    /// The Client of the logout request, when known.
    pub client_id: Option<String>,
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
        let dir = &config.server.templates_dir;
        for name in [LOGIN, ERROR, SIGNED_OUT] {
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

    fn render(&self, name: &str, ctx: &impl Serialize) -> Result<String, String> {
        self.env
            .get_template(name)
            .and_then(|t| t.render(minijinja::value::Serde(ctx)))
            .map_err(|e| format!("{name}: {e:#}"))
    }
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
            custom_sub: String::new(),
            custom_claims: String::new(),
            override_claims: String::new(),
            remember: false,
            static_base: STATIC_BASE.into(),
        }
    }

    #[test]
    fn login_page_renders_form_and_escapes() {
        let templates = Templates::load(&config("")).unwrap();
        let html = templates.render_login("auth0", &login_ctx()).unwrap();
        assert!(html.contains("<form method=\"post\" action=\"&#x2f;auth0&#x2f;authorize\">"));
        assert!(html.contains("name=\"state\" value=\"a&quot;b&lt;c\""));
        assert!(html.contains("<option value=\"bob\" selected>bob</option>"));
        assert!(html.contains("<option value=\"alice\">Alice Admin</option>"));
        assert!(html.contains("value=\"__custom__\""));
        assert!(html.contains("Client: example-app · Issuer: auth0"));
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
