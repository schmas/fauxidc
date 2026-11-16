//! The admin dashboard at `/_mock/`: one HTML page for every Test API operation.
//!
//! The page lists the Issuers. A small script (`/_mock/static/dashboard.js`) does the rest
//! with the JSON routes of the Test API, so the page and the API stay the same.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{Html, IntoResponse, Redirect, Response},
};

use crate::config::Endpoint;
use crate::error::OAuthError;
use crate::issuer::{effective_issuer, issuer_path};
use crate::state::{AppState, IssuerCtx};
use crate::templates::{CONTEXT_VERSION, DashboardContext, DashboardIssuer, STATIC_BASE};

/// The path of the dashboard.
pub const DASHBOARD_PATH: &str = "/_mock/";

/// The links of one Issuer, relative to this server.
fn issuer_links(state: &Arc<AppState>, id: &str, headers: &HeaderMap) -> Option<DashboardIssuer> {
    let issuer = state.config.issuer.get(id)?;
    let path = issuer_path(&issuer.issuer_url).ok()?;
    let ctx = IssuerCtx {
        app: state.clone(),
        id: id.to_owned(),
        path: path.clone(),
    };
    Some(DashboardIssuer {
        id: id.to_owned(),
        issuer_url: effective_issuer(&state.config.server, issuer, headers),
        lenient: issuer.lenient,
        discovery_href: format!(
            "{}/.well-known/openid-configuration",
            path.trim_end_matches('/')
        ),
        jwks_href: ctx.endpoint_href(Endpoint::Jwks),
        debugger_href: ctx.endpoint_href(Endpoint::Debugger),
        endsession_href: ctx.endpoint_href(Endpoint::Endsession),
    })
}

/// The page context for this request.
pub fn context(state: &Arc<AppState>, headers: &HeaderMap) -> DashboardContext {
    DashboardContext {
        context_version: CONTEXT_VERSION,
        issuers: state
            .config
            .issuer
            .keys()
            .filter_map(|id| issuer_links(state, id, headers))
            .collect(),
        request_log: state.request_log.enabled(),
        static_base: STATIC_BASE.to_owned(),
    }
}

/// `GET /_mock/`: the dashboard page. `Cache-Control: no-store`; other sites cannot frame it
/// (`X-Frame-Options: DENY` and `frame-ancestors 'none'`), so a click on a framed page cannot
/// change the mock.
pub async fn page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match state.templates.render_dashboard(&context(&state, &headers)) {
        Ok(html) => (
            [
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                (header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")),
                (
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("frame-ancestors 'none'"),
                ),
            ],
            Html(html),
        )
            .into_response(),
        Err(e) => OAuthError::ServerError(format!("dashboard page: {e}")).into_response(),
    }
}

/// `GET /_mock`: 308 to the dashboard.
pub async fn to_dashboard() -> Redirect {
    Redirect::permanent(DASHBOARD_PATH)
}

/// The router fallback: `GET /` and `HEAD /` redirect (303) to the dashboard, every other
/// request gets 404. An Issuer route at `/` wins over the fallback.
pub async fn fallback(method: Method, uri: Uri) -> Response {
    if uri.path() == "/" && (method == Method::GET || method == Method::HEAD) {
        return Redirect::to(DASHBOARD_PATH).into_response();
    }
    StatusCode::NOT_FOUND.into_response()
}
