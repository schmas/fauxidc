//! RP-Initiated Logout 1.0: `/endsession` with provider parameter aliases.

use std::collections::BTreeMap;

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::Value;

use crate::authorize::error_page;
use crate::clients::{find_client, redirect_uri_matches};
use crate::config::Claims;
use crate::cookies::{
    auto_select_clear, login_view_clear, read_cookie, session_clear, session_name,
};
use crate::debugger::change_href;
use crate::error::{OAuthError, append_query};
use crate::logging::{record_client, record_endpoint};
use crate::state::IssuerCtx;
use crate::templates::{CONTEXT_VERSION, STATIC_BASE, SignedOutContext, issuer_page};
use crate::tokens::verify_id_token_hint;

/// The logout request parameters after aliases are applied.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct LogoutParams {
    pub id_token_hint: Option<String>,
    pub logout_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
    pub ui_locales: Option<String>,
}

impl LogoutParams {
    fn slot(&mut self, name: &str) -> Option<&mut Option<String>> {
        match name {
            "id_token_hint" => Some(&mut self.id_token_hint),
            "logout_hint" => Some(&mut self.logout_hint),
            "client_id" => Some(&mut self.client_id),
            "post_logout_redirect_uri" => Some(&mut self.post_logout_redirect_uri),
            "state" => Some(&mut self.state),
            "ui_locales" => Some(&mut self.ui_locales),
            _ => None,
        }
    }
}

/// Maps alias names to standard names. A standard name that is also sent wins. Unknown names
/// are dropped. Empty values count as absent; for a repeated name the first value wins.
pub fn apply_aliases(
    raw: Vec<(String, String)>,
    aliases: &BTreeMap<String, String>,
) -> LogoutParams {
    let mut params = LogoutParams::default();
    let mut from_aliases = Vec::new();
    for (name, value) in raw {
        if value.is_empty() {
            continue;
        }
        match params.slot(&name) {
            Some(slot) => {
                if slot.is_none() {
                    *slot = Some(value);
                }
            }
            None => {
                if let Some(target) = aliases.get(&name) {
                    from_aliases.push((target.clone(), value));
                }
            }
        }
    }
    for (target, value) in from_aliases {
        if let Some(slot) = params.slot(&target)
            && slot.is_none()
        {
            *slot = Some(value);
        }
    }
    params
}

/// `GET {issuer}/endsession`.
pub async fn endsession_get(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Query(raw): Query<Vec<(String, String)>>,
) -> Response {
    endsession(&ctx, &headers, raw).await
}

/// `POST {issuer}/endsession` with a form body.
pub async fn endsession_post(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Form(raw): Form<Vec<(String, String)>>,
) -> Response {
    endsession(&ctx, &headers, raw).await
}

/// `true` if the `aud` claim is `client_id` or an array that holds it.
fn audience_contains(claims: &Claims, client_id: &str) -> bool {
    match claims.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        Some(Value::Array(items)) => items.iter().any(|a| a.as_str() == Some(client_id)),
        _ => false,
    }
}

/// The Client of the hint: `azp`, else `aud` (a string, or the first array item).
fn hint_client(claims: &Claims) -> Option<String> {
    claims
        .get("azp")
        .and_then(Value::as_str)
        .or_else(|| match claims.get("aud") {
            Some(Value::String(aud)) => Some(aud.as_str()),
            Some(Value::Array(items)) => items.first().and_then(Value::as_str),
            _ => None,
        })
        .map(str::to_owned)
}

async fn endsession(ctx: &IssuerCtx, request: &HeaderMap, raw: Vec<(String, String)>) -> Response {
    record_endpoint(&ctx.id, "endsession");
    let p = apply_aliases(raw, &ctx.issuer().logout_param_aliases);
    let reject = |message: String| error_page(ctx, StatusCode::BAD_REQUEST, message);

    let hint = match p.id_token_hint.as_deref() {
        None => None,
        Some(token) => {
            let keys = match ctx.keys().await {
                Ok(keys) => keys,
                Err(e) => return e.into_response(),
            };
            match verify_id_token_hint(&keys, &ctx.issuer_url(request), token) {
                Ok(claims) => Some(claims),
                Err(e) => {
                    tracing::info!(issuer = %ctx.id, "{e}");
                    if let Err(rule) = ctx.enforce(false, || "id_token_hint is invalid".to_owned())
                    {
                        return reject(rule);
                    }
                    None
                }
            }
        }
    };

    let client_id = match (p.client_id.as_deref(), hint.as_ref()) {
        (Some(id), Some(claims)) => {
            if let Err(rule) = ctx.enforce(audience_contains(claims, id), || {
                "client_id does not match id_token_hint".to_owned()
            }) {
                return reject(rule);
            }
            Some(id.to_owned())
        }
        (Some(id), None) => Some(id.to_owned()),
        (None, Some(claims)) => hint_client(claims),
        (None, None) => None,
    };
    if let Some(id) = client_id.as_deref() {
        record_client(id);
    }

    let mut response = if let Some(uri) = p.post_logout_redirect_uri.as_deref() {
        let checked = match client_id.as_deref() {
            None => ctx.enforce(false, || {
                "post_logout_redirect_uri needs client_id or id_token_hint".to_owned()
            }),
            Some(id) => match find_client(ctx, id) {
                None => ctx.enforce(false, || format!("unknown client_id: {id}")),
                Some(client) => ctx.enforce(
                    client
                        .config
                        .post_logout_redirect_uris
                        .iter()
                        .any(|r| redirect_uri_matches(r, uri)),
                    || format!("post_logout_redirect_uri not registered: {uri}"),
                ),
            },
        };
        if let Err(rule) = checked {
            return reject(rule);
        }
        let target = match p.state.as_deref() {
            Some(state) => append_query(uri, &[("state", state)]),
            None => uri.to_owned(),
        };
        let Ok(location) = HeaderValue::try_from(target) else {
            return reject(format!("invalid post_logout_redirect_uri: {uri}"));
        };
        (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
    } else {
        let context = SignedOutContext {
            context_version: CONTEXT_VERSION,
            issuer_id: ctx.id.clone(),
            client_id,
            // The same response clears the Auto-select cookie (plan Ruling 6).
            signed_in_as: None,
            change_href: Some(change_href(ctx)),
            static_base: STATIC_BASE.to_owned(),
        };
        match ctx.app.templates.render_signed_out(&context) {
            Ok(html) => issuer_page(StatusCode::OK, html),
            Err(e) => {
                return OAuthError::ServerError(format!("signed-out page: {e}")).into_response();
            }
        }
    };
    // The Session is deleted on the server too, so its cookie value never works again.
    if let Some(value) = read_cookie(request, &session_name(&ctx.id)) {
        ctx.app.store.sessions.remove(&ctx.id, &value);
    }
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let cookies = auto_select_clear(&ctx.id, &ctx.path)
        .into_iter()
        .chain(session_clear(&ctx.id, &ctx.path))
        .chain(login_view_clear(&ctx.id, &ctx.path));
    for cookie in cookies {
        headers.append(header::SET_COOKIE, cookie);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_map_and_standard_wins() {
        let aliases =
            BTreeMap::from([("returnTo".to_owned(), "post_logout_redirect_uri".to_owned())]);
        let p = apply_aliases(
            vec![
                ("returnTo".into(), "http://a/".into()),
                ("client_id".into(), "x".into()),
                ("junk".into(), "1".into()),
            ],
            &aliases,
        );
        assert_eq!(p.post_logout_redirect_uri.as_deref(), Some("http://a/"));
        assert_eq!(p.client_id.as_deref(), Some("x"));
        let p = apply_aliases(
            vec![
                ("returnTo".into(), "http://a/".into()),
                ("post_logout_redirect_uri".into(), "http://b/".into()),
            ],
            &aliases,
        );
        assert_eq!(p.post_logout_redirect_uri.as_deref(), Some("http://b/"));
    }

    #[test]
    fn empty_values_are_absent() {
        let p = apply_aliases(
            vec![
                ("state".into(), String::new()),
                ("state".into(), "s".into()),
            ],
            &BTreeMap::new(),
        );
        assert_eq!(p.state.as_deref(), Some("s"));
    }

    #[test]
    fn hint_client_prefers_azp_then_first_aud() {
        let c: Claims = serde_json::from_str(r#"{"azp":"a","aud":["b"]}"#).unwrap();
        assert_eq!(hint_client(&c).as_deref(), Some("a"));
        let c: Claims = serde_json::from_str(r#"{"aud":["b","c"]}"#).unwrap();
        assert_eq!(hint_client(&c).as_deref(), Some("b"));
        assert!(audience_contains(&c, "c") && !audience_contains(&c, "d"));
    }
}
