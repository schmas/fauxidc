//! The `/debugger` page: decodes a pasted JWT and checks it against this Issuer's key set.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;

use crate::config::Endpoint;
use crate::cookies::{auto_select_clear, auto_select_name, read_cookie};
use crate::error::OAuthError;
use crate::keys::KeySet;
use crate::logging::record_endpoint;
use crate::state::{IssuerCtx, now_secs};
use crate::templates::{CONTEXT_VERSION, DebuggerContext, DecodedJwt, STATIC_BASE};

/// The query of `GET {debugger}`.
#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    /// `?forget=1` clears the Auto-select cookie and redirects to the debugger page.
    pub forget: Option<String>,
}

/// The form of `POST {debugger}`.
#[derive(Debug, Deserialize)]
pub struct DecodeForm {
    pub token: String,
}

/// Decodes one base64url JWT segment as a JSON object.
fn segment(part: &str, name: &str) -> Result<Value, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part.trim_end_matches('='))
        .map_err(|_| format!("not a JWT: the {name} is not base64url"))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| format!("not a JWT: the {name} is not JSON"))?;
    if !value.is_object() {
        return Err(format!("not a JWT: the {name} is not a JSON object"));
    }
    Ok(value)
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
}

/// Decodes `token` and checks its signature with `keys` (by `kid`) and its `exp` against
/// `now`. `Err` only for a value that is not a JWT.
pub fn decode_jwt(keys: &KeySet, token: &str, now: u64) -> Result<DecodedJwt, String> {
    let token = token.trim();
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, _] = parts.as_slice() else {
        return Err("not a JWT: expected three parts separated by dots".to_owned());
    };
    let header = segment(h, "header")?;
    let payload = segment(p, "payload")?;
    let verified = keys.verify(token, |v| {
        v.validate_exp = false;
        v.validate_aud = false;
        v.required_spec_claims.clear();
    });
    let (signature_valid, signature_note) = match verified {
        Ok((h, _)) => {
            let kid = h.kid.unwrap_or_else(|| keys.active.kid.clone());
            (true, format!("valid (kid {kid}, {:?})", h.alg))
        }
        Err(e) if e == "unknown kid" => {
            let kid = header.get("kid").and_then(Value::as_str).unwrap_or("");
            (false, format!("no key with kid {kid}"))
        }
        Err(e) => (false, e),
    };
    let expiry_note = match payload.get("exp") {
        None => "no exp".to_owned(),
        Some(exp) => match exp.as_u64() {
            Some(exp) if exp > now => format!("exp {exp}: expires in {} s", exp - now),
            Some(exp) => format!("exp {exp}: expired {} s ago", now - exp),
            None => format!("exp {exp}: not a non-negative integer"),
        },
    };
    Ok(DecodedJwt {
        header: pretty(&header),
        payload: pretty(&payload),
        signature_valid,
        signature_note,
        expiry_note,
    })
}

/// The label of the Auto-select User of the request, when the cookie names a configured User.
pub(crate) fn signed_in_as(ctx: &IssuerCtx, headers: &HeaderMap) -> Option<String> {
    let id = read_cookie(headers, &auto_select_name(&ctx.id))?;
    let user = ctx.app.config.user.get(&id)?;
    Some(if user.label.is_empty() {
        id
    } else {
        user.label.clone()
    })
}

/// The debugger `?forget=1` URL of the Issuer.
pub(crate) fn change_href(ctx: &IssuerCtx) -> String {
    format!("{}?forget=1", ctx.endpoint_href(Endpoint::Debugger))
}

/// An empty page context for this request.
pub(crate) fn context(ctx: &IssuerCtx, headers: &HeaderMap) -> DebuggerContext {
    let action = ctx.endpoint_href(Endpoint::Debugger);
    DebuggerContext {
        context_version: CONTEXT_VERSION,
        issuer_id: ctx.id.clone(),
        start_href: format!("{action}/start"),
        action,
        token: String::new(),
        decoded: None,
        flow: Vec::new(),
        flow_raw: None,
        error: None,
        signed_in_as: signed_in_as(ctx, headers),
        change_href: change_href(ctx),
        static_base: STATIC_BASE.to_owned(),
    }
}

/// Renders the page with `status`.
pub(crate) fn render(ctx: &IssuerCtx, status: StatusCode, page: &DebuggerContext) -> Response {
    match ctx.app.templates.render_debugger(page) {
        Ok(html) => (
            status,
            [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
            Html(html),
        )
            .into_response(),
        Err(e) => OAuthError::ServerError(format!("debugger page: {e}")).into_response(),
    }
}

/// `GET {debugger}`: the form. `?forget=1` clears the Auto-select cookie and answers 303 to
/// the debugger page.
pub async fn page(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Query(q): Query<PageQuery>,
) -> Response {
    record_endpoint(&ctx.id, "debugger");
    if q.forget.is_some() {
        let mut res = StatusCode::SEE_OTHER.into_response();
        let h = res.headers_mut();
        if let Ok(location) = HeaderValue::try_from(ctx.endpoint_href(Endpoint::Debugger)) {
            h.insert(header::LOCATION, location);
        }
        if let Some(cookie) = auto_select_clear(&ctx.id, &ctx.path) {
            h.insert(header::SET_COOKIE, cookie);
        }
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return res;
    }
    render(&ctx, StatusCode::OK, &context(&ctx, &headers))
}

/// `POST {debugger}` with form field `token`: the page with the decoded token.
pub async fn decode(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Form(f): Form<DecodeForm>,
) -> Response {
    record_endpoint(&ctx.id, "debugger");
    let keys = match ctx.keys().await {
        Ok(keys) => keys,
        Err(e) => return e.into_response(),
    };
    let mut page = context(&ctx, &headers);
    match decode_jwt(&keys, &f.token, now_secs()) {
        Ok(d) => page.decoded = Some(d),
        Err(e) => page.error = Some(e),
    }
    page.token = f.token;
    render(&ctx, StatusCode::OK, &page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningAlg;
    use crate::keys::SigningKey;
    use std::sync::Arc;

    fn sign(key: &SigningKey, claims: &Value) -> String {
        let mut header = jsonwebtoken::Header::new(key.alg.jwt());
        header.kid = Some(key.kid.clone());
        jsonwebtoken::encode(&header, claims, &key.encoding).unwrap()
    }

    #[test]
    fn valid_token_and_expiry() {
        let key = Arc::new(SigningKey::generate_for(SigningAlg::ES256).unwrap());
        let keys = KeySet::single(key.clone());
        let t = sign(&key, &serde_json::json!({"sub":"a","exp":1100}));
        let d = decode_jwt(&keys, &t, 1000).unwrap();
        assert!(d.signature_valid);
        assert_eq!(d.signature_note, format!("valid (kid {}, ES256)", key.kid));
        assert_eq!(d.expiry_note, "exp 1100: expires in 100 s");
        let d = decode_jwt(&keys, &t, 1112).unwrap();
        assert_eq!(d.expiry_note, "exp 1100: expired 12 s ago");
        assert!(d.payload.contains("\"sub\": \"a\""));
    }

    #[test]
    fn unknown_kid_and_no_exp() {
        let key = Arc::new(SigningKey::generate_for(SigningAlg::ES256).unwrap());
        let other = SigningKey::generate_for(SigningAlg::ES256).unwrap();
        let t = sign(&other, &serde_json::json!({"sub":"a"}));
        let d = decode_jwt(&KeySet::single(key), &t, 1000).unwrap();
        assert!(!d.signature_valid);
        assert_eq!(d.signature_note, format!("no key with kid {}", other.kid));
        assert_eq!(d.expiry_note, "no exp");
    }

    #[test]
    fn not_a_jwt() {
        let key = Arc::new(SigningKey::generate_for(SigningAlg::ES256).unwrap());
        let keys = KeySet::single(key);
        for t in ["x", "a.b", "a.b.c.d", "e30.!!!.x", "WzFd.e30.x"] {
            assert!(
                decode_jwt(&keys, t, 0)
                    .unwrap_err()
                    .starts_with("not a JWT"),
                "{t}"
            );
        }
    }
}
