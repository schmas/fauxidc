//! The `/debugger` page: decodes a pasted JWT and checks it against this Issuer's key set,
//! and runs a code + PKCE login flow with the built-in `debugger` Client.

use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::clients::{BUILTIN_DEBUGGER, builtin_debugger, find_client};
use crate::config::Endpoint;
use crate::cookies::{
    auto_select_clear, auto_select_name, debugger_clear, debugger_name, debugger_set, read_cookie,
};
use crate::error::OAuthError;
use crate::keys::KeySet;
use crate::logging::record_endpoint;
use crate::state::{DebuggerFlow, IssuerCtx, now_secs};
use crate::templates::{CONTEXT_VERSION, DebuggerContext, DecodedJwt, STATIC_BASE};
use crate::token_endpoint::redeem_code;

/// The query of `GET {debugger}`.
#[derive(Debug, Default, Deserialize)]
pub struct PageQuery {
    /// `?forget=1` clears the Auto-select cookie and redirects to the debugger page.
    pub forget: Option<String>,
}

/// The form of `POST {debugger}`.
#[derive(Debug, Deserialize)]
pub struct DecodeForm {
    /// Missing: the page with status 400 and the error "paste a JWT".
    pub token: Option<String>,
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

/// The `issuer_note` of a payload: its `iss` compared with `issuer_url` as an exact string.
fn issuer_note(payload: &Value, issuer_url: &str) -> String {
    match payload.get("iss") {
        None => "no iss".to_owned(),
        Some(Value::String(iss)) if iss == issuer_url => "iss matches this Issuer".to_owned(),
        Some(Value::String(iss)) => format!("iss {iss} is not this Issuer ({issuer_url})"),
        Some(other) => format!("iss {other} is not this Issuer ({issuer_url})"),
    }
}

/// Decodes `token`, checks its signature with `keys` (by `kid`), its `exp` against `now` and
/// its `iss` against `issuer_url`. `Err` only for a value that is not a JWT.
pub fn decode_jwt(
    keys: &KeySet,
    issuer_url: &str,
    token: &str,
    now: u64,
) -> Result<DecodedJwt, String> {
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
        issuer_note: issuer_note(&payload, issuer_url),
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
        start_href: format!("{}/start", action.trim_end_matches('/')),
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

/// `POST {debugger}` with form field `token`: the page with the decoded token. Without
/// `token`: the page with status 400 and the error "paste a JWT".
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
    let Some(token) = f.token else {
        page.error = Some("paste a JWT".to_owned());
        return render(&ctx, StatusCode::BAD_REQUEST, &page);
    };
    match decode_jwt(&keys, &ctx.issuer().issuer_url, &token, now_secs()) {
        Ok(d) => page.decoded = Some(d),
        Err(e) => page.error = Some(e),
    }
    page.token = token;
    render(&ctx, StatusCode::OK, &page)
}

/// How long a debugger flow waits for its callback, in seconds.
pub const FLOW_TTL_SECS: u64 = 600;

const DEFAULT_SCOPE: &str = "openid profile email";
const UNKNOWN_STATE: &str = "unknown or expired state";

/// The query of `GET {debugger}/start`.
#[derive(Debug, Deserialize)]
pub struct StartQuery {
    /// Default `openid profile email`.
    pub scope: Option<String>,
}

/// The query of `GET {debugger}/callback`.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// 32 random bytes, base64url: 43 characters of `[A-Za-z0-9-_]`.
fn random_token() -> Result<String, OAuthError> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| OAuthError::ServerError(format!("random source failed: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// `GET {debugger}/start`: a new PKCE verifier and `state`, kept on the server for
/// [`FLOW_TTL_SECS`]; 302 to `/authorize` with the built-in `debugger` Client. The cookie
/// `fauxidc_debugger_<issuer id>` = `state` binds the flow to this browser (plan Ruling 33).
pub async fn start(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Query(q): Query<StartQuery>,
) -> Response {
    record_endpoint(&ctx.id, "debugger");
    let (verifier, state) = match (random_token(), random_token()) {
        (Ok(v), Ok(s)) => (v, s),
        (Err(e), _) | (_, Err(e)) => return e.into_response(),
    };
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = format!(
        "{}/callback",
        ctx.endpoint_url(&headers, Endpoint::Debugger)
            .trim_end_matches('/')
    );
    let scope = q
        .scope
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_SCOPE.to_owned());
    let query = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", BUILTIN_DEBUGGER),
        ("redirect_uri", redirect_uri.as_str()),
        ("scope", scope.as_str()),
        ("state", state.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ])
    .unwrap_or_default();
    let target = format!(
        "{}?{query}",
        ctx.endpoint_url(&headers, Endpoint::Authorize)
    );
    let Ok(location) = HeaderValue::try_from(target) else {
        return OAuthError::ServerError("invalid authorize URL".into()).into_response();
    };
    let Some(cookie) = debugger_set(&ctx.id, &debugger_cookie_path(&ctx), &state) else {
        return OAuthError::ServerError("invalid debugger cookie".into()).into_response();
    };
    ctx.app.store.insert_flow(
        state,
        DebuggerFlow {
            issuer_id: ctx.id.clone(),
            verifier,
            redirect_uri,
            expires_at: now_secs() + FLOW_TTL_SECS,
        },
    );
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, location),
            (header::SET_COOKIE, cookie),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
    )
        .into_response()
}

/// The `Path` of the debugger state cookie: the debugger path of the Issuer, so the cookie
/// reaches `{debugger}/callback`.
fn debugger_cookie_path(ctx: &IssuerCtx) -> String {
    ctx.endpoint_href(Endpoint::Debugger)
}

/// `GET {debugger}/callback`: needs the state cookie equal to `state`, then takes the flow by
/// `state` (no or another cookie, unknown, reused, expired or of another Issuer: 400 with
/// "unknown or expired state"), redeems the code in-process and shows the decoded tokens. An
/// `error` from `/authorize` is shown on the page. Every response clears the state cookie.
pub async fn callback(
    State(ctx): State<IssuerCtx>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    record_endpoint(&ctx.id, "debugger");
    let mut response = callback_page(&ctx, &headers, &q).await;
    if let Some(clear) = debugger_clear(&ctx.id, &debugger_cookie_path(&ctx)) {
        response.headers_mut().append(header::SET_COOKIE, clear);
    }
    response
}

async fn callback_page(ctx: &IssuerCtx, headers: &HeaderMap, q: &CallbackQuery) -> Response {
    let mut page = context(ctx, headers);
    let cookie = read_cookie(headers, &debugger_name(&ctx.id));
    let flow = q
        .state
        .as_deref()
        .filter(|s| cookie.as_deref() == Some(*s))
        .and_then(|s| ctx.app.store.take_flow(s))
        .filter(|f| f.issuer_id == ctx.id);
    if let Some(error) = q.error.as_deref() {
        page.error = Some(match q.error_description.as_deref() {
            Some(d) if !d.is_empty() => format!("{error}: {d}"),
            _ => error.to_owned(),
        });
        return render(ctx, StatusCode::OK, &page);
    }
    let Some(flow) = flow else {
        page.error = Some(UNKNOWN_STATE.to_owned());
        return render(ctx, StatusCode::BAD_REQUEST, &page);
    };
    let Some(code) = q.code.as_deref().filter(|c| !c.is_empty()) else {
        page.error = Some("missing code".to_owned());
        return render(ctx, StatusCode::BAD_REQUEST, &page);
    };
    // A configured Client named `debugger` replaces the built-in one.
    let client = find_client(ctx, BUILTIN_DEBUGGER).unwrap_or_else(|| builtin_debugger(ctx));
    let body = match redeem_code(
        ctx,
        &client,
        code,
        Some(&flow.redirect_uri),
        Some(&flow.verifier),
    )
    .await
    {
        Ok(body) => body,
        Err(e) => {
            page.error = Some(format!("token request failed: {e}"));
            return render(ctx, StatusCode::BAD_REQUEST, &page);
        }
    };
    let keys = match ctx.keys().await {
        Ok(keys) => keys,
        Err(e) => return e.into_response(),
    };
    let now = now_secs();
    for name in ["id_token", "access_token", "refresh_token"] {
        if let Some(token) = body.get(name).and_then(Value::as_str)
            && let Ok(d) = decode_jwt(&keys, &ctx.issuer().issuer_url, token, now)
        {
            page.flow.push((name.to_owned(), d));
        }
    }
    page.flow_raw = Some(pretty(&body));
    render(ctx, StatusCode::OK, &page)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningAlg;
    use crate::keys::SigningKey;
    use std::sync::Arc;

    const ISS: &str = "http://localhost:9000/a";

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
        let d = decode_jwt(&keys, ISS, &t, 1000).unwrap();
        assert!(d.signature_valid);
        assert_eq!(d.signature_note, format!("valid (kid {}, ES256)", key.kid));
        assert_eq!(d.expiry_note, "exp 1100: expires in 100 s");
        let d = decode_jwt(&keys, ISS, &t, 1112).unwrap();
        assert_eq!(d.expiry_note, "exp 1100: expired 12 s ago");
        assert!(d.payload.contains("\"sub\": \"a\""));
    }

    #[test]
    fn unknown_kid_and_no_exp() {
        let key = Arc::new(SigningKey::generate_for(SigningAlg::ES256).unwrap());
        let other = SigningKey::generate_for(SigningAlg::ES256).unwrap();
        let t = sign(&other, &serde_json::json!({"sub":"a"}));
        let d = decode_jwt(&KeySet::single(key), ISS, &t, 1000).unwrap();
        assert!(!d.signature_valid);
        assert_eq!(d.signature_note, format!("no key with kid {}", other.kid));
        assert_eq!(d.expiry_note, "no exp");
    }

    #[test]
    fn issuer_note_compares_the_exact_string() {
        let key = Arc::new(SigningKey::generate_for(SigningAlg::ES256).unwrap());
        let keys = KeySet::single(key.clone());
        let note = |claims: Value| {
            decode_jwt(&keys, ISS, &sign(&key, &claims), 0)
                .unwrap()
                .issuer_note
        };
        assert_eq!(
            note(serde_json::json!({"iss": ISS})),
            "iss matches this Issuer"
        );
        assert_eq!(
            note(serde_json::json!({"iss": "http://localhost:9000/a/"})),
            "iss http://localhost:9000/a/ is not this Issuer (http://localhost:9000/a)"
        );
        assert_eq!(note(serde_json::json!({"sub": "x"})), "no iss");
    }

    #[test]
    fn not_a_jwt() {
        let key = Arc::new(SigningKey::generate_for(SigningAlg::ES256).unwrap());
        let keys = KeySet::single(key);
        for t in ["x", "a.b", "a.b.c.d", "e30.!!!.x", "WzFd.e30.x"] {
            assert!(
                decode_jwt(&keys, ISS, t, 0)
                    .unwrap_err()
                    .starts_with("not a JWT"),
                "{t}"
            );
        }
    }
}
