//! The RFC 8693 token exchange grant.
//!
//! A subject token that is a JWT from any fauxidc Issuer is verified (signature, `alg`, `exp`,
//! revocation). In Strict mode every other token is rejected; in Lenient mode a JWT that fails
//! verification is used unverified. The result is an RFC 9068 access token of this Issuer.

use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

use crate::client_auth::{ClientAuth, authenticate_client};
use crate::config::{Claims, Endpoint};
use crate::error::OAuthError;
use crate::refresh::REFRESH_TOKEN_TYP;
use crate::state::{AppState, IssuerCtx};
use crate::token_endpoint::{TokenForm, require_grant};
use crate::tokens::{AccessTokenInput, lifetime_secs, sign_access_token};

/// The token exchange grant type.
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// Token type: an OAuth access token.
pub const TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
/// Token type: an OpenID Connect ID token.
pub const TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";
/// Token type: a JWT.
pub const TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Token types accepted for `subject_token_type` and `actor_token_type`.
const INPUT_TYPES: [&str; 3] = [TYPE_ACCESS_TOKEN, TYPE_ID_TOKEN, TYPE_JWT];

/// Claims dropped from a subject token before they go into the new token.
pub const DROPPED_CLAIMS: [&str; 17] = [
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "azp",
    "client_id",
    "scope",
    "auth_time",
    "nonce",
    "sid",
    "at_hash",
    "c_hash",
    "act",
    "may_act",
    "cnf",
];

fn invalid_request(description: impl Into<String>) -> OAuthError {
    OAuthError::json("invalid_request", description)
}

/// The header and payload of a compact JWT, both JSON objects, without any check.
fn decode_unverified(token: &str) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(_), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err("not a JWT".to_owned());
    };
    let object = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Claims>(&bytes).ok())
            .ok_or_else(|| "not a JWT".to_owned())
    };
    object(header)?;
    object(payload)
}

/// A JWT signed by any configured Issuer: `iss` (unverified) → Issuer; key by `kid` from that
/// Issuer's set; `alg` must match; `exp` checked, leeway 0; `typ` not `rt+jwt`; `jti` not
/// revoked. Error text is for logs.
pub(crate) async fn verify_fauxidc_jwt(app: &AppState, token: &str) -> Result<Claims, String> {
    let unverified = decode_unverified(token)?;
    let iss = unverified
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| "no iss claim".to_owned())?;
    let (issuer_id, issuer) = app
        .config
        .issuer
        .iter()
        .find(|(_, issuer)| issuer.issuer_url == iss)
        .ok_or_else(|| format!("iss {iss} is not a fauxidc Issuer"))?;
    let header = jsonwebtoken::decode_header(token).map_err(|_| "malformed token".to_owned())?;
    if header.typ.as_deref() == Some(REFRESH_TOKEN_TYP) {
        return Err("a refresh token cannot be exchanged".to_owned());
    }
    let keys = app
        .keys
        .key_set(issuer_id)
        .await
        .map_err(|e| format!("keys of Issuer {issuer_id}: {e}"))?;
    let (_, claims) = keys.verify(token, |v| {
        v.leeway = 0;
        v.validate_aud = false;
        v.set_issuer(&[issuer.issuer_url.as_str()]);
        v.set_required_spec_claims(&["exp", "iss"]);
    })?;
    if let Some(jti) = claims.get("jti").and_then(Value::as_str)
        && app.store.is_revoked(jti)
    {
        return Err("token was revoked".to_owned());
    }
    Ok(claims)
}

/// Strict: `verify_fauxidc_jwt`. Lenient: the same, and on failure a warning plus the unverified
/// claims. A value that is not a JWT fails in both modes. `sub` must be a non-empty string.
/// `what` names the parameter in errors and logs.
pub(crate) async fn token_claims(
    ctx: &IssuerCtx,
    token: &str,
    what: &str,
) -> Result<Claims, OAuthError> {
    let unverified = decode_unverified(token).map_err(|e| {
        tracing::info!(issuer = %ctx.id, "{what} rejected: {e}");
        invalid_request(format!("{what} is not a JWT"))
    })?;
    let claims = match verify_fauxidc_jwt(&ctx.app, token).await {
        Ok(claims) => claims,
        Err(e) => {
            ctx.enforce(false, || format!("{what} is invalid: {e}"))
                .map_err(invalid_request)?;
            unverified
        }
    };
    let has_sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    if !has_sub {
        return Err(invalid_request(format!("{what} has no sub")));
    }
    Ok(claims)
}

/// A required, non-empty form value.
fn required<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, OAuthError> {
    value
        .filter(|v| !v.is_empty())
        .ok_or_else(|| invalid_request(format!("{name} is missing")))
}

/// `name` must be one of the accepted input token types.
fn check_input_type(value: &str, name: &str) -> Result<(), OAuthError> {
    if INPUT_TYPES.contains(&value) {
        Ok(())
    } else {
        Err(invalid_request(format!("unsupported {name}: {value}")))
    }
}

/// The JWT header `typ` of an access token (RFC 9068).
const ACCESS_TOKEN_TYP: &str = "at+jwt";

/// Ruling 20: `access_token` → header `typ` `at+jwt`; `id_token` → `typ` not `at+jwt`;
/// `jwt` → any.
fn type_matches(token_type: &str, header_typ: Option<&str>) -> bool {
    let is_access_token = header_typ.is_some_and(|t| t.eq_ignore_ascii_case(ACCESS_TOKEN_TYP));
    match token_type {
        TYPE_ACCESS_TOKEN => is_access_token,
        TYPE_ID_TOKEN => !is_access_token,
        _ => true,
    }
}

/// `{name}` must fit the token (through `enforce`: Strict `invalid_request`, Lenient a
/// warning). `name` is `subject_token_type` or `actor_token_type`.
fn check_token_type(
    ctx: &IssuerCtx,
    token: &str,
    token_type: &str,
    name: &str,
) -> Result<(), OAuthError> {
    let typ = jsonwebtoken::decode_header(token).ok().and_then(|h| h.typ);
    ctx.enforce(type_matches(token_type, typ.as_deref()), || {
        format!(
            "{name} {token_type} does not match the token (typ {})",
            typ.as_deref().unwrap_or("none")
        )
    })
    .map_err(invalid_request)
}

/// Ruling 23 (RFC 8693 4.4): when the subject token has a `may_act` object with `sub`, the
/// actor `sub` must equal it (through `enforce`).
fn check_may_act(ctx: &IssuerCtx, subject: &Claims, actor: &Claims) -> Result<(), OAuthError> {
    let Some(allowed) = subject
        .get("may_act")
        .and_then(|m| m.get("sub"))
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    let actor_sub = actor.get("sub").and_then(Value::as_str);
    ctx.enforce(actor_sub == Some(allowed), || {
        "actor is not allowed by may_act".to_owned()
    })
    .map_err(invalid_request)
}

/// The space-separated values of a string, or `None` if there are none.
fn split_scope(value: Option<&str>) -> Option<Vec<String>> {
    let scope: Vec<String> = value?.split_whitespace().map(str::to_owned).collect();
    (!scope.is_empty()).then_some(scope)
}

/// The `act` claim (RFC 8693 4.1): the actor's `sub`, with the subject token's `act` object
/// nested inside as the prior actor.
fn act_claim(actor: &Claims, subject: &Claims) -> Value {
    let mut act = json!({ "sub": actor.get("sub").cloned().unwrap_or(Value::Null) });
    if let Some(prior) = subject.get("act").filter(|v| v.is_object()) {
        act["act"] = prior.clone();
    }
    act
}

/// The token exchange grant (RFC 8693 2.1, plan Ruling 8). With an `actor_token`, the new
/// token gets an `act` claim (Ruling 9).
pub async fn grant(
    ctx: &IssuerCtx,
    headers: &HeaderMap,
    f: &TokenForm,
) -> Result<Value, OAuthError> {
    let ClientAuth { client, .. } =
        authenticate_client(ctx, headers, Endpoint::Token, f.credentials()).await?;
    require_grant(ctx, &client, GRANT_TOKEN_EXCHANGE)?;

    let subject_token = required(f.subject_token.as_deref(), "subject_token")?;
    let subject_type = required(f.subject_token_type.as_deref(), "subject_token_type")?;
    check_input_type(subject_type, "subject_token_type")?;
    if let Some(requested) = f.requested_token_type.as_deref().filter(|v| !v.is_empty())
        && requested != TYPE_ACCESS_TOKEN
        && requested != TYPE_JWT
    {
        return Err(invalid_request(format!(
            "unsupported requested_token_type: {requested}"
        )));
    }

    let actor_token = f.actor_token.as_deref().filter(|v| !v.is_empty());
    let actor_type = f.actor_token_type.as_deref().filter(|v| !v.is_empty());
    match (actor_token, actor_type) {
        (Some(_), None) => return Err(invalid_request("actor_token_type is missing")),
        (None, Some(_)) => {
            return Err(invalid_request(
                "actor_token_type was sent without actor_token",
            ));
        }
        (Some(_), Some(t)) => check_input_type(t, "actor_token_type")?,
        (None, None) => {}
    }

    let subject = token_claims(ctx, subject_token, "subject_token").await?;
    check_token_type(ctx, subject_token, subject_type, "subject_token_type")?;
    let mut claims = subject.clone();
    for name in DROPPED_CLAIMS {
        claims.remove(name);
    }
    if let (Some(actor_token), Some(actor_type)) = (actor_token, actor_type) {
        let actor = token_claims(ctx, actor_token, "actor_token").await?;
        check_token_type(ctx, actor_token, actor_type, "actor_token_type")?;
        check_may_act(ctx, &subject, &actor)?;
        claims.insert("act".to_owned(), act_claim(&actor, &subject));
    }

    let non_empty = |v: Option<&str>| v.filter(|s| !s.is_empty()).map(str::to_owned);
    let audience = non_empty(f.audience.as_deref())
        .or_else(|| non_empty(f.resource.as_deref()))
        .or_else(|| non_empty(Some(client.config.audience.as_str())))
        .unwrap_or_else(|| client.client_id.clone());
    let scope = split_scope(f.scope.as_deref())
        .or_else(|| split_scope(subject.get("scope").and_then(Value::as_str)))
        .unwrap_or_default();
    let auth_time = subject.get("auth_time").and_then(Value::as_u64);

    let keys = ctx.keys().await?;
    let issuer = ctx.issuer();
    let lifetime = lifetime_secs(
        issuer
            .lifetimes
            .with_override(&client.config.lifetimes)
            .access_token,
    );
    let access_token = sign_access_token(
        &keys.active,
        AccessTokenInput {
            issuer_url: &issuer.issuer_url,
            client_id: &client.client_id,
            audience: &audience,
            claims,
            scope: &scope,
            auth_time,
            lifetime,
        },
    )
    .await?;
    let mut body = json!({
        "access_token": access_token,
        "issued_token_type": TYPE_ACCESS_TOKEN,
        "token_type": "Bearer",
        "expires_in": lifetime,
    });
    if !scope.is_empty() {
        body["scope"] = json!(scope.join(" "));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_unverified_needs_three_json_parts() {
        let enc = |v: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(v).unwrap());
        let t = format!(
            "{}.{}.",
            enc(&json!({"alg":"none"})),
            enc(&json!({"sub":"a"}))
        );
        assert_eq!(decode_unverified(&t).unwrap()["sub"], "a");
        assert!(decode_unverified("opaque").is_err());
        assert!(decode_unverified("a.b.c").is_err());
        assert!(decode_unverified(&format!("{t}.x")).is_err());
        let not_object = format!("{}.{}.", enc(&json!({"alg":"none"})), enc(&json!([1])));
        assert!(decode_unverified(&not_object).is_err());
    }

    #[test]
    fn act_nests_the_prior_actor() {
        let obj = |v: Value| v.as_object().unwrap().clone();
        let actor = obj(json!({"sub": "svc-b", "act": {"sub": "x"}}));
        assert_eq!(
            act_claim(&actor, &obj(json!({"sub": "alice"}))),
            json!({"sub": "svc-b"})
        );
        let subject = obj(json!({"sub": "alice", "act": {"sub": "svc-a"}}));
        assert_eq!(
            act_claim(&actor, &subject),
            json!({"sub": "svc-b", "act": {"sub": "svc-a"}})
        );
        let not_object = obj(json!({"sub": "alice", "act": "svc-a"}));
        assert_eq!(act_claim(&actor, &not_object), json!({"sub": "svc-b"}));
    }

    #[test]
    fn type_matches_the_header_typ() {
        assert!(type_matches(TYPE_ACCESS_TOKEN, Some("at+jwt")));
        assert!(!type_matches(TYPE_ACCESS_TOKEN, Some("JWT")));
        assert!(!type_matches(TYPE_ACCESS_TOKEN, None));
        assert!(type_matches(TYPE_ID_TOKEN, Some("JWT")));
        assert!(type_matches(TYPE_ID_TOKEN, None));
        assert!(!type_matches(TYPE_ID_TOKEN, Some("at+jwt")));
        assert!(type_matches(TYPE_JWT, Some("at+jwt")));
        assert!(type_matches(TYPE_JWT, None));
    }

    #[test]
    fn split_scope_ignores_empty() {
        assert_eq!(
            split_scope(Some("a  b")),
            Some(vec!["a".into(), "b".into()])
        );
        assert_eq!(split_scope(Some(" ")), None);
        assert_eq!(split_scope(None), None);
    }

    #[test]
    fn dropped_claims_cover_the_protocol_claims() {
        for name in crate::claims::PROTOCOL_CLAIMS {
            assert!(DROPPED_CLAIMS.contains(name), "{name}");
        }
    }
}
