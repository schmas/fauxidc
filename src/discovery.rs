//! Discovery document (OpenID Connect Discovery and RFC 8414).

use axum::{Json, extract::State, http::HeaderMap};
use serde_json::{Value, json};

use crate::logging::record_endpoint;
use crate::state::IssuerCtx;

/// Returns the discovery document. `issuer` is fixed; endpoints follow the request.
pub async fn document(State(ctx): State<IssuerCtx>, headers: HeaderMap) -> Json<Value> {
    record_endpoint(&ctx.id, "discovery");
    let b = ctx.base_url(&headers);
    Json(json!({
        "issuer": ctx.issuer().issuer_url,
        "authorization_endpoint": format!("{b}/authorize"),
        "token_endpoint": format!("{b}/token"),
        "userinfo_endpoint": format!("{b}/userinfo"),
        "jwks_uri": format!("{b}/jwks"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name", "family_name", "nickname", "preferred_username", "picture", "email", "email_verified"],
    }))
}
