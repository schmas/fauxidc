//! Discovery document (OpenID Connect Discovery and RFC 8414).

use axum::{Json, extract::State, http::HeaderMap};
use serde_json::{Value, json};

use crate::client_auth::ASSERTION_ALGS;
use crate::config::Endpoint;
use crate::jwt_bearer::GRANT_JWT_BEARER;
use crate::logging::record_endpoint;
use crate::state::IssuerCtx;
use crate::token_exchange::GRANT_TOKEN_EXCHANGE;

/// Returns the discovery document. `issuer` is fixed unless `issuer_from_host`; endpoints
/// follow the request.
pub async fn document(State(ctx): State<IssuerCtx>, headers: HeaderMap) -> Json<Value> {
    record_endpoint(&ctx.id, "discovery");
    let url = |e| ctx.endpoint_url(&headers, e);
    Json(json!({
        "issuer": ctx.issuer_url(&headers),
        "authorization_endpoint": url(Endpoint::Authorize),
        "token_endpoint": url(Endpoint::Token),
        "userinfo_endpoint": url(Endpoint::Userinfo),
        "jwks_uri": url(Endpoint::Jwks),
        "end_session_endpoint": url(Endpoint::Endsession),
        "revocation_endpoint": url(Endpoint::Revoke),
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "revocation_endpoint_auth_signing_alg_values_supported": ASSERTION_ALGS,
        "introspection_endpoint": url(Endpoint::Introspect),
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
        "introspection_endpoint_auth_signing_alg_values_supported": ASSERTION_ALGS,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "form_post"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials", GRANT_TOKEN_EXCHANGE, GRANT_JWT_BEARER],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ctx.issuer().signing_alg.as_str()],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt", "none"],
        "token_endpoint_auth_signing_alg_values_supported": ASSERTION_ALGS,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false,
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "given_name", "family_name", "nickname", "preferred_username", "picture", "email", "email_verified"],
    }))
}
