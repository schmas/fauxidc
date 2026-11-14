//! The axum router: one sub-router per issuer, nested at the issuer path.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};

use crate::authorize;
use crate::discovery;
use crate::issuer::issuer_path;
use crate::jwks;
use crate::state::{AppState, IssuerCtx};
use crate::templates;
use crate::token_endpoint;
use crate::userinfo;

/// Builds the router for all configured issuers.
pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new().allow_origin(Any);
    let mut router = Router::new();
    for (id, issuer) in &state.config.issuer {
        // `validate` accepted every issuer URL, so the path is valid.
        let Ok(path) = issuer_path(&issuer.issuer_url) else {
            continue;
        };
        let ctx = IssuerCtx {
            app: state.clone(),
            id: id.clone(),
            path: path.clone(),
        };
        let sub: Router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(discovery::document).layer(cors.clone()),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(discovery::document).layer(cors.clone()),
            )
            .route("/jwks", get(jwks::jwks).layer(cors.clone()))
            .route(
                "/authorize",
                get(authorize::authorize_get).post(authorize::authorize_post),
            )
            .route("/token", post(token_endpoint::token))
            .route(
                "/userinfo",
                get(userinfo::userinfo).post(userinfo::userinfo),
            )
            .with_state(ctx);
        router = if path == "/" {
            router.merge(sub)
        } else {
            router.nest(&path, sub)
        };
    }
    router
        .route(
            "/.well-known/oauth-authorization-server/{*issuer_path}",
            get(rfc8414_discovery).layer(cors).with_state(state.clone()),
        )
        .route(
            "/_mock/static/{*path}",
            get(templates::static_file).with_state(state),
        )
}

/// RFC 8414 path insertion: the well-known segment comes before the issuer path.
async fn rfc8414_discovery(
    State(state): State<Arc<AppState>>,
    Path(issuer_path_tail): Path<String>,
    headers: HeaderMap,
) -> Response {
    let wanted = format!("/{}", issuer_path_tail.trim_end_matches('/'));
    let found = state.config.issuer.keys().find(|id| {
        state
            .config
            .issuer
            .get(*id)
            .and_then(|i| issuer_path(&i.issuer_url).ok())
            .is_some_and(|p| p == wanted)
    });
    match found {
        Some(id) => {
            let ctx = IssuerCtx {
                app: state.clone(),
                id: id.clone(),
                path: wanted,
            };
            discovery::document(State(ctx), headers)
                .await
                .into_response()
        }
        None => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}
