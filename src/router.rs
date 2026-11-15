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
use tower_http::trace::{DefaultOnResponse, TraceLayer};

use crate::authorize;
use crate::config::Endpoint;
use crate::discovery;
use crate::health;
use crate::issuer::issuer_path;
use crate::jwks;
use crate::logging::{record_endpoint, request_span};
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
            .route(
                ctx.endpoint_path(Endpoint::Jwks),
                get(jwks::jwks).layer(cors.clone()),
            )
            .route(
                ctx.endpoint_path(Endpoint::Authorize),
                get(authorize::authorize_get).post(authorize::authorize_post),
            )
            .route(
                ctx.endpoint_path(Endpoint::Token),
                post(token_endpoint::token),
            )
            .route(
                ctx.endpoint_path(Endpoint::Userinfo),
                get(userinfo::userinfo).post(userinfo::userinfo),
            )
            .with_state(ctx.clone());
        router = if path == "/" {
            router.merge(sub)
        } else {
            router.nest(&path, sub)
        };
    }
    let trace = TraceLayer::new_for_http()
        .make_span_with(request_span)
        .on_response(DefaultOnResponse::new().level(tracing::Level::INFO));
    router
        .route(
            "/.well-known/oauth-authorization-server/{*issuer_path}",
            get(rfc8414_discovery).layer(cors).with_state(state.clone()),
        )
        .route(
            "/_mock/static/{*path}",
            get(templates::static_file).with_state(state.clone()),
        )
        .route("/_mock/health", get(health::health).with_state(state))
        .layer(trace)
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
            record_endpoint(id, "discovery");
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
