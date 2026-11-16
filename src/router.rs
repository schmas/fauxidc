//! The axum router: one sub-router per issuer, nested at the issuer path.

use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{MethodRouter, delete, get, post},
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::{DefaultOnResponse, TraceLayer};

use crate::authorize;
use crate::clients_api;
use crate::config::Endpoint;
use crate::cors::client_cors_layer;
use crate::debugger;
use crate::discovery;
use crate::endsession;
use crate::failures::{self, FailureTarget};
use crate::health;
use crate::introspect;
use crate::issuer::issuer_path;
use crate::jwks;
use crate::logging::{record_endpoint, request_span};
use crate::request_log;
use crate::revoke;
use crate::state::{AppState, IssuerCtx};
use crate::templates;
use crate::test_api;
use crate::token_endpoint;
use crate::userinfo;
use crate::users_api;

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
        let sub = issuer_router(&ctx, &cors);
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
        .route(
            "/_mock/{issuer_id}/token",
            post(test_api::issue).with_state(state.clone()),
        )
        .route(
            "/_mock/{issuer_id}/rotate-key",
            post(test_api::rotate_key).with_state(state.clone()),
        )
        .route(
            "/_mock/{issuer_id}/fail-next",
            post(failures::fail_next)
                .delete(failures::clear)
                .with_state(state.clone()),
        )
        .route(
            "/_mock/users",
            get(users_api::list)
                .post(users_api::create)
                .with_state(state.clone()),
        )
        .route(
            "/_mock/users/{user_id}",
            get(users_api::get)
                .put(users_api::replace)
                .patch(users_api::merge)
                .delete(users_api::remove)
                .with_state(state.clone()),
        )
        .route(
            "/_mock/clients",
            get(clients_api::list)
                .post(clients_api::create)
                .with_state(state.clone()),
        )
        .route(
            "/_mock/clients/{client_key}",
            get(clients_api::get)
                .put(clients_api::replace)
                .patch(clients_api::merge)
                .delete(clients_api::remove)
                .with_state(state.clone()),
        )
        .route(
            "/_mock/state",
            delete(test_api::reset_state).with_state(state.clone()),
        )
        .route(
            "/_mock/requests",
            get(request_log::list)
                .delete(request_log::clear)
                .with_state(state.clone()),
        )
        .route(
            "/_mock/health",
            get(health::health).with_state(state.clone()),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            request_log::record,
        ))
        .layer(trace)
}

/// The routes of one Issuer, relative to its path.
fn issuer_router(ctx: &IssuerCtx, cors: &CorsLayer) -> Router {
    let client_cors = client_cors_layer(&ctx.app.config, &ctx.id);
    let fail = |endpoint: &'static str| FailureTarget {
        store: ctx.app.store.clone(),
        issuer_id: ctx.id.clone(),
        endpoint,
    };
    let debugger_path = ctx.endpoint_path(Endpoint::Debugger).trim_end_matches('/');
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            guarded(get(discovery::document), fail("discovery")).layer(cors.clone()),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            guarded(get(discovery::document), fail("discovery")).layer(cors.clone()),
        )
        .route(
            ctx.endpoint_path(Endpoint::Jwks),
            guarded(get(jwks::jwks), fail("jwks")).layer(cors.clone()),
        )
        .route(
            ctx.endpoint_path(Endpoint::Authorize),
            guarded(
                get(authorize::authorize_get).post(authorize::authorize_post),
                fail("authorize"),
            ),
        )
        .route(
            ctx.endpoint_path(Endpoint::Token),
            guarded(post(token_endpoint::token), fail("token")).layer(client_cors.clone()),
        )
        .route(
            ctx.endpoint_path(Endpoint::Userinfo),
            guarded(
                get(userinfo::userinfo_get).post(userinfo::userinfo_post),
                fail("userinfo"),
            )
            .layer(client_cors.clone()),
        )
        .route(
            ctx.endpoint_path(Endpoint::Endsession),
            guarded(
                get(endsession::endsession_get).post(endsession::endsession_post),
                fail("endsession"),
            ),
        )
        .route(
            ctx.endpoint_path(Endpoint::Revoke),
            guarded(post(revoke::revoke), fail("revoke")).layer(client_cors),
        )
        .route(
            ctx.endpoint_path(Endpoint::Introspect),
            guarded(post(introspect::introspect), fail("introspect")),
        )
        .route(
            ctx.endpoint_path(Endpoint::Debugger),
            guarded(get(debugger::page).post(debugger::decode), fail("debugger")),
        )
        .route(
            &format!("{debugger_path}/start"),
            guarded(get(debugger::start), fail("debugger")),
        )
        .route(
            &format!("{debugger_path}/callback"),
            guarded(get(debugger::callback), fail("debugger")),
        )
        .with_state(ctx.clone())
}

/// Adds the Injected failure middleware of `target` to a route. It sits inside the CORS layer.
/// `route_layer`: a request with a wrong method gets 405 and does not use up an Injected
/// failure (plan Ruling 31).
fn guarded(route: MethodRouter<IssuerCtx>, target: FailureTarget) -> MethodRouter<IssuerCtx> {
    route.route_layer(axum::middleware::from_fn_with_state(
        target,
        failures::inject,
    ))
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
            if let Some(res) = failures::apply(&state.store, id, "discovery").await {
                return res;
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SourceMap, load_str, validate};
    use crate::keys::KeyHandle;

    /// Plan Ruling 30: a guard against a `build_router` panic on a reload. Each config has an
    /// unusual path shape. A config that `validate` rejects never reaches `build_router` (today
    /// that is the jwks path under `/.well-known`); every accepted one must build.
    #[test]
    fn build_router_accepts_unusual_valid_paths() {
        let issuer = |url: &str, paths: &str| {
            format!(
                "[issuer.a]\nissuer_url = \"{url}\"\n{paths}\n[user.alice]\nlabel = \"Alice\"\n"
            )
        };
        let configs = [
            issuer(
                "http://localhost:9000/a",
                "paths = { token = \"/oauth/token\" }",
            ),
            issuer(
                "http://localhost:9000/a/b",
                "paths = { jwks = \"/.well-known/jwks.json\" }",
            ),
            issuer(
                "http://localhost:9000/a",
                "paths = { debugger = \"/v1/debug/\" }",
            ),
            issuer(
                "http://localhost:9000/a",
                "paths = { authorize = \"/a:b\" }",
            ),
            issuer("http://localhost:9000/", ""),
        ];
        let mut built = 0;
        for text in configs {
            // `load_str` runs `validate` too.
            let Ok(loaded) = load_str(&text) else {
                continue;
            };
            let config = loaded.config;
            validate(&config, &SourceMap::new()).unwrap_or_else(|e| panic!("{text}\n{e}"));
            built += 1;
            let (keys, _publisher) = KeyHandle::channel();
            let state = Arc::new(AppState::new(config, keys, true).unwrap());
            let _router = build_router(state);
        }
        assert_eq!(built, 4, "the other four shapes are valid");
    }
}
