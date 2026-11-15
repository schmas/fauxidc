mod common;
use common::*;

#[tokio::test]
async fn next_token_request_fails_then_recovers() {
    let app = app(STRICT);
    let (s, _, b) = send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"token","status":503,"error":"temporarily_unavailable"}),
        ),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(json(&b)["remaining"], 1);
    let form = [("grant_type", "client_credentials")];
    let (s, h, b) = send(
        &app,
        post_form(
            "/auth0/token",
            &form,
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 503);
    assert_eq!(
        json(&b),
        json!({"error":"temporarily_unavailable","error_description":"injected failure"})
    );
    assert_eq!(h["cache-control"], "no-store");
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/token",
            &form,
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_ne!(s, 503);
}

#[tokio::test]
async fn post_response_shows_the_entry() {
    let app = app(STRICT);
    let (s, _, b) = send(
        &app,
        post_json("/_mock/auth0/fail-next", &json!({"endpoint":"jwks"})),
    )
    .await;
    assert_eq!(s, 200, "{b}");
    assert_eq!(
        json(&b),
        json!({"endpoint":"jwks","status":500,"error":"server_error","remaining":1,"delay_ms":0})
    );
}

#[tokio::test]
async fn count_and_defaults() {
    let app = app(STRICT);
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"jwks","count":2}),
        ),
    )
    .await;
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 500);
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 500);
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 200);
}

#[tokio::test]
async fn delay_only_entry_delays_and_succeeds() {
    let app = app(STRICT);
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"discovery","delay_ms":300}),
        ),
    )
    .await;
    let t = std::time::Instant::now();
    assert_eq!(
        send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .0,
        200
    );
    assert!(t.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn discovery_covers_the_rfc8414_form() {
    let app = app(STRICT);
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"discovery","count":2}),
        ),
    )
    .await;
    assert_eq!(
        send(&app, get("/.well-known/oauth-authorization-server/auth0"))
            .await
            .0,
        500
    );
    assert_eq!(
        send(&app, get("/auth0/.well-known/oauth-authorization-server"))
            .await
            .0,
        500
    );
    assert_eq!(
        send(&app, get("/auth0/.well-known/openid-configuration"))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn failure_is_per_issuer_and_survives_reload() {
    let cfg = format!("{STRICT}\n[issuer.okta]\nissuer_url = \"http://localhost:9000/okta\"\n");
    let (app, handle) = live_app(&cfg);
    send(
        &app,
        post_json("/_mock/auth0/fail-next", &json!({"endpoint":"jwks"})),
    )
    .await;
    assert_eq!(send(&app, get("/okta/jwks")).await.0, 200);
    handle
        .apply(fauxidc::config::load_str(&cfg).unwrap().config)
        .unwrap();
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 500);
}

#[tokio::test]
async fn bad_bodies_and_unknown_issuer() {
    let app = app(STRICT);
    for body in [
        json!({"endpoint":"nope"}),
        json!({"endpoint":"token","status":200}),
        json!({"endpoint":"token","delay_ms":60001}),
        json!({"endpoint":"token","extra":1}),
        json!({"endpoint":"token","error":""}),
    ] {
        let (s, _, b) = send(&app, post_json("/_mock/auth0/fail-next", &body)).await;
        assert_eq!(s, 400, "{body}");
        assert_eq!(json(&b)["error"], "invalid_request");
    }
    assert_eq!(
        send(
            &app,
            post_json("/_mock/nope/fail-next", &json!({"endpoint":"token"}))
        )
        .await
        .0,
        404
    );
}

#[tokio::test]
async fn count_zero_and_delete_remove_entries() {
    let app = app(STRICT);
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"jwks","count":5}),
        ),
    )
    .await;
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"jwks","count":0}),
        ),
    )
    .await;
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 200);
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"jwks","count":5}),
        ),
    )
    .await;
    let del = Request::builder()
        .method("DELETE")
        .uri("/_mock/auth0/fail-next")
        .header("host", "localhost:9000")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, del).await.0, 204);
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 200);
}

#[tokio::test]
async fn failure_count_is_exact_under_parallel_requests() {
    let app = app(STRICT);
    send(
        &app,
        post_json("/_mock/auth0/fail-next", &json!({"endpoint":"jwks"})),
    )
    .await;
    let (a, b) = tokio::join!(
        send(&app, get("/auth0/jwks")),
        send(&app, get("/auth0/jwks"))
    );
    assert_eq!(
        [a.0.as_u16(), b.0.as_u16()]
            .iter()
            .filter(|s| **s == 500)
            .count(),
        1
    );
}

#[tokio::test]
async fn preflight_does_not_consume_a_failure() {
    let app = app(STRICT);
    send(
        &app,
        post_json(
            "/_mock/auth0/fail-next",
            &json!({"endpoint":"token","status":503}),
        ),
    )
    .await;
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/auth0/token")
        .header("host", "localhost:9000")
        .header("origin", "http://localhost:5173")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    let (s, h, _) = send(&app, preflight).await;
    assert!(s.is_success(), "{s}");
    assert_eq!(h["access-control-allow-origin"], "http://localhost:5173");
    let (s, _, _) = send(
        &app,
        post_form(
            "/auth0/token",
            &[("grant_type", "client_credentials")],
            &[("authorization", &basic("example-app", "local"))],
        ),
    )
    .await;
    assert_eq!(s, 503);
}
