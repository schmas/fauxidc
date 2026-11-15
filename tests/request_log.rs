mod common;
use common::*;

fn delete(uri: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("host", "localhost:9000")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn token_post_is_logged_and_still_works() {
    let app = app(STRICT);
    let _ = access_token_for(&app, &[]).await; // proves the form still parses
    let (s, _, b) = send(&app, get("/_mock/requests?issuer=auth0&path=/auth0/token")).await;
    assert_eq!(s, 200);
    let entries = json(&b);
    let e = &entries.as_array().unwrap()[0];
    assert_eq!(e["method"], "POST");
    assert_eq!(e["status"], 200);
    assert_eq!(e["issuer"], "auth0");
    assert!(
        e["body"]
            .as_str()
            .unwrap()
            .contains("grant_type=authorization_code")
    );
    assert!(
        e["headers"]["authorization"]
            .as_str()
            .unwrap()
            .starts_with("Basic ")
    );
}

#[tokio::test]
async fn ring_buffer_keeps_newest() {
    let app = app(&format!("[server]\nrequest_log_size = 2\n{STRICT}"));
    for _ in 0..3 {
        send(&app, get("/auth0/.well-known/openid-configuration")).await;
    }
    let (_, _, b) = send(&app, get("/_mock/requests")).await;
    let entries = json(&b);
    let ids: Vec<u64> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, vec![2, 3]);
}

#[tokio::test]
async fn delete_clears_and_mock_requests_are_not_logged() {
    let app = app(STRICT);
    send(&app, get("/auth0/.well-known/openid-configuration")).await;
    let (s, _, _) = send(&app, delete("/_mock/requests")).await;
    assert_eq!(s, 204);
    let (_, _, b) = send(&app, get("/_mock/requests")).await;
    assert_eq!(json(&b), json!([]));
    // ids are never reused
    send(&app, get("/auth0/.well-known/openid-configuration")).await;
    let (_, _, b) = send(&app, get("/_mock/requests")).await;
    assert_eq!(json(&b)[0]["id"], 2);
}

#[tokio::test]
async fn size_zero_disables_log() {
    let app = app(&format!("[server]\nrequest_log_size = 0\n{STRICT}"));
    send(&app, get("/auth0/.well-known/openid-configuration")).await;
    let (s, _, b) = send(&app, get("/_mock/requests")).await;
    assert_eq!(s, 200);
    assert_eq!(json(&b), json!([]));
}

#[tokio::test]
async fn query_and_issuer_are_recorded() {
    let app = app(STRICT);
    send(&app, get(&authorize_url(&[]))).await;
    let (_, _, b) = send(&app, get("/_mock/requests?issuer=auth0")).await;
    let e = &json(&b)[0];
    assert!(
        e["query"]
            .as_str()
            .unwrap()
            .contains("client_id=example-app")
    );
    assert_eq!(e["issuer"], "auth0");
    assert_eq!(e["path"], "/auth0/authorize");
    let (_, _, b) = send(&app, get("/_mock/requests?issuer=other")).await;
    assert_eq!(json(&b), json!([]));
}

#[tokio::test]
async fn oversized_body_is_413() {
    let big = "a".repeat(1024 * 1024 + 1);
    let req = Request::builder()
        .method("POST")
        .uri("/auth0/token")
        .header("host", "localhost:9000")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(big))
        .unwrap();
    let (s, _, b) = send(&app(STRICT), req).await;
    assert_eq!(s, 413);
    assert_eq!(json(&b)["error"], "invalid_request");
}

#[tokio::test]
async fn issuer_path_starting_with_mock_prefix_is_logged() {
    let app = app("[issuer.m]\nissuer_url = \"http://localhost:9000/_mockery\"\n");
    send(&app, get("/_mockery/.well-known/openid-configuration")).await;
    let (_, _, b) = send(&app, get("/_mock/requests")).await;
    assert_eq!(json(&b).as_array().unwrap().len(), 1);
}
