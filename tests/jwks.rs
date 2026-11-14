mod common;
use common::*;

#[tokio::test]
async fn jwks_has_the_key() {
    let (s, h, b) = send(&app(AUTH0), get("/auth0/jwks")).await;
    assert_eq!(s, 200);
    assert_eq!(h["access-control-allow-origin"], "*");
    assert_eq!(h["content-type"], "application/json");
    let j = json(&b);
    assert_eq!(j["keys"][0]["kid"], KEY.kid.as_str());
    assert_eq!(j["keys"][0]["use"], "sig");
}

#[tokio::test]
async fn jwks_waits_for_key() {
    let (keys, publisher) = KeyHandle::channel();
    let app = app_with_keys(AUTH0, keys);
    let req = tokio::spawn(async move { send(&app, get("/auth0/jwks")).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(!req.is_finished());
    publisher.publish(KEY.clone());
    assert_eq!(req.await.unwrap().0, 200);
}

#[tokio::test]
async fn jwks_is_503_when_key_generation_failed() {
    let (keys, publisher) = KeyHandle::channel();
    publisher.fail();
    let (s, _, b) = send(&app_with_keys(AUTH0, keys), get("/auth0/jwks")).await;
    assert_eq!(s, 503);
    let j = json(&b);
    assert_eq!(j["error"], "server_error");
    assert_eq!(j["error_description"], "signing key not available");
}
