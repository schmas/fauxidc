mod common;
use common::*;

#[tokio::test]
async fn health_ok_before_and_after_key() {
    let (keys, publisher) = fauxidc::keys::KeyHandle::channel();
    let app = app_with_keys(AUTH0, keys);
    let (s, _, b) = send(&app, get("/_mock/health")).await;
    assert_eq!(
        (s.as_u16(), json(&b)["key"].as_str()),
        (200, Some("pending"))
    );
    publisher.publish(KEY.clone());
    assert_eq!(
        json(&send(&app, get("/_mock/health")).await.2)["key"],
        "ready"
    );
}
