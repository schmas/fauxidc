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

#[tokio::test]
async fn health_waits_for_all_issuer_keys() {
    let (keys, publisher) = fauxidc::keys::KeyHandle::channel();
    let cfg = format!(
        "{AUTH0}\n[issuer.es]\nissuer_url = \"http://localhost:9000/es\"\nsigning_alg = \"ES256\"\n"
    );
    let app = app_with_keys(&cfg, keys);
    assert_eq!(
        json(&send(&app, get("/_mock/health")).await.2)["key"],
        "pending"
    );
    publisher.publish(KEY.clone());
    let mut state = Value::Null;
    for _ in 0..200 {
        state = json(&send(&app, get("/_mock/health")).await.2)["key"].clone();
        if state == "ready" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(state, "ready");
    // The ES256 Issuer JWKS waits for its own key and serves it.
    assert_eq!(
        json(&send(&app, get("/es/jwks")).await.2)["keys"][0]["alg"],
        "ES256"
    );
}

#[tokio::test]
async fn health_is_pending_while_one_issuer_key_is_pending() {
    // The server key is ready; the RS256 Issuer "rs" generates its own key for its key_file
    // in the background (RSA generation takes a while in a debug build).
    let dir = tmp_dir();
    let cfg = format!(
        "{AUTH0}\n[issuer.rs]\nissuer_url = \"http://localhost:9000/rs\"\nkey_file = \"{}\"\n",
        dir.join("rs.pem").display()
    );
    let app = app(&cfg);
    assert_eq!(
        json(&send(&app, get("/_mock/health")).await.2)["key"],
        "pending"
    );
    wait_until(Duration::from_secs(60), || async {
        json(&send(&app, get("/_mock/health")).await.2)["key"] == "ready"
    })
    .await;
}
