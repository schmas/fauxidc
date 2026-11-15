//! Its own test binary: a thread-local log capture (`set_default`) misses events when other
//! tests of the same binary hit the same callsites in parallel.

mod common;
use common::*;

struct CaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn injected_failure_records_the_endpoint() {
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let w = logs.clone();
    let sub = tracing_subscriber::fmt()
        .with_writer(move || CaptureWriter(w.clone()))
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);
    let app = app(STRICT);
    send(
        &app,
        post_json("/_mock/auth0/fail-next", &json!({"endpoint":"jwks"})),
    )
    .await;
    assert_eq!(send(&app, get("/auth0/jwks")).await.0, 500);
    let text = String::from_utf8_lossy(&logs.lock().unwrap()).into_owned();
    let line = text
        .lines()
        .find(|l| l.contains("injected failure") && l.contains("status=500"))
        .unwrap_or_else(|| panic!("{text}"));
    // The request span (before the `:`) carries the fields, not only the event.
    let span = line.split("}:").next().unwrap();
    assert!(
        span.contains("issuer=\"auth0\"") && span.contains("endpoint=\"jwks\""),
        "{line}"
    );
}
