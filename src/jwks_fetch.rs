//! Fetches a Client JWK set from an `http://` `jwks_uri` (HTTP/1.0 on a tokio socket).

use std::time::Duration;

use axum::http::Uri;
use jsonwebtoken::jwk::JwkSet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The bound of one whole fetch: connect, write and read.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest accepted response body.
pub const MAX_BODY: usize = 1024 * 1024;
/// How long a fetched JWK set stays in the cache.
pub const CACHE_TTL_SECS: u64 = 60;

/// HTTP/1.0 GET of an `http://` URL on a tokio socket. Status must be 200; the body (at most
/// `MAX_BODY`) must parse as a JWK set. The whole call is bounded by `timeout`.
pub async fn fetch_jwks(url: &str, timeout: Duration) -> Result<JwkSet, String> {
    let uri: Uri = url.parse().map_err(|_| format!("invalid URL \"{url}\""))?;
    let authority = match (uri.scheme_str(), uri.authority()) {
        (Some("http"), Some(a)) if !a.as_str().contains('@') => a.clone(),
        _ => return Err(format!("not an http:// URL: \"{url}\"")),
    };
    let address = format!(
        "{}:{}",
        authority.host(),
        authority.port_u16().unwrap_or(80)
    );
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {authority}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    let response = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(&address)
            .await
            .map_err(|e| format!("connect to {address} failed: {e}"))?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| format!("write failed: {e}"))?;
        let mut buf = Vec::new();
        let limit = u64::try_from(MAX_BODY + MAX_HEAD + 1).unwrap_or(u64::MAX);
        stream
            .take(limit)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        Ok::<_, String>(buf)
    })
    .await
    .map_err(|_| format!("timed out after {} ms", timeout.as_millis()))??;
    parse_response(&response)
}

/// The largest accepted status line plus headers.
const MAX_HEAD: usize = 16 * 1024;

/// Splits an HTTP/1.x response at the blank line, checks the status and parses the body.
fn parse_response(response: &[u8]) -> Result<JwkSet, String> {
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .filter(|&end| end <= MAX_HEAD)
        .ok_or_else(|| "malformed HTTP response".to_owned())?;
    let (head, body) = (&response[..split], &response[split + 4..]);
    let status_line = head.split(|&b| b == b'\r').next().unwrap_or_default();
    let status = String::from_utf8_lossy(status_line);
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code != "200" {
        return Err(format!("status {code}, expected 200"));
    }
    if body.len() > MAX_BODY {
        return Err(format!(
            "response body is too large (limit {MAX_BODY} bytes)"
        ));
    }
    serde_json::from_slice(body).map_err(|e| format!("not a JWK set: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Serves `response` once on a local port and returns the URL `http://127.0.0.1:{port}/jwks`.
    async fn serve_once(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
        format!("http://127.0.0.1:{port}/jwks")
    }

    const SET: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","x":"AQAB","y":"AQAB"}]}"#;

    #[tokio::test]
    async fn fetches_a_jwk_set() {
        let url = serve_once(
            format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{SET}").into_bytes(),
        )
        .await;
        let set = fetch_jwks(&url, Duration::from_secs(2)).await.unwrap();
        assert!(set.find("k1").is_some());
    }

    #[tokio::test]
    async fn non_200_is_an_error() {
        let url = serve_once(b"HTTP/1.0 404 Not Found\r\n\r\n{}".to_vec()).await;
        let e = fetch_jwks(&url, Duration::from_secs(2)).await.unwrap_err();
        assert!(e.contains("404"), "{e}");
    }

    #[tokio::test]
    async fn oversized_body_is_an_error() {
        let mut response = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        response.extend(std::iter::repeat_n(b' ', MAX_BODY + 1));
        let url = serve_once(response).await;
        let e = fetch_jwks(&url, Duration::from_secs(5)).await.unwrap_err();
        assert!(e.contains("too large"), "{e}");
    }

    #[tokio::test]
    async fn slow_host_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            // Accept and never answer.
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let started = std::time::Instant::now();
        let e = fetch_jwks(
            &format!("http://127.0.0.1:{port}/jwks"),
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(1), "{e}");
        assert!(e.contains("timed out"), "{e}");
    }

    #[tokio::test]
    async fn https_url_is_an_error() {
        let e = fetch_jwks("https://keys.example.com/jwks", Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(e.contains("http://"), "{e}");
    }

    #[tokio::test]
    async fn bad_json_is_an_error() {
        let url = serve_once(b"HTTP/1.0 200 OK\r\n\r\nnot json".to_vec()).await;
        assert!(fetch_jwks(&url, Duration::from_secs(2)).await.is_err());
    }
}
