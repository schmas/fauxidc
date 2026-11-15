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
        read_response(&mut stream).await
    })
    .await
    .map_err(|_| format!("timed out after {} ms", timeout.as_millis()))??;
    parse_response(&response)
}

/// Reads the response until EOF, or until `Content-Length` body bytes arrived, or until more
/// than `MAX_HEAD + MAX_BODY` bytes arrived.
async fn read_response(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let limit = MAX_BODY + MAX_HEAD + 1;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut expected_len: Option<usize> = None;
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            return Ok(buf);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        if expected_len.is_none()
            && let Some(end) = head_end(&buf)
            && let Some(len) = content_length(buf.get(..end).unwrap_or_default())
        {
            if len > MAX_BODY {
                return Err(format!(
                    "response body is too large (limit {MAX_BODY} bytes)"
                ));
            }
            expected_len = Some(end + 4 + len);
        }
        if expected_len.is_some_and(|total| buf.len() >= total) || buf.len() >= limit {
            return Ok(buf);
        }
    }
}

/// The index of the `\r\n\r\n` that ends the head, if it arrived.
fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The `Content-Length` value of a response head, if present and valid.
fn content_length(head: &[u8]) -> Option<usize> {
    String::from_utf8_lossy(head)
        .split("\r\n")
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse().ok()
            } else {
                None
            }
        })
}

/// The largest accepted status line plus headers.
const MAX_HEAD: usize = 16 * 1024;

/// Splits an HTTP/1.x response at the blank line, checks the status and parses the body.
fn parse_response(response: &[u8]) -> Result<JwkSet, String> {
    let split = head_end(response)
        .filter(|&end| end <= MAX_HEAD)
        .ok_or_else(|| "malformed HTTP response".to_owned())?;
    let (head, mut body) = (&response[..split], &response[split + 4..]);
    if let Some(len) = content_length(head) {
        body = body.get(..len).unwrap_or(body);
    }
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
    async fn stops_at_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{SET}",
                SET.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            // Keep the socket open.
            tokio::time::sleep(Duration::from_secs(10)).await;
        });
        let set = fetch_jwks(
            &format!("http://127.0.0.1:{port}/jwks"),
            Duration::from_millis(500),
        )
        .await
        .unwrap();
        assert!(set.find("k1").is_some());
    }

    #[tokio::test]
    async fn too_large_content_length_is_an_error() {
        let url = serve_once(
            format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{{}}",
                MAX_BODY + 1
            )
            .into_bytes(),
        )
        .await;
        let e = fetch_jwks(&url, Duration::from_secs(2)).await.unwrap_err();
        assert!(e.contains("too large"), "{e}");
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
