//! Minimal blocking HTTP probe for the `healthcheck` command (scratch images have no curl).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use axum::http::Uri;

/// Probe an `http://host:port/path` URL. `Ok` only when the status is 200.
pub fn check(url: &str, timeout: Duration) -> Result<(), String> {
    let uri: Uri = url.parse().map_err(|e| format!("invalid url {url}: {e}"))?;
    if uri.scheme_str() != Some("http") {
        return Err(format!("only http:// urls are supported: {url}"));
    }
    let authority = uri
        .authority()
        .ok_or_else(|| format!("url has no host: {url}"))?;
    let port = authority.port_u16().unwrap_or(80);
    let path = uri.path_and_query().map_or("/", |p| p.as_str());

    let addr: SocketAddr = (authority.host(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {authority}: {e}"))?
        .next()
        .ok_or_else(|| format!("cannot resolve {authority}"))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("cannot connect to {authority}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| format!("cannot set timeout: {e}"))?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\nHost: {authority}\r\n\r\n").as_bytes())
        .map_err(|e| format!("cannot send request: {e}"))?;

    let mut head = [0u8; 64];
    let mut len = 0;
    while len < head.len() && !head[..len].contains(&b'\n') {
        match stream.read(&mut head[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) => return Err(format!("cannot read response: {e}")),
        }
    }
    let text = String::from_utf8_lossy(&head[..len]);
    let status_line = text.lines().next().unwrap_or_default();
    match status_line.split_whitespace().nth(1) {
        Some("200") => Ok(()),
        _ => Err(format!("unexpected response: {status_line:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn serve_once(status_line: &'static str) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(format!("{status_line}\r\n\r\n").as_bytes());
            }
        });
        port
    }

    #[test]
    fn rejects_https() {
        assert!(check("https://localhost:1/x", Duration::from_millis(200)).is_err());
    }

    #[test]
    fn closed_port_fails_fast() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let t = std::time::Instant::now();
        assert!(
            check(
                &format!("http://127.0.0.1:{port}/_mock/health"),
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(t.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn accepts_200() {
        let port = serve_once("HTTP/1.1 200 OK");
        let url = format!("http://127.0.0.1:{port}/_mock/health");
        assert_eq!(check(&url, Duration::from_secs(2)), Ok(()));
    }

    #[test]
    fn rejects_non_200() {
        let port = serve_once("HTTP/1.1 503 Service Unavailable");
        let url = format!("http://127.0.0.1:{port}/_mock/health");
        assert!(check(&url, Duration::from_secs(2)).is_err());
    }
}
