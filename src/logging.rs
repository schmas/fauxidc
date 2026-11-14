//! Log setup and request spans.
//!
//! Request spans carry the method and the path only. They never carry the query string,
//! headers or bodies, because those can hold client secrets, codes and tokens.

use std::net::IpAddr;

use tracing::field::Empty;
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;

/// Installs the global subscriber: logs to stderr, JSON for [`LogFormat::Json`].
///
/// `filter` uses `EnvFilter` syntax (the `FAUXIDC_LOG` value) and defaults to `info`.
pub fn init(format: LogFormat, filter: Option<&str>) -> Result<(), String> {
    let filter = EnvFilter::try_new(filter.unwrap_or("info"))
        .map_err(|err| format!("invalid log filter: {err}"))?;
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    let result = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
    result.map_err(|err| format!("cannot install logger: {err}"))
}

/// Whether `bind` only accepts connections from this machine.
pub fn is_loopback_bind(bind: &str) -> bool {
    bind == "localhost" || bind.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The span for one request: method and path only; the other fields are filled by handlers.
pub fn request_span<B>(request: &axum::http::Request<B>) -> tracing::Span {
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
        issuer = Empty,
        endpoint = Empty,
        client_id = Empty,
    )
}

/// Records the issuer and the endpoint on the current request span.
pub fn record_endpoint(issuer: &str, endpoint: &str) {
    let span = tracing::Span::current();
    span.record("issuer", issuer);
    span.record("endpoint", endpoint);
}

/// Records the client on the current request span.
pub fn record_client(client_id: &str) {
    tracing::Span::current().record("client_id", client_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        for b in ["127.0.0.1", "::1", "localhost"] {
            assert!(is_loopback_bind(b), "{b}");
        }
        for b in ["0.0.0.0", "::", "192.168.1.10"] {
            assert!(!is_loopback_bind(b), "{b}");
        }
    }
}
