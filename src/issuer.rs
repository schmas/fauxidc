//! Issuer URL helpers.

use axum::http::{HeaderMap, Uri, header::HOST};

use crate::config::{Config, IssuerConfig, ServerConfig};

/// Returns the path of an issuer URL without a trailing slash; `/` stays `/`.
///
/// The URL must use `http` or `https`, have an authority, and have no query or fragment.
pub fn issuer_path(issuer_url: &str) -> Result<String, String> {
    if issuer_url.contains('#') {
        return Err("a fragment is not allowed".to_owned());
    }
    let uri: Uri = issuer_url
        .parse()
        .map_err(|e| format!("invalid URL: {e}"))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err("the scheme must be http or https".to_owned());
    }
    if uri.authority().is_none() {
        return Err("a host is required".to_owned());
    }
    if uri.query().is_some() {
        return Err("a query is not allowed".to_owned());
    }
    let path = uri.path().trim_end_matches('/');
    Ok(if path.is_empty() { "/" } else { path }.to_owned())
}

/// `true` if `path` equals `prefix` or lies below it, matching whole segments.
pub(crate) fn under(path: &str, prefix: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The Issuer whose path equals `path` or is a whole-segment prefix of it; the RFC 8414 form
/// `/.well-known/oauth-authorization-server{issuer path}` maps to that Issuer. `/_mock/*` → None.
pub fn issuer_for_path(config: &Config, path: &str) -> Option<String> {
    if under(path, "/_mock") {
        return None;
    }
    let path = match path.strip_prefix("/.well-known/oauth-authorization-server") {
        Some("") => "/",
        Some(rest) if rest.starts_with('/') => rest.trim_end_matches('/'),
        _ => path,
    };
    config
        .issuer
        .iter()
        .filter_map(|(id, issuer)| Some((id, issuer_path(&issuer.issuer_url).ok()?)))
        .filter(|(_, p)| under(path, p))
        .max_by_key(|(_, p)| p.len())
        .map(|(id, _)| id.clone())
}

/// Returns the URL that endpoint paths are appended to, without a trailing slash.
///
/// Order: issuer `public_base_url`, server `public_base_url`, forwarded headers
/// (only if trusted), the `Host` header, then the origin of `issuer_url`.
/// The issuer path is appended to every choice.
pub fn endpoint_base(server: &ServerConfig, issuer: &IssuerConfig, headers: &HeaderMap) -> String {
    let path = match issuer_path(&issuer.issuer_url) {
        Ok(p) if p != "/" => p,
        _ => String::new(),
    };
    let origin = if !issuer.public_base_url.is_empty() {
        issuer.public_base_url.trim_end_matches('/').to_owned()
    } else if !server.public_base_url.is_empty() {
        server.public_base_url.trim_end_matches('/').to_owned()
    } else if let Some(host) = server
        .trust_forwarded_headers
        .then(|| first_value(headers, "x-forwarded-host"))
        .flatten()
    {
        // Without X-Forwarded-Proto, the scheme of this listener (plan Ruling 9).
        let default = if server.tls.enabled() {
            "https"
        } else {
            "http"
        };
        let proto = first_value(headers, "x-forwarded-proto").unwrap_or(default);
        format!("{proto}://{host}")
    } else if let Some(host) = headers.get(HOST).and_then(|v| v.to_str().ok()) {
        let scheme = if server.tls.enabled() {
            "https"
        } else {
            "http"
        };
        format!("{scheme}://{host}")
    } else {
        issuer_origin(&issuer.issuer_url)
    };
    format!("{origin}{path}")
}

/// Returns the first comma-separated value of a header, trimmed, if not empty.
fn first_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let raw = headers.get(name)?.to_str().ok()?;
    let first = raw.split(',').next()?.trim();
    (!first.is_empty()).then_some(first)
}

/// Returns `scheme://authority` of a URL, or an empty string if it has none.
fn issuer_origin(issuer_url: &str) -> String {
    match issuer_url.parse::<Uri>() {
        Ok(uri) => match (uri.scheme_str(), uri.authority()) {
            (Some(scheme), Some(authority)) => format!("{scheme}://{authority}"),
            _ => String::new(),
        },
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IssuerConfig, ServerConfig};
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    fn hdrs(v: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, val) in v {
            map.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(val).unwrap(),
            );
        }
        map
    }

    fn iss(url: &str) -> IssuerConfig {
        IssuerConfig {
            issuer_url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn forwarded_host_without_proto_uses_https_when_tls_is_on() {
        let headers = hdrs(&[("x-forwarded-host", "id.example.test")]);
        let mut server = ServerConfig {
            trust_forwarded_headers: true,
            ..Default::default()
        };
        let issuer = iss("http://localhost:9000/auth0");
        assert!(
            endpoint_base(&server, &issuer, &headers).starts_with("http://id.example.test"),
            "without tls"
        );
        server.tls = crate::config::TlsConfig {
            cert_file: "c.pem".into(),
            key_file: "k.pem".into(),
        };
        assert!(
            endpoint_base(&server, &issuer, &headers).starts_with("https://id.example.test"),
            "with tls"
        );
        // An explicit X-Forwarded-Proto still wins.
        let headers = hdrs(&[
            ("x-forwarded-host", "id.example.test"),
            ("x-forwarded-proto", "http"),
        ]);
        assert!(endpoint_base(&server, &issuer, &headers).starts_with("http://id.example.test"));
    }

    #[test]
    fn issuer_for_path_matches_whole_segments() {
        let cfg = crate::config::load_str(
            "[issuer.auth0]\nissuer_url=\"http://h/auth0\"\n[issuer.okta]\nissuer_url=\"http://h/oauth2/default\"\n",
        )
        .unwrap()
        .config;
        let f = |p: &str| issuer_for_path(&cfg, p);
        assert_eq!(f("/auth0/token").as_deref(), Some("auth0"));
        assert_eq!(f("/auth0").as_deref(), Some("auth0"));
        assert_eq!(f("/auth0x/token"), None);
        assert_eq!(
            f("/.well-known/oauth-authorization-server/auth0").as_deref(),
            Some("auth0")
        );
        assert_eq!(f("/oauth2/default/v1/token").as_deref(), Some("okta"));
        assert_eq!(f("/_mock/health"), None);
        assert_eq!(f("/nothing"), None);
        let root = crate::config::load_str("[issuer.r]\nissuer_url=\"http://h\"\n")
            .unwrap()
            .config;
        assert_eq!(issuer_for_path(&root, "/anything").as_deref(), Some("r"));
        assert_eq!(issuer_for_path(&root, "/_mock/health"), None);
    }

    #[test]
    fn uses_host() {
        assert_eq!(
            endpoint_base(
                &ServerConfig::default(),
                &iss("http://localhost:9000/auth0/"),
                &hdrs(&[("host", "fauxidc:9000")])
            ),
            "http://fauxidc:9000/auth0"
        );
    }

    #[test]
    fn tls_uses_https_with_the_host() {
        let server = ServerConfig {
            tls: crate::config::TlsConfig {
                cert_file: "c.pem".into(),
                key_file: "k.pem".into(),
            },
            ..Default::default()
        };
        assert_eq!(
            endpoint_base(
                &server,
                &iss("http://localhost:9000/auth0/"),
                &hdrs(&[("host", "localhost:9000")])
            ),
            "https://localhost:9000/auth0"
        );
    }

    #[test]
    fn root_issuer_has_no_path() {
        assert_eq!(
            endpoint_base(
                &ServerConfig::default(),
                &iss("http://localhost:9000"),
                &hdrs(&[("host", "a:1")])
            ),
            "http://a:1"
        );
    }

    #[test]
    fn no_host_falls_back_to_issuer_origin() {
        assert_eq!(
            endpoint_base(
                &ServerConfig::default(),
                &iss("http://localhost:9000/a"),
                &hdrs(&[])
            ),
            "http://localhost:9000/a"
        );
    }

    #[test]
    fn forwarded_ignored_unless_trusted() {
        let h = hdrs(&[
            ("host", "a:1"),
            ("x-forwarded-host", "evil"),
            ("x-forwarded-proto", "https"),
        ]);
        let mut s = ServerConfig::default();
        assert_eq!(
            endpoint_base(&s, &iss("http://localhost:9000/a"), &h),
            "http://a:1/a"
        );
        s.trust_forwarded_headers = true;
        assert_eq!(
            endpoint_base(&s, &iss("http://localhost:9000/a"), &h),
            "https://evil/a"
        );
    }

    #[test]
    fn forwarded_takes_first_value() {
        let h = hdrs(&[
            ("x-forwarded-host", "one.example.com, two.example.com"),
            ("x-forwarded-proto", "https, http"),
        ]);
        let s = ServerConfig {
            trust_forwarded_headers: true,
            ..Default::default()
        };
        assert_eq!(
            endpoint_base(&s, &iss("http://localhost:9000/a"), &h),
            "https://one.example.com/a"
        );
    }

    #[test]
    fn public_base_url_precedence() {
        let s = ServerConfig {
            public_base_url: "https://mock.example.com/".into(),
            ..Default::default()
        };
        let mut i = iss("http://localhost:9000/a");
        assert_eq!(
            endpoint_base(&s, &i, &hdrs(&[("host", "a:1")])),
            "https://mock.example.com/a"
        );
        i.public_base_url = "http://per-issuer:1".into();
        assert_eq!(endpoint_base(&s, &i, &hdrs(&[])), "http://per-issuer:1/a");
    }
}
