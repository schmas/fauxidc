//! CORS for the browser-facing endpoints `/token`, `/userinfo` and `/revoke`.
//!
//! The allowed origins are computed once per Issuer when the router is built. A preflight
//! has no `client_id`, so the set is the union over every Client of the Issuer.

use std::collections::BTreeSet;
use std::time::Duration;

use axum::http::{HeaderValue, Method};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

use crate::config::Config;

/// `scheme://host[:port]` of an absolute http(s) URI, scheme and host lowercased; a trailing `*`
/// segment and the path are dropped. `None` for anything else.
pub fn origin_of(uri: &str) -> Option<String> {
    let (scheme, rest) = uri.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains(['@', '*'])
        || authority.contains(char::is_whitespace)
    {
        return None;
    }
    Some(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

/// The union over every Client of this Issuer (`issuer` = the id or `"*"`): its `web_origins`
/// (trailing `/` trimmed) when set, else the origins of its `redirect_uris`.
pub fn allowed_origins(config: &Config, issuer_id: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for client in config
        .client
        .values()
        .filter(|c| c.issuer == "*" || c.issuer == issuer_id)
    {
        match &client.web_origins {
            Some(origins) => out.extend(
                origins
                    .iter()
                    .filter_map(|o| origin_of(o.trim_end_matches('/'))),
            ),
            None => out.extend(client.redirect_uris.iter().filter_map(|u| origin_of(u))),
        }
    }
    out
}

/// Strict: `AllowOrigin::predicate` over `allowed_origins`. Lenient: `AllowOrigin::mirror_request()`.
/// Both: methods GET, POST; `AllowHeaders::mirror_request()`; `max_age` 600 s; no credentials.
pub fn client_cors_layer(config: &Config, issuer_id: &str) -> CorsLayer {
    let lenient = config.issuer.get(issuer_id).is_some_and(|i| i.lenient);
    let origin = if lenient {
        AllowOrigin::mirror_request()
    } else {
        let allowed = allowed_origins(config, issuer_id);
        AllowOrigin::predicate(move |origin: &HeaderValue, _parts| {
            origin
                .to_str()
                .is_ok_and(|o| allowed.contains(&o.to_ascii_lowercase()))
        })
    };
    CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(AllowHeaders::mirror_request())
        .max_age(Duration::from_secs(600))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_str;

    #[test]
    fn origins() {
        assert_eq!(
            origin_of("http://localhost:3000/api/auth/callback/*").as_deref(),
            Some("http://localhost:3000")
        );
        assert_eq!(
            origin_of("HTTPS://App.Example.com/cb").as_deref(),
            Some("https://app.example.com")
        );
        assert_eq!(origin_of("not a url"), None);
        assert_eq!(origin_of("ftp://example.com/x"), None);
    }

    #[test]
    fn web_origins_replace_redirect_origins() {
        let c = load_str(
            "[issuer.a]\nissuer_url=\"http://h/a\"\n[client.x]\nredirect_uris=[\"http://localhost:3000/cb\"]\n\
        [client.y]\nredirect_uris=[\"http://localhost:4000/cb\"]\nweb_origins=[\"http://localhost:5000/\"]\n",
        )
        .unwrap()
        .config;
        let o = allowed_origins(&c, "a");
        assert!(o.contains("http://localhost:3000") && o.contains("http://localhost:5000"));
        assert!(!o.contains("http://localhost:4000"));
    }
}
