//! Issuer URL helpers.

use axum::http::Uri;

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
