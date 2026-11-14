//! The auto-select cookie: it remembers which configured user signed in.

use axum::http::{HeaderMap, HeaderValue, header};

/// Reads the value of cookie `name` from all `Cookie` headers.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|line| line.split("; "))
        .find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.to_owned())
        })
}

/// The name of the auto-select cookie of one issuer.
pub fn auto_select_name(issuer_id: &str) -> String {
    format!("fauxidc_user_{issuer_id}")
}

/// The `Set-Cookie` value that remembers `user_id` for one year.
///
/// Returns `None` if the value is not a valid header value.
pub fn auto_select_set(issuer_id: &str, issuer_path: &str, user_id: &str) -> Option<HeaderValue> {
    let path = match issuer_path.trim_end_matches('/') {
        "" => "/",
        trimmed => trimmed,
    };
    let name = auto_select_name(issuer_id);
    HeaderValue::try_from(format!(
        "{name}={user_id}; Path={path}; HttpOnly; SameSite=Lax; Max-Age=31536000"
    ))
    .ok()
}
