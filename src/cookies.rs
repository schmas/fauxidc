//! The Auto-select cookie (it remembers which configured User signed in) and the Session cookie.

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
    let path = cookie_path(issuer_path);
    let name = auto_select_name(issuer_id);
    HeaderValue::try_from(format!(
        "{name}={user_id}; Path={path}; HttpOnly; SameSite=Lax; Max-Age=31536000"
    ))
    .ok()
}

/// The `Set-Cookie` value that removes the auto-select cookie (same path as `auto_select_set`).
///
/// Returns `None` if the value is not a valid header value.
pub fn auto_select_clear(issuer_id: &str, issuer_path: &str) -> Option<HeaderValue> {
    let path = cookie_path(issuer_path);
    let name = auto_select_name(issuer_id);
    HeaderValue::try_from(format!(
        "{name}=; Path={path}; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .ok()
}

/// The name of the Session cookie of one Issuer.
pub fn session_name(issuer_id: &str) -> String {
    format!("fauxidc_session_{issuer_id}")
}

/// The `Set-Cookie` value of a Session: a browser-session cookie (no `Max-Age`).
///
/// Returns `None` if the value is not a valid header value.
pub fn session_set(issuer_id: &str, issuer_path: &str, value: &str) -> Option<HeaderValue> {
    let path = cookie_path(issuer_path);
    let name = session_name(issuer_id);
    HeaderValue::try_from(format!(
        "{name}={value}; Path={path}; HttpOnly; SameSite=Lax"
    ))
    .ok()
}

/// The `Set-Cookie` value that removes the Session cookie (same path as `session_set`).
///
/// Returns `None` if the value is not a valid header value.
pub fn session_clear(issuer_id: &str, issuer_path: &str) -> Option<HeaderValue> {
    let path = cookie_path(issuer_path);
    let name = session_name(issuer_id);
    HeaderValue::try_from(format!(
        "{name}=; Path={path}; HttpOnly; SameSite=Lax; Max-Age=0"
    ))
    .ok()
}

/// The cookie `Path`: the Issuer path without a trailing slash, or `/`.
fn cookie_path(issuer_path: &str) -> &str {
    match issuer_path.trim_end_matches('/') {
        "" => "/",
        trimmed => trimmed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_uses_the_set_path() {
        assert_eq!(
            auto_select_clear("auth0", "/auth0/").unwrap(),
            "fauxidc_user_auth0=; Path=/auth0; HttpOnly; SameSite=Lax; Max-Age=0"
        );
        assert!(
            auto_select_clear("r", "/")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Path=/;")
        );
    }

    #[test]
    fn session_cookie_has_no_max_age_and_clear_uses_its_path() {
        assert_eq!(
            session_set("auth0", "/auth0/", "v").unwrap(),
            "fauxidc_session_auth0=v; Path=/auth0; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            session_clear("auth0", "/auth0/").unwrap(),
            "fauxidc_session_auth0=; Path=/auth0; HttpOnly; SameSite=Lax; Max-Age=0"
        );
    }
}
