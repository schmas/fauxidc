//! The Auto-select cookie (it remembers which configured User signed in), the Session cookie,
//! the login view cookie and the debugger state cookie.

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

/// The name of the login view cookie of one Issuer. The login page script sets it (`list` or
/// `form`), so it is not `HttpOnly`.
pub fn login_view_name(issuer_id: &str) -> String {
    format!("fauxidc_login_view_{issuer_id}")
}

/// The `Path` of the login view cookie: the Issuer cookie path.
pub fn login_view_path(issuer_path: &str) -> String {
    cookie_path(issuer_path).to_owned()
}

/// The `Set-Cookie` value that removes the login view cookie (same path as the page script sets).
///
/// Returns `None` if the value is not a valid header value.
pub fn login_view_clear(issuer_id: &str, issuer_path: &str) -> Option<HeaderValue> {
    let path = cookie_path(issuer_path);
    let name = login_view_name(issuer_id);
    HeaderValue::try_from(format!("{name}=; Path={path}; SameSite=Lax; Max-Age=0")).ok()
}

/// The saved login view: `Some(true)` for `list`, `Some(false)` for `form`. Any other value or no
/// cookie gives `None`.
pub fn read_login_view(headers: &HeaderMap, issuer_id: &str) -> Option<bool> {
    match read_cookie(headers, &login_view_name(issuer_id))?.as_str() {
        "list" => Some(true),
        "form" => Some(false),
        _ => None,
    }
}

/// The name of the debugger state cookie of one Issuer.
pub fn debugger_name(issuer_id: &str) -> String {
    format!("fauxidc_debugger_{issuer_id}")
}

/// The `Set-Cookie` value that binds a debugger flow `state` to this browser for 600 s.
/// `path` is the debugger path of the Issuer, so the cookie reaches `{debugger}/callback`.
///
/// Returns `None` if the value is not a valid header value.
pub fn debugger_set(issuer_id: &str, path: &str, state: &str) -> Option<HeaderValue> {
    let path = cookie_path(path);
    let name = debugger_name(issuer_id);
    HeaderValue::try_from(format!(
        "{name}={state}; Path={path}; HttpOnly; SameSite=Lax; Max-Age=600"
    ))
    .ok()
}

/// The `Set-Cookie` value that removes the debugger state cookie (same path as `debugger_set`).
///
/// Returns `None` if the value is not a valid header value.
pub fn debugger_clear(issuer_id: &str, path: &str) -> Option<HeaderValue> {
    let path = cookie_path(path);
    let name = debugger_name(issuer_id);
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
    fn login_view_clear_uses_the_issuer_path() {
        assert_eq!(
            login_view_clear("auth0", "/auth0/").unwrap(),
            "fauxidc_login_view_auth0=; Path=/auth0; SameSite=Lax; Max-Age=0"
        );
        assert!(
            login_view_clear("r", "/")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("Path=/;")
        );
        assert_eq!(login_view_name("auth0"), "fauxidc_login_view_auth0");
        assert_eq!(login_view_path("/auth0/"), "/auth0");
        assert_eq!(login_view_path("/"), "/");
    }

    #[test]
    fn read_login_view_accepts_list_and_form_only() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, HeaderValue::try_from(value).unwrap());
            headers
        };
        let read = |value: &str| read_login_view(&with(value), "auth0");
        assert_eq!(read("fauxidc_login_view_auth0=list"), Some(true));
        assert_eq!(read("a=b; fauxidc_login_view_auth0=form"), Some(false));
        assert_eq!(read("fauxidc_login_view_auth0=xyz"), None);
        assert_eq!(read("fauxidc_login_view_other=list"), None);
        assert_eq!(read_login_view(&HeaderMap::new(), "auth0"), None);
    }

    #[test]
    fn debugger_cookie_uses_the_debugger_path() {
        assert_eq!(
            debugger_set("auth0", "/auth0/debugger", "st").unwrap(),
            "fauxidc_debugger_auth0=st; Path=/auth0/debugger; HttpOnly; SameSite=Lax; Max-Age=600"
        );
        assert_eq!(
            debugger_clear("auth0", "/auth0/v1/debug/").unwrap(),
            "fauxidc_debugger_auth0=; Path=/auth0/v1/debug; HttpOnly; SameSite=Lax; Max-Age=0"
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
