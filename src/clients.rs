//! Client lookup, redirect URI matching and the Strict and Lenient checks.

use axum::http::{HeaderMap, Uri};

use crate::config::ClientConfig;
use crate::state::IssuerCtx;

/// A client found by `find_client` or created by `register_lenient`.
#[derive(Debug, Clone)]
pub struct ResolvedClient {
    /// The config key, or the `client_id` for a Lenient registration.
    pub key: String,
    pub client_id: String,
    pub config: ClientConfig,
    pub lenient_registered: bool,
    /// `true` for the built-in `debugger` Client.
    pub builtin: bool,
}

impl ResolvedClient {
    /// A public client has no secret, no `jwks` and no `jwks_uri`.
    pub fn is_public(&self) -> bool {
        self.config.client_secret.is_none() && !self.has_keys()
    }

    /// `true` if the Client has a `jwks` or a `jwks_uri` for `private_key_jwt`.
    pub fn has_keys(&self) -> bool {
        self.config.jwks.is_some() || !self.config.jwks_uri.is_empty()
    }
}

/// Finds a configured client for this issuer, else a Lenient registration when the Issuer
/// is Lenient now.
pub fn find_client(ctx: &IssuerCtx, client_id: &str) -> Option<ResolvedClient> {
    let configured = ctx.app.config.client.iter().find(|(key, c)| {
        c.client_id.as_deref().unwrap_or(key) == client_id
            && (c.issuer == "*" || c.issuer == ctx.id)
    });
    if let Some((key, config)) = configured {
        return Some(ResolvedClient {
            key: key.clone(),
            client_id: client_id.to_owned(),
            config: config.clone(),
            lenient_registered: false,
            builtin: false,
        });
    }
    // A reload can turn the Issuer to Strict while the Store keeps its Lenient
    // registrations; Strict mode must not see them.
    if ctx.issuer().lenient {
        let store = ctx
            .app
            .store
            .lenient_clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(config) = store.get(&(ctx.id.clone(), client_id.to_owned())) {
            return Some(ResolvedClient {
                key: client_id.to_owned(),
                client_id: client_id.to_owned(),
                config: config.clone(),
                lenient_registered: true,
                builtin: false,
            });
        }
    }
    (client_id == BUILTIN_DEBUGGER).then(|| builtin_debugger(ctx))
}

/// The `client_id` of the built-in debugger Client.
pub const BUILTIN_DEBUGGER: &str = "debugger";

/// The built-in public Client of an Issuer: grant `authorization_code`, PKCE required, default
/// scopes, no `redirect_uris` (the redirect rule is [`debugger_redirect_ok`]).
pub fn builtin_debugger(ctx: &IssuerCtx) -> ResolvedClient {
    ResolvedClient {
        key: BUILTIN_DEBUGGER.to_owned(),
        client_id: BUILTIN_DEBUGGER.to_owned(),
        config: ClientConfig {
            issuer: ctx.id.clone(),
            client_id: Some(BUILTIN_DEBUGGER.to_owned()),
            grant_types: vec!["authorization_code".to_owned()],
            redirect_uris: Vec::new(),
            require_pkce: true,
            ..ClientConfig::default()
        },
        lenient_registered: false,
        builtin: true,
    }
}

/// `true` only for exactly `endpoint_url(headers, Debugger)` without a trailing `/`, plus
/// `/callback`: the URL that `{debugger}/start` builds for this request (plan Ruling 5). It
/// uses `public_base_url` when that is set, else the request host.
pub fn debugger_redirect_ok(ctx: &IssuerCtx, headers: &HeaderMap, redirect_uri: &str) -> bool {
    let wanted = format!(
        "{}/callback",
        ctx.endpoint_url(headers, crate::config::Endpoint::Debugger)
            .trim_end_matches('/')
    );
    redirect_uri == wanted
}

/// Registers an unknown client as a public client (Lenient mode).
///
/// The first `redirect_uri` is the only registered one. Later requests with
/// another `redirect_uri` only log a warning.
pub fn register_lenient(ctx: &IssuerCtx, client_id: &str, redirect_uri: &str) -> ResolvedClient {
    let config = ClientConfig {
        issuer: ctx.id.clone(),
        client_id: Some(client_id.to_owned()),
        redirect_uris: vec![redirect_uri.to_owned()],
        ..ClientConfig::default()
    };
    ctx.app
        .store
        .lenient_clients
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert((ctx.id.clone(), client_id.to_owned()), config.clone());
    ResolvedClient {
        key: client_id.to_owned(),
        client_id: client_id.to_owned(),
        config,
        lenient_registered: true,
        builtin: false,
    }
}

/// Matches a redirect URI against a registered one.
///
/// A match is exact, or a wildcard when `registered` ends with `/*`. A wildcard
/// stands for exactly one non-empty last path segment, with no query or fragment.
pub fn redirect_uri_matches(registered: &str, actual: &str) -> bool {
    if registered == actual {
        return true;
    }
    let Some(prefix) = registered.strip_suffix('*') else {
        return false;
    };
    if !prefix.ends_with('/') {
        return false;
    }
    let (Ok(reg), Ok(act)) = (prefix.parse::<Uri>(), actual.parse::<Uri>()) else {
        return false;
    };
    if act.query().is_some() || actual.contains(['?', '#']) {
        return false;
    }
    if reg.scheme() != act.scheme() || reg.host() != act.host() || reg.port_u16() != act.port_u16()
    {
        return false;
    }
    if act.authority().is_some_and(|a| a.as_str().contains('@')) {
        return false;
    }
    act.path()
        .strip_prefix(reg.path())
        .is_some_and(|last| !last.is_empty() && !last.contains('/'))
}

impl IssuerCtx {
    /// Applies one check rule.
    ///
    /// A passed check is `Ok`. A failed check logs the rule. Lenient mode logs a
    /// warning and continues. Strict mode logs at info level and returns the rule.
    pub fn enforce(&self, passed: bool, rule: impl FnOnce() -> String) -> Result<(), String> {
        if passed {
            return Ok(());
        }
        let rule = rule();
        if self.issuer().lenient {
            tracing::warn!(issuer = %self.id, "lenient: {rule}");
            Ok(())
        } else {
            tracing::info!(issuer = %self.id, "{rule}");
            Err(rule)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_ctx;

    #[test]
    fn redirect_matching() {
        let r = "http://localhost:3000/api/auth/callback/*";
        assert!(redirect_uri_matches(
            r,
            "http://localhost:3000/api/auth/callback/auth0"
        ));
        assert!(!redirect_uri_matches(
            r,
            "http://localhost:3000/api/auth/callback/"
        ));
        assert!(!redirect_uri_matches(
            r,
            "http://localhost:3000/api/auth/callback/a/b"
        ));
        assert!(!redirect_uri_matches(
            r,
            "http://localhost:3001/api/auth/callback/auth0"
        ));
        assert!(!redirect_uri_matches(
            r,
            "https://localhost:3000/api/auth/callback/auth0"
        ));
        assert!(!redirect_uri_matches(
            r,
            "http://evil.example.com/api/auth/callback/auth0"
        ));
        assert!(!redirect_uri_matches(
            r,
            "http://localhost:3000/api/auth/callback/auth0?x=1"
        ));
        assert!(redirect_uri_matches(
            "http://localhost:5173/cb",
            "http://localhost:5173/cb"
        ));
        assert!(!redirect_uri_matches(
            "http://localhost:5173/cb",
            "http://localhost:5173/cb/"
        ));
    }

    #[test]
    fn find_client_respects_issuer_and_default_id() {
        let ctx = test_ctx(
            "[issuer.a]\nissuer_url=\"http://h/a\"\n[issuer.b]\nissuer_url=\"http://h/b\"\n\
        [client.example_app]\nclient_id=\"example-app\"\n[client.only_b]\nissuer=\"b\"\n",
            "a",
        );
        assert_eq!(find_client(&ctx, "example-app").unwrap().key, "example_app");
        assert!(find_client(&ctx, "example_app").is_none());
        assert!(find_client(&ctx, "only_b").is_none());
    }

    #[test]
    fn debugger_redirect_rule() {
        let ctx = test_ctx(
            "[issuer.auth0]\nissuer_url=\"http://localhost:9000/auth0/\"\n[issuer.okta]\nissuer_url=\"http://localhost:9000/okta\"\n",
            "auth0",
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            axum::http::HeaderValue::from_static("localhost:9000"),
        );
        assert!(debugger_redirect_ok(
            &ctx,
            &headers,
            "http://localhost:9000/auth0/debugger/callback"
        ));
        for bad in [
            "https://fauxidc/auth0/debugger/callback",
            "http://evil.example.com/auth0/debugger/callback",
            "https://localhost:9000/auth0/debugger/callback",
            "http://localhost:9000/auth0/debugger/callback?x=1",
            "http://localhost:9000/auth0/debugger/callback#x",
            "http://localhost:9000/auth0/debugger/callbackx",
            "http://localhost:9000/okta/debugger/callback",
            "ftp://localhost:9000/auth0/debugger/callback",
            "http://u@localhost:9000/auth0/debugger/callback",
            "/auth0/debugger/callback",
        ] {
            assert!(!debugger_redirect_ok(&ctx, &headers, bad), "{bad}");
        }
    }

    #[test]
    fn builtin_debugger_is_the_fallback() {
        let ctx = test_ctx("[issuer.a]\nissuer_url=\"http://h/a\"\n", "a");
        let c = find_client(&ctx, BUILTIN_DEBUGGER).unwrap();
        assert!(c.builtin && c.is_public() && c.config.require_pkce);
        let ctx = test_ctx(
            "[issuer.a]\nissuer_url=\"http://h/a\"\n[client.debugger]\nredirect_uris=[\"http://x/cb\"]\n",
            "a",
        );
        assert!(!find_client(&ctx, BUILTIN_DEBUGGER).unwrap().builtin);
    }

    #[test]
    fn enforce_strict_vs_lenient() {
        let strict = test_ctx("[issuer.a]\nissuer_url=\"http://h/a\"\n", "a");
        assert_eq!(strict.enforce(false, || "rule".into()), Err("rule".into()));
        let lenient = test_ctx("[issuer.a]\nissuer_url=\"http://h/a\"\nlenient=true\n", "a");
        assert!(lenient.enforce(false, || "rule".into()).is_ok());
    }

    #[test]
    fn register_lenient_stores_public_client() {
        let ctx = test_ctx("[issuer.a]\nissuer_url=\"http://h/a\"\nlenient=true\n", "a");
        assert!(find_client(&ctx, "new-app").is_none());
        let c = register_lenient(&ctx, "new-app", "http://localhost:1/cb");
        assert!(c.is_public() && c.lenient_registered);
        let found = find_client(&ctx, "new-app").unwrap();
        assert_eq!(found.config.redirect_uris, vec!["http://localhost:1/cb"]);
    }
}
