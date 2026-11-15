//! Client lookup, redirect URI matching and the Strict and Lenient checks.

use axum::http::Uri;

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

/// Finds a configured client for this issuer, else a Lenient registration.
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
        });
    }
    let store = ctx
        .app
        .store
        .lenient_clients
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    store
        .get(&(ctx.id.clone(), client_id.to_owned()))
        .map(|config| ResolvedClient {
            key: client_id.to_owned(),
            client_id: client_id.to_owned(),
            config: config.clone(),
            lenient_registered: true,
        })
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
