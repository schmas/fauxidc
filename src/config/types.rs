//! Configuration types and their defaults.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A JSON object of claims.
pub type Claims = serde_json::Map<String, serde_json::Value>;

/// Root configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    pub issuer: BTreeMap<String, IssuerConfig>,
    pub client: BTreeMap<String, ClientConfig>,
    pub user: BTreeMap<String, UserConfig>,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// Server-wide settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub port: u16,
    pub bind: String,
    pub public_base_url: String,
    pub trust_forwarded_headers: bool,
    pub key_file: String,
    pub templates_dir: String,
    pub static_dir: String,
    pub log_format: LogFormat,
    pub request_log_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 9000,
            bind: "127.0.0.1".to_owned(),
            public_base_url: String::new(),
            trust_forwarded_headers: false,
            key_file: String::new(),
            templates_dir: String::new(),
            static_dir: String::new(),
            log_format: LogFormat::default(),
            request_log_size: 500,
        }
    }
}

/// One issuer (a mounted OIDC provider).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IssuerConfig {
    pub issuer_url: String,
    pub public_base_url: String,
    pub lenient: bool,
    pub auto_login: bool,
    pub require_nonce: bool,
    pub sub_template: String,
    pub default_claims: Claims,
    pub login_template: String,
    pub lifetimes: Lifetimes,
    pub paths: EndpointPaths,
    pub logout_param_aliases: BTreeMap<String, String>,
}

/// The endpoints of an Issuer that have a configurable path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    Authorize,
    Token,
    Userinfo,
    Jwks,
    Endsession,
    Introspect,
    Revoke,
    Debugger,
}

impl Endpoint {
    /// The config key of this endpoint under `paths`.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Endpoint::Authorize => "authorize",
            Endpoint::Token => "token",
            Endpoint::Userinfo => "userinfo",
            Endpoint::Jwks => "jwks",
            Endpoint::Endsession => "endsession",
            Endpoint::Introspect => "introspect",
            Endpoint::Revoke => "revoke",
            Endpoint::Debugger => "debugger",
        }
    }
}

/// Endpoint paths below the Issuer path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointPaths {
    pub authorize: String,
    pub token: String,
    pub userinfo: String,
    pub jwks: String,
    pub endsession: String,
    pub introspect: String,
    pub revoke: String,
    /// Routed in M3; the key is accepted and validated now.
    pub debugger: String,
}

impl Default for EndpointPaths {
    fn default() -> Self {
        Self {
            authorize: "/authorize".to_owned(),
            token: "/token".to_owned(),
            userinfo: "/userinfo".to_owned(),
            jwks: "/jwks".to_owned(),
            endsession: "/endsession".to_owned(),
            introspect: "/introspect".to_owned(),
            revoke: "/revoke".to_owned(),
            debugger: "/debugger".to_owned(),
        }
    }
}

impl EndpointPaths {
    /// The path of `e`.
    #[must_use]
    pub fn get(&self, e: Endpoint) -> &str {
        match e {
            Endpoint::Authorize => &self.authorize,
            Endpoint::Token => &self.token,
            Endpoint::Userinfo => &self.userinfo,
            Endpoint::Jwks => &self.jwks,
            Endpoint::Endsession => &self.endsession,
            Endpoint::Introspect => &self.introspect,
            Endpoint::Revoke => &self.revoke,
            Endpoint::Debugger => &self.debugger,
        }
    }

    /// All eight (endpoint, path) pairs in the order of the enum.
    #[must_use]
    pub fn all(&self) -> [(Endpoint, &str); 8] {
        [
            Endpoint::Authorize,
            Endpoint::Token,
            Endpoint::Userinfo,
            Endpoint::Jwks,
            Endpoint::Endsession,
            Endpoint::Introspect,
            Endpoint::Revoke,
            Endpoint::Debugger,
        ]
        .map(|e| (e, self.get(e)))
    }
}

/// Token and code lifetimes in seconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lifetimes {
    pub id_token: u64,
    pub access_token: u64,
    pub refresh_token: u64,
    pub code: u64,
}

impl Default for Lifetimes {
    fn default() -> Self {
        Self {
            id_token: 3600,
            access_token: 3600,
            refresh_token: 86400,
            code: 60,
        }
    }
}

/// Per-client lifetime overrides. Unset fields inherit from the issuer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LifetimesOverride {
    pub id_token: Option<u64>,
    pub access_token: Option<u64>,
    pub refresh_token: Option<u64>,
    pub code: Option<u64>,
}

impl Lifetimes {
    /// Returns a copy with every set override field applied.
    #[must_use]
    pub fn with_override(&self, o: &LifetimesOverride) -> Lifetimes {
        Lifetimes {
            id_token: o.id_token.unwrap_or(self.id_token),
            access_token: o.access_token.unwrap_or(self.access_token),
            refresh_token: o.refresh_token.unwrap_or(self.refresh_token),
            code: o.code.unwrap_or(self.code),
        }
    }
}

/// One OAuth client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfig {
    pub issuer: String,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uris: Vec<String>,
    pub post_logout_redirect_uris: Vec<String>,
    pub web_origins: Option<Vec<String>>,
    pub grant_types: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub require_pkce: bool,
    pub rotate_refresh_tokens: bool,
    pub refresh_reuse_leeway_secs: u64,
    pub id_claims: Claims,
    pub access_claims: Claims,
    pub lifetimes: LifetimesOverride,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            issuer: "*".to_owned(),
            client_id: None,
            client_secret: None,
            redirect_uris: Vec::new(),
            post_logout_redirect_uris: Vec::new(),
            web_origins: None,
            grant_types: vec!["authorization_code".to_owned(), "refresh_token".to_owned()],
            scopes: ["openid", "profile", "email", "offline_access"]
                .map(str::to_owned)
                .to_vec(),
            audience: String::new(),
            require_pkce: false,
            rotate_refresh_tokens: true,
            refresh_reuse_leeway_secs: 0,
            id_claims: Claims::new(),
            access_claims: Claims::new(),
            lifetimes: LifetimesOverride::default(),
        }
    }
}

/// One mock user.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserConfig {
    pub label: String,
    pub claims: Claims,
    pub issuer: BTreeMap<String, UserIssuerConfig>,
}

/// Per-issuer claims for a user.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UserIssuerConfig {
    pub claims: Claims,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_toml_gives_defaults() {
        let c: Config = toml::from_str("").unwrap();
        assert_eq!(c.server.port, 9000);
        assert_eq!(c.server.bind, "127.0.0.1");
        assert!(c.issuer.is_empty());
    }

    #[test]
    fn partial_issuer_table_deserializes() {
        let c: Config = toml::from_str("[issuer.a]\nlenient = true").unwrap();
        assert!(c.issuer["a"].lenient);
        assert_eq!(c.issuer["a"].issuer_url, "");
        assert_eq!(c.issuer["a"].lifetimes.code, 60);
    }

    #[test]
    fn unknown_key_is_rejected_with_line() {
        let err = toml::from_str::<Config>("[server]\nprot = 1").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("prot"), "{msg}");
        assert!(msg.contains("line 2"), "{msg}");
    }

    #[test]
    fn client_lifetimes_override_issuer() {
        let l = Lifetimes::default().with_override(&LifetimesOverride {
            code: Some(5),
            ..Default::default()
        });
        assert_eq!((l.code, l.id_token), (5, 3600));
    }

    #[test]
    fn endpoint_paths_defaults_and_override() {
        let c: Config = toml::from_str("[issuer.a]\npaths = { token = \"/oauth/token\" }").unwrap();
        let p = &c.issuer["a"].paths;
        assert_eq!(p.get(Endpoint::Token), "/oauth/token");
        assert_eq!(p.get(Endpoint::Endsession), "/endsession");
        assert_eq!(p.all().len(), 8);
    }

    #[test]
    fn unknown_paths_key_is_rejected() {
        assert!(toml::from_str::<Config>("[issuer.a]\npaths = { tokn = \"/t\" }").is_err());
    }
}
