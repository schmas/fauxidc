//! Configuration types and their defaults.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A JSON object of claims.
pub type Claims = serde_json::Map<String, serde_json::Value>;

/// Root configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Server-wide settings.
    pub server: ServerConfig,
    /// Issuers by Issuer id (lowercase letters, digits and `_`).
    #[schemars(extend("propertyNames" = {"pattern": "^[a-z0-9_]+$"}))]
    pub issuer: BTreeMap<String, IssuerConfig>,
    /// Clients by key (lowercase letters, digits and `_`).
    #[schemars(extend("propertyNames" = {"pattern": "^[a-z0-9_]+$"}))]
    pub client: BTreeMap<String, ClientConfig>,
    /// Users by key (lowercase letters, digits and `_`).
    #[schemars(extend("propertyNames" = {"pattern": "^[a-z0-9_]+$"}))]
    pub user: BTreeMap<String, UserConfig>,
}

/// Log output format.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// The JWS algorithm an Issuer signs its tokens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub enum SigningAlg {
    #[default]
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
}

impl SigningAlg {
    /// Every algorithm: RSA PKCS#1 v1.5, then RSA-PSS, then ECDSA.
    pub const ALL: [SigningAlg; 8] = [
        SigningAlg::RS256,
        SigningAlg::RS384,
        SigningAlg::RS512,
        SigningAlg::PS256,
        SigningAlg::PS384,
        SigningAlg::PS512,
        SigningAlg::ES256,
        SigningAlg::ES384,
    ];

    /// The JOSE name, for example `"ES256"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            SigningAlg::RS256 => "RS256",
            SigningAlg::RS384 => "RS384",
            SigningAlg::RS512 => "RS512",
            SigningAlg::PS256 => "PS256",
            SigningAlg::PS384 => "PS384",
            SigningAlg::PS512 => "PS512",
            SigningAlg::ES256 => "ES256",
            SigningAlg::ES384 => "ES384",
        }
    }

    /// The `jsonwebtoken` algorithm.
    #[must_use]
    pub fn jwt(self) -> jsonwebtoken::Algorithm {
        use jsonwebtoken::Algorithm;
        match self {
            SigningAlg::RS256 => Algorithm::RS256,
            SigningAlg::RS384 => Algorithm::RS384,
            SigningAlg::RS512 => Algorithm::RS512,
            SigningAlg::PS256 => Algorithm::PS256,
            SigningAlg::PS384 => Algorithm::PS384,
            SigningAlg::PS512 => Algorithm::PS512,
            SigningAlg::ES256 => Algorithm::ES256,
            SigningAlg::ES384 => Algorithm::ES384,
        }
    }

    /// The `SigningAlg` of a `jsonwebtoken` algorithm; `None` for HS256, `EdDSA` and the others.
    #[must_use]
    pub fn from_jwt(alg: jsonwebtoken::Algorithm) -> Option<SigningAlg> {
        SigningAlg::ALL.into_iter().find(|a| a.jwt() == alg)
    }

    /// `true` for the RSA algorithms (RS* and PS*), which use an RSA key.
    #[must_use]
    pub fn is_rsa(self) -> bool {
        !matches!(self, SigningAlg::ES256 | SigningAlg::ES384)
    }
}

/// Server-wide settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// The listening port. Default 9000.
    pub port: u16,
    /// The listening address. Default 127.0.0.1.
    pub bind: String,
    /// The public base URL of the server. Empty: derived from the request.
    pub public_base_url: String,
    /// Trust `X-Forwarded-*` request headers when it builds URLs.
    pub trust_forwarded_headers: bool,
    /// PEM file of the server signing key. Empty: generated, not saved.
    pub key_file: String,
    /// Directory of template overrides. Empty: the built-in templates.
    pub templates_dir: String,
    /// Directory of static file overrides. Empty: the built-in files.
    pub static_dir: String,
    /// The log output format.
    pub log_format: LogFormat,
    /// The number of requests the Request log keeps.
    pub request_log_size: usize,
    /// HTTPS from PEM files. Needs a build with the `tls` feature.
    pub tls: TlsConfig,
    /// A fixed server time, an RFC 3339 date-time such as `2020-01-21T00:00:00Z`. Issued token
    /// times and every token time check use it (ADR 0007). Empty: the system clock.
    pub fixed_time: String,
}

/// `[server.tls]`: the PEM certificate chain and private key of the HTTPS listener.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// PEM certificate chain file.
    pub cert_file: String,
    /// PEM private key file.
    pub key_file: String,
}

impl TlsConfig {
    /// Whether TLS is on: both files are set.
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.cert_file.is_empty() && !self.key_file.is_empty()
    }
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
            tls: TlsConfig::default(),
            fixed_time: String::new(),
        }
    }
}

/// One issuer (a mounted OIDC provider).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // independent TOML switches, not states of one machine
pub struct IssuerConfig {
    /// The issuer URL (the `iss` claim). Empty: derived from the Issuer id.
    pub issuer_url: String,
    /// Take `iss` and the discovery `issuer` from the request host, not from `issuer_url`
    /// (ADR 0006). `issuer_url` still gives the path and the trailing slash.
    pub issuer_from_host: bool,
    /// The public base URL of this Issuer. Empty: the server value.
    pub public_base_url: String,
    /// Lenient mode: skip the strict checks of the authorize and token requests.
    pub lenient: bool,
    /// Auto-select the only User and skip the login page.
    pub auto_login: bool,
    /// Require a `nonce` in authorize requests.
    pub require_nonce: bool,
    /// Template of the `sub` claim. Empty: the User key.
    pub sub_template: String,
    /// Claims added to every token of this Issuer.
    pub default_claims: Claims,
    /// Template file of the login page. Empty: the built-in page.
    pub login_template: String,
    /// Token and code lifetimes of this Issuer.
    pub lifetimes: Lifetimes,
    /// Endpoint paths below the Issuer path.
    pub paths: EndpointPaths,
    /// Extra names for end-session request parameters, alias to standard name.
    pub logout_param_aliases: BTreeMap<String, String>,
    /// The JWS algorithm of this Issuer's tokens.
    pub signing_alg: SigningAlg,
    /// PEM file of this Issuer's own key. Empty: an RS256 Issuer uses the server key, any
    /// other Issuer gets a generated key that is not saved.
    pub key_file: String,
    /// The Custom user template of the login page. None: the subject + JSON fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_user: Option<CustomUserConfig>,
}

/// The placeholder in [`CustomUserConfig::claims`] string values.
pub const USERNAME_PLACEHOLDER: &str = "{username}";

/// `[issuer.<id>.custom_user]`: the Custom user template of the login page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CustomUserConfig {
    /// The dropdown label. Default "Custom…".
    pub label: String,
    /// Claims with `{username}` placeholders in string values.
    pub claims: Claims,
}

impl Default for CustomUserConfig {
    fn default() -> Self {
        Self {
            label: "Custom…".to_owned(),
            claims: Claims::new(),
        }
    }
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct EndpointPaths {
    /// Authorize endpoint path.
    pub authorize: String,
    /// Token endpoint path.
    pub token: String,
    /// Userinfo endpoint path.
    pub userinfo: String,
    /// JWKS endpoint path.
    pub jwks: String,
    /// End-session endpoint path.
    pub endsession: String,
    /// Introspection endpoint path.
    pub introspect: String,
    /// Revocation endpoint path.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Lifetimes {
    /// ID token lifetime in seconds.
    pub id_token: u64,
    /// Access token lifetime in seconds.
    pub access_token: u64,
    /// Refresh token lifetime in seconds.
    pub refresh_token: u64,
    /// Authorization code lifetime in seconds.
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
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LifetimesOverride {
    /// ID token lifetime in seconds.
    pub id_token: Option<u64>,
    /// Access token lifetime in seconds.
    pub access_token: Option<u64>,
    /// Refresh token lifetime in seconds.
    pub refresh_token: Option<u64>,
    /// Authorization code lifetime in seconds.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClientConfig {
    /// The Issuer id this Client belongs to. `*`: every Issuer.
    pub issuer: String,
    /// The client id. Unset: the Client key.
    pub client_id: Option<String>,
    /// The client secret. Unset: a public Client.
    pub client_secret: Option<String>,
    /// Allowed redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Allowed post-logout redirect URIs.
    pub post_logout_redirect_uris: Vec<String>,
    /// Allowed CORS origins. Unset: derived from the redirect URIs.
    pub web_origins: Option<Vec<String>>,
    /// Allowed grant types.
    pub grant_types: Vec<String>,
    /// Allowed scopes.
    pub scopes: Vec<String>,
    /// The `aud` claim of access tokens. Empty: the client id.
    pub audience: String,
    /// Require PKCE in authorize requests.
    pub require_pkce: bool,
    /// Issue a new refresh token at each refresh.
    pub rotate_refresh_tokens: bool,
    /// Seconds in which a rotated refresh token still works.
    pub refresh_reuse_leeway_secs: u64,
    /// Claim overrides for ID tokens.
    pub id_claims: Claims,
    /// Claim overrides for access tokens.
    pub access_claims: Claims,
    /// Lifetime overrides of this Client.
    pub lifetimes: LifetimesOverride,
    /// Inline JWK set for `private_key_jwt` (RFC 7523): `{ keys = [ .. ] }`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Claims>,
    /// `http://` URL of the Client JWK set for `private_key_jwt`. Empty: none.
    pub jwks_uri: String,
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
            jwks: None,
            jwks_uri: String::new(),
        }
    }
}

/// One mock user.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UserConfig {
    /// The label on the login page.
    pub label: String,
    /// Claims of this User in every Issuer.
    pub claims: Claims,
    /// Per-Issuer claims, by Issuer id.
    #[schemars(extend("propertyNames" = {"pattern": "^[a-z0-9_]+$"}))]
    pub issuer: BTreeMap<String, UserIssuerConfig>,
}

/// Per-issuer claims for a user.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UserIssuerConfig {
    /// Claims of this User in this Issuer.
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

    #[test]
    fn custom_user_defaults_its_label() {
        let c: Config = toml::from_str(
            "[issuer.a.custom_user]\nclaims = { email = \"{username}@example.test\" }",
        )
        .unwrap();
        let cu = c.issuer["a"].custom_user.as_ref().unwrap();
        assert_eq!(cu.label, "Custom…");
        assert_eq!(cu.claims["email"], "{username}@example.test");
        assert!(c.issuer["a"].custom_user.is_some());
        let plain: Config = toml::from_str("[issuer.a]").unwrap();
        assert!(plain.issuer["a"].custom_user.is_none());
    }
}
