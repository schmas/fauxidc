//! fauxidc: a small OAuth 2.0 / OpenID Connect mock server for local development and tests.
//!
//! The library API is unstable before 1.0.
#![forbid(unsafe_code)]

pub mod authorize;
pub mod claims;
pub mod cli;
pub mod client_auth;
pub mod client_credentials;
pub mod clients;
pub mod clients_admin;
pub mod clients_api;
pub mod clients_cli;
pub mod clock;
pub mod config;
pub mod config_api;
pub mod cookies;
pub mod cors;
pub mod debugger;
pub mod discovery;
pub mod endsession;
pub mod error;
pub mod failures;
pub mod health;
pub mod healthcheck;
pub mod introspect;
pub mod issuer;
pub mod jwks;
pub mod jwks_fetch;
pub mod jwt_bearer;
pub mod keys;
pub mod logging;
pub mod prompt;
pub mod refresh;
pub mod reload;
pub mod request_log;
pub mod revoke;
pub mod router;
pub mod server;
pub mod session;
pub mod state;
pub mod templates;
pub mod test_api;
#[cfg(feature = "tls")]
pub mod tls;
pub mod token_check;
pub mod token_endpoint;
pub mod token_exchange;
pub mod tokens;
pub mod userinfo;
pub mod users;
pub mod users_api;
pub mod users_cli;

pub use server::{RunningServer, Server, StartOptions};
