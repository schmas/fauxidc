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
pub mod config;
pub mod cookies;
pub mod discovery;
pub mod endsession;
pub mod error;
pub mod health;
pub mod healthcheck;
pub mod issuer;
pub mod jwks;
pub mod keys;
pub mod logging;
pub mod refresh;
pub mod revoke;
pub mod router;
pub mod server;
pub mod state;
pub mod templates;
pub mod token_check;
pub mod token_endpoint;
pub mod tokens;
pub mod userinfo;

pub use server::{RunningServer, Server, StartOptions};
