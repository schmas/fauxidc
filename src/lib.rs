//! fauxidc: a small OAuth 2.0 / OpenID Connect mock server for local development and tests.
//!
//! The library API is unstable before 1.0.
#![forbid(unsafe_code)]

pub mod clients;
pub mod config;
pub mod discovery;
pub mod error;
pub mod issuer;
pub mod jwks;
pub mod keys;
pub mod router;
pub mod server;
pub mod state;
pub mod templates;

pub use server::{RunningServer, Server, StartOptions};
