//! Configuration errors that carry the origin of the bad value.

use std::fmt;

use crate::config::Source;

/// One configuration error and where the value came from.
#[derive(Debug, thiserror::Error)]
#[error("{origin}: {message}")]
pub struct ConfigError {
    pub origin: Source,
    pub message: String,
}

/// A list of configuration errors, reported together.
#[derive(Debug)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, error) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{error}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigErrors {}
