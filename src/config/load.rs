//! Loading and merging of all configuration layers.

use super::types::LogFormat;

/// Settings given as command-line flags.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOverrides {
    pub port: Option<u16>,
    pub bind: Option<String>,
    pub log_format: Option<LogFormat>,
}
