//! Command-line interface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::{CliOverrides, LogFormat};

#[derive(Parser, Debug)]
#[command(
    name = "fauxidc",
    version,
    about = "OAuth 2.0 / OpenID Connect mock server for local development and tests"
)]
pub struct Cli {
    /// Config file (repeatable, merged in order)
    #[arg(long = "config", value_name = "FILE", global = true)]
    pub config: Vec<PathBuf>,
    #[arg(long, global = true)]
    pub port: Option<u16>,
    #[arg(long, global = true)]
    pub bind: Option<String>,
    #[arg(long, value_enum, global = true)]
    pub log_format: Option<LogFormat>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the merged config with the source of each value
    Config {
        /// Only validate the config
        #[arg(long)]
        check: bool,
        /// Print the JSON Schema of the config file and read no config
        #[arg(long, conflicts_with = "check")]
        schema: bool,
    },
    /// Exit 0 if the server answers /_mock/health with 200
    Healthcheck {
        #[arg(long)]
        url: Option<String>,
    },
}

impl Cli {
    /// The settings given as flags.
    pub fn overrides(&self) -> CliOverrides {
        CliOverrides {
            port: self.port,
            bind: self.bind.clone(),
            log_format: self.log_format,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_become_overrides() {
        let cli = Cli::parse_from(["fauxidc", "--port", "9100", "--log-format", "json"]);
        assert_eq!(
            cli.overrides(),
            CliOverrides {
                port: Some(9100),
                bind: None,
                log_format: Some(LogFormat::Json),
            }
        );
    }

    #[test]
    fn global_flags_work_after_the_subcommand() {
        let cli = Cli::parse_from(["fauxidc", "config", "--check", "--config", "a.toml"]);
        assert_eq!(cli.config, vec![PathBuf::from("a.toml")]);
        assert!(matches!(
            cli.command,
            Some(Command::Config {
                check: true,
                schema: false
            })
        ));
    }
}
