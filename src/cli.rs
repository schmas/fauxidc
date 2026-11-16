//! Command-line interface.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::{CliOverrides, LogFormat};

#[derive(Parser, Debug)]
#[command(
    name = "fauxidc",
    version,
    about = "OAuth 2.0 / OpenID Connect mock server for local development and tests",
    // A later --port, --bind or --log-format wins, so `docker run <image> --bind ...`
    // overrides the `--bind 0.0.0.0` of the image entrypoint.
    args_override_self = true
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
    /// Take `iss` from the request host on every Issuer (also `FAUXIDC_ISSUER_FROM_HOST=true`)
    #[arg(long, global = true)]
    pub issuer_from_host: bool,
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
    /// List, show and change the Users of the config file
    ///
    /// Changes go to the last config file and keep its comments. They need no running server:
    /// a running server applies the change with its hot reload. A User that an earlier file,
    /// inline config or an env var sets cannot change. Exit code 2 on invalid input or config,
    /// 1 on a conflict.
    #[command(subcommand)]
    Users(UsersCommand),
    /// List, show and change the Clients of the config file
    ///
    /// A Client is named by its config key ([client.<key>]), not by its `client_id`. Reads mask
    /// `client_secret`. Changes go to the last config file and keep its comments. They need no
    /// running server: a running server applies the change with its hot reload. A Client that an
    /// earlier file, inline config or an env var sets cannot change. Exit code 2 on invalid input
    /// or config, 1 on a conflict.
    #[command(subcommand)]
    Clients(ClientsCommand),
}

/// `fauxidc clients ...`
#[derive(Subcommand, Debug)]
pub enum ClientsCommand {
    /// Print all Clients
    List {
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Print one Client
    Get {
        /// The Client key: lowercase letters, digits and underscores
        client_key: String,
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a Client to the last config file
    Create {
        /// The Client key: lowercase letters, digits and underscores
        client_key: String,
        /// Read the Client from a JSON or TOML file, or `-` for stdin. The same shape as
        /// [client.<key>]
        #[arg(long, value_name = "FILE")]
        from: PathBuf,
    },
    /// Replace a Client in the last config file, or merge into it with --merge
    Update {
        /// The Client key: lowercase letters, digits and underscores
        client_key: String,
        /// Read the Client, or the changes with --merge, from a JSON or TOML file, or `-` for
        /// stdin
        #[arg(long, value_name = "FILE")]
        from: PathBuf,
        /// Merge into the Client (JSON Merge Patch, RFC 7396) instead of replacing it
        #[arg(long)]
        merge: bool,
    },
    /// Remove a Client from the last config file
    Delete {
        /// The Client key
        client_key: String,
    },
}

/// `fauxidc users ...`
#[derive(Subcommand, Debug)]
pub enum UsersCommand {
    /// Print all Users
    List {
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Print one User
    Get {
        /// The User id: lowercase letters, digits and underscores
        user_id: String,
        /// Print JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a User to the last config file
    Create {
        /// The User id: lowercase letters, digits and underscores
        user_id: String,
        #[command(flatten)]
        fields: UserFields,
    },
    /// Replace a User in the last config file, or merge into it with --merge
    Update {
        /// The User id: lowercase letters, digits and underscores
        user_id: String,
        #[command(flatten)]
        fields: UserFields,
        /// Merge into the User (JSON Merge Patch, RFC 7396) instead of replacing it
        #[arg(long)]
        merge: bool,
    },
    /// Remove a User from the last config file
    Delete {
        /// The User id
        user_id: String,
    },
}

/// The fields of a User. `--from` is read first; the other flags change its values.
#[derive(clap::Args, Debug, Default, Clone)]
pub struct UserFields {
    /// The label on the login page
    #[arg(long)]
    pub label: Option<String>,
    /// Claims as a JSON object, for example '{"email": "carol@example.com"}'
    #[arg(long, value_name = "JSON")]
    pub claims: Option<String>,
    /// Claims for one Issuer, for example auth0='{"org": "o-1"}' (repeatable)
    #[arg(long, value_name = "ISSUER_ID=JSON")]
    pub issuer_claims: Vec<String>,
    /// Read the User from a JSON or TOML file, or `-` for stdin. The same shape as [user.<id>]
    #[arg(long, value_name = "FILE")]
    pub from: Option<PathBuf>,
}

impl Cli {
    /// The settings given as flags.
    pub fn overrides(&self) -> CliOverrides {
        CliOverrides {
            port: self.port,
            bind: self.bind.clone(),
            log_format: self.log_format,
            issuer_from_host: self.issuer_from_host,
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
                issuer_from_host: false,
            }
        );
    }

    /// The image entrypoint passes `--bind 0.0.0.0`; a user flag after it wins, and
    /// `--config` still appends.
    #[test]
    fn a_later_flag_overrides_an_earlier_one() {
        let cli = Cli::parse_from([
            "fauxidc",
            "--bind",
            "0.0.0.0",
            "--config",
            "a.toml",
            "--bind",
            "127.0.0.1",
            "--config",
            "b.toml",
        ]);
        assert_eq!(cli.bind.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            cli.config,
            vec![PathBuf::from("a.toml"), PathBuf::from("b.toml")]
        );
    }

    #[test]
    fn issuer_from_host_flag() {
        let cli = Cli::parse_from(["fauxidc", "--issuer-from-host"]);
        assert!(cli.overrides().issuer_from_host);
        assert!(!Cli::parse_from(["fauxidc"]).overrides().issuer_from_host);
    }

    #[test]
    fn users_commands_parse() {
        let cli = Cli::parse_from([
            "fauxidc",
            "users",
            "update",
            "carol",
            "--label",
            "Carol",
            "--issuer-claims",
            "a={}",
            "--issuer-claims",
            "b={}",
            "--merge",
            "--config",
            "a.toml",
        ]);
        assert_eq!(cli.config, vec![PathBuf::from("a.toml")]);
        let Some(Command::Users(UsersCommand::Update {
            user_id,
            fields,
            merge: true,
        })) = cli.command
        else {
            panic!("not users update --merge");
        };
        assert_eq!(user_id, "carol");
        assert_eq!(fields.label.as_deref(), Some("Carol"));
        assert_eq!(fields.issuer_claims, ["a={}", "b={}"]);
    }

    #[test]
    fn clients_commands_parse() {
        let cli = Cli::parse_from([
            "fauxidc", "clients", "update", "web", "--from", "-", "--merge",
        ]);
        let Some(Command::Clients(ClientsCommand::Update {
            client_key,
            from,
            merge: true,
        })) = cli.command
        else {
            panic!("not clients update --merge");
        };
        assert_eq!(client_key, "web");
        assert_eq!(from, PathBuf::from("-"));
        assert!(Cli::try_parse_from(["fauxidc", "clients", "create", "web"]).is_err());
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
