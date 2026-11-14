#![forbid(unsafe_code)]

use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use fauxidc::cli::{Cli, Command};
use fauxidc::config::{self, LoadInputs, Loaded};
use fauxidc::error::StartError;
use fauxidc::{Server, StartOptions, logging};

const DEFAULT_PORT: u16 = 9000;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let inputs = LoadInputs::from_process(cli.config.clone(), cli.overrides())
        .context("cannot read the working directory")?;
    match (cli.command, config::load(&inputs)) {
        // A config error never fails the healthcheck: it falls back to the default port.
        (Some(Command::Healthcheck { url: _ }), loaded) => {
            let _port = loaded.map_or(DEFAULT_PORT, |loaded| loaded.config.server.port);
            eprintln!("healthcheck not implemented");
            Ok(ExitCode::from(1))
        }
        (_, Err(errors)) => {
            eprintln!("{errors}");
            Ok(ExitCode::from(2))
        }
        (Some(Command::Config { check }), Ok(loaded)) => {
            if !check {
                print!("{}", config::render(&loaded));
            }
            Ok(ExitCode::SUCCESS)
        }
        (None, Ok(loaded)) => serve(loaded, &inputs).await,
    }
}

async fn serve(loaded: Loaded, inputs: &LoadInputs) -> anyhow::Result<ExitCode> {
    let env = |name: &str| {
        inputs
            .env
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    if let Err(message) = logging::init(
        loaded.config.server.log_format,
        env("FAUXIDC_LOG").as_deref(),
    ) {
        eprintln!("{message}");
        return Ok(ExitCode::from(2));
    }
    if loaded.zero_config {
        tracing::info!("zero config");
    }
    let options = StartOptions {
        key_pem: env("FAUXIDC_KEY_PEM"),
    };
    let server = match Server::start_with(loaded.config, options).await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(match error {
                StartError::Bind(_) => ExitCode::from(1),
                StartError::Key(_) | StartError::Config(_) | StartError::Templates(_) => {
                    ExitCode::from(2)
                }
            });
        }
    };
    wait_for_signal()
        .await
        .context("cannot wait for a signal")?;
    tracing::info!("shutting down");
    server.shutdown().await.context("shutdown failed")?;
    Ok(ExitCode::SUCCESS)
}

async fn wait_for_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}
