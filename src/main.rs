#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use clap::Parser;
use fauxidc::cli::{Cli, Command};
use fauxidc::config::{self, LoadInputs, Loaded};
use fauxidc::error::StartError;
use fauxidc::reload::{POLL_INTERVAL, on_sighup, watch_files};
use fauxidc::{Server, StartOptions, healthcheck, logging};

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
    // Taken before the load: a file saved during the load is reloaded at the first poll.
    let loaded_at = SystemTime::now();
    match (cli.command, config::load(&inputs)) {
        // A config error never fails the healthcheck: it falls back to the default port.
        (Some(Command::Healthcheck { url }), loaded) => {
            let port = loaded.map_or(DEFAULT_PORT, |loaded| loaded.config.server.port);
            let url = url.unwrap_or_else(|| format!("http://127.0.0.1:{port}/_mock/health"));
            match healthcheck::check(&url, Duration::from_secs(2)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(message) => {
                    eprintln!("healthcheck failed: {message}");
                    Ok(ExitCode::from(1))
                }
            }
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
        (None, Ok(loaded)) => serve(loaded, &inputs, loaded_at).await,
    }
}

async fn serve(
    loaded: Loaded,
    inputs: &LoadInputs,
    loaded_at: SystemTime,
) -> anyhow::Result<ExitCode> {
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
    let files = loaded.files;
    // Install the stop handlers before the server logs `listening`: a signal that follows the
    // log line must stop the server cleanly, not kill it.
    let stop = stop_signal().context("cannot wait for a signal")?;
    let server = match Server::start_with(loaded.config, options).await {
        Ok(server) => server,
        Err(error) => {
            eprintln!("error: {error}");
            return Ok(match error {
                StartError::Bind(_) => ExitCode::from(1),
                StartError::Key(_)
                | StartError::Config(_)
                | StartError::Templates(_)
                | StartError::Tls(_) => ExitCode::from(2),
            });
        }
    };
    // Env and inline values stay as at startup (spec 11): reloads reuse `inputs`.
    let handle = server.reload_handle();
    if !files.is_empty() {
        watch_files(
            handle.clone(),
            inputs.clone(),
            files,
            POLL_INTERVAL,
            loaded_at,
        );
    }
    if let Err(error) = on_sighup(handle, inputs.clone()) {
        tracing::warn!("cannot listen for SIGHUP: {error}; reload on SIGHUP is off");
    }
    stop.await.context("cannot wait for a signal")?;
    tracing::info!("shutting down");
    server.shutdown().await.context("shutdown failed")?;
    Ok(ExitCode::SUCCESS)
}

/// Registers the handlers for Ctrl-C and SIGTERM now and returns the future that waits for
/// either one.
fn stop_signal() -> std::io::Result<impl std::future::Future<Output = std::io::Result<()>>> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        Ok(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = int.recv() => {}
            }
            Ok(())
        })
    }
    #[cfg(not(unix))]
    {
        Ok(tokio::signal::ctrl_c())
    }
}
