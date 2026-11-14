#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use fauxidc::cli::{Cli, Command};
use fauxidc::config::{self, LoadInputs, Loaded};
use fauxidc::error::StartError;
use fauxidc::{Server, StartOptions, logging};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const DEFAULT_PORT: u16 = 9000;
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

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
    let loaded = config::load(&inputs);
    if let Some(Command::Healthcheck { url }) = &cli.command {
        let port = loaded
            .as_ref()
            .map_or(DEFAULT_PORT, |loaded| loaded.config.server.port);
        let url = url
            .clone()
            .unwrap_or_else(|| format!("http://127.0.0.1:{port}/_mock/health"));
        return Ok(healthcheck(&url).await);
    }
    let loaded = match loaded {
        Ok(loaded) => loaded,
        Err(errors) => {
            eprintln!("{errors}");
            return Ok(ExitCode::from(2));
        }
    };
    match cli.command {
        Some(Command::Config { check }) => {
            if !check {
                print!("{}", config::render(&loaded));
            }
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Healthcheck { .. }) => Ok(ExitCode::SUCCESS),
        None => serve(loaded, &inputs).await,
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

/// Exit 0 if `GET url` answers 200. The client speaks plain HTTP/1.1 over TCP, because
/// the image has no TLS and the health endpoint is local.
async fn healthcheck(url: &str) -> ExitCode {
    match tokio::time::timeout(HEALTH_TIMEOUT, fetch_status(url)).await {
        Ok(Ok(200)) => ExitCode::SUCCESS,
        Ok(Ok(status)) => {
            eprintln!("healthcheck failed: status {status}");
            ExitCode::from(1)
        }
        Ok(Err(error)) => {
            eprintln!("healthcheck failed: {error:#}");
            ExitCode::from(1)
        }
        Err(_) => {
            eprintln!("healthcheck failed: timeout");
            ExitCode::from(1)
        }
    }
}

async fn fetch_status(url: &str) -> anyhow::Result<u16> {
    let rest = url
        .strip_prefix("http://")
        .context("only http:// URLs are supported")?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| rest.split_at(i));
    let address = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let mut stream = TcpStream::connect(&address)
        .await
        .with_context(|| format!("cannot connect to {address}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut head = Vec::new();
    stream.take(256).read_to_end(&mut head).await?;
    let head = String::from_utf8_lossy(&head);
    head.split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .context("malformed HTTP response")
}
