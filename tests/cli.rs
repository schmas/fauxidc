use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

fn fauxidc_cmd(args: &[&str]) -> Command {
    let dir = std::env::temp_dir().join(format!("fauxidc-cli-cwd-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fauxidc"));
    cmd.args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default());
    cmd
}

fn write_tmp(text: &str) -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "fauxidc-cli-{}-{}.toml",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::write(&path, text).unwrap();
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_port(port: u16, timeout: Duration) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(start.elapsed() < timeout, "port {port} did not open");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn send_sigterm(child: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn wait_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn config_prints_zero_config() {
    let out = fauxidc_cmd(&["config"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(
        s.contains("issuer.default.issuer_url = \"http://localhost:9000/default\"  # default"),
        "{s}"
    );
}

#[test]
fn config_check_reports_all_errors_with_exit_2() {
    let f = write_tmp("[server]\nprot = 1\n");
    let out = fauxidc_cmd(&["config", "--check", "--config", f.to_str().unwrap()])
        .env("FAUXIDC__SERVER__X", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let e = String::from_utf8(out.stderr).unwrap();
    assert!(
        e.contains("prot") && e.contains("env FAUXIDC__SERVER__X"),
        "{e}"
    );
}

#[test]
fn config_check_ok() {
    let out = fauxidc_cmd(&["config", "--check"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(out.stdout, b"");
}

#[test]
fn serve_starts_and_stops_on_sigterm() {
    let port = free_port();
    let mut child = fauxidc_cmd(&["--port", &port.to_string()])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for_port(port, Duration::from_secs(2));
    send_sigterm(&child);
    let status = wait_timeout(&mut child, Duration::from_secs(2)).expect("stopped in time");
    assert!(status.success());
}

#[test]
fn bind_failure_exits_1() {
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    let out = fauxidc_cmd(&["--port", &port.to_string()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn healthcheck_against_running_server() {
    let port = free_port();
    let mut child = fauxidc_cmd(&["--port", &port.to_string()]).spawn().unwrap();
    wait_for_port(port, Duration::from_secs(2));
    assert!(
        fauxidc_cmd(&["healthcheck", "--port", &port.to_string()])
            .status()
            .unwrap()
            .success()
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Starts the binary with a config file made by `config(port)` on a free port and waits for
/// `/_mock/health`. Tries a new port when the child cannot bind (another socket may take the
/// port between `free_port` and the bind).
#[cfg(unix)]
async fn start_with_config(
    client: &reqwest::Client,
    config: impl Fn(u16) -> String,
) -> (Child, u16, PathBuf, String) {
    for _ in 0..5 {
        let port = free_port();
        let text = config(port);
        let file = write_tmp(&text);
        let mut child = fauxidc_cmd(&[
            "--config",
            file.to_str().unwrap(),
            "--port",
            &port.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
        let start = Instant::now();
        loop {
            let health = client
                .get(format!("http://127.0.0.1:{port}/_mock/health"))
                .send()
                .await;
            if health.is_ok() {
                // Drain the logs so a full pipe never blocks the server.
                let mut logs = child.stderr.take().unwrap();
                std::thread::spawn(move || std::io::copy(&mut logs, &mut std::io::sink()));
                return (child, port, file, text);
            }
            if let Some(status) = child.try_wait().unwrap() {
                let mut err = String::new();
                std::io::Read::read_to_string(child.stderr.as_mut().unwrap(), &mut err).unwrap();
                assert!(
                    err.contains("cannot bind"),
                    "server exited with {status}: {err}"
                );
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "server did not start"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    panic!("no free port after 5 tries");
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_config() {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (mut child, port, file, text) = start_with_config(&client, |port| {
        format!(
            "[server]\nport = {port}\n\n[issuer.auth0]\nissuer_url = \"http://localhost:{port}/auth0/\"\n\n[user.alice]\nlabel = \"Alice\"\n\n[user.bob]\nlabel = \"Bob\"\n"
        )
    })
    .await;
    let base = format!("http://127.0.0.1:{port}");
    let old_mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::fs::write(&file, text.replace("[user.bob]", "[user.cob]")).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(old_mtime)
        .unwrap();
    let status = || async {
        client
            .post(format!("{base}/_mock/auth0/token"))
            .json(&serde_json::json!({"user": "cob"}))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    };
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(status().await, 400, "the poller must not see the change");
    let hup = Command::new("kill")
        .args(["-HUP", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(hup.success());
    let start = Instant::now();
    while status().await != 200 {
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "SIGHUP did not reload"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    child.kill().unwrap();
    let _ = child.wait();
}
