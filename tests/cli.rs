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
