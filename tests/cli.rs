use std::net::TcpListener;
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
#[cfg(unix)]
fn serve_starts_and_stops_on_sigterm() {
    let (mut child, _addr) = start_server(&[]);
    send_sigterm(&child);
    let status = wait_timeout(&mut child, Duration::from_secs(10)).expect("stopped in time");
    assert!(status.success());
}

/// SIGTERM right after `listening` must not wait for the background key generation: the
/// runtime used to wait for that blocking task when it dropped, which took over a second in a
/// debug build and more on a loaded runner.
#[test]
#[cfg(unix)]
fn sigterm_does_not_wait_for_key_generation() {
    for _ in 0..5 {
        let (mut child, _addr) = start_server(&[]);
        let start = Instant::now();
        send_sigterm(&child);
        let status = wait_timeout(&mut child, Duration::from_secs(10)).expect("stopped");
        let took = start.elapsed();
        assert!(status.success());
        assert!(took < Duration::from_millis(500), "shutdown took {took:?}");
    }
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
#[cfg(unix)]
fn healthcheck_against_running_server() {
    let (mut child, addr) = start_server(&[]);
    let port = addr.rsplit(':').next().unwrap().to_owned();
    assert!(
        fauxidc_cmd(&["healthcheck", "--port", &port])
            .status()
            .unwrap()
            .success()
    );
    child.kill().unwrap();
    child.wait().unwrap();
}

/// Starts the binary with `args` plus `--port 0 --log-format json` and returns the child and
/// the address it bound, read from the JSON `listening` log line. The OS picks the port at the
/// bind, so parallel runs never race for one. The rest of the log is drained so a full pipe
/// never blocks the server.
#[cfg(unix)]
fn start_server(args: &[&str]) -> (Child, String) {
    use std::io::BufRead;
    let mut all: Vec<&str> = args.to_vec();
    all.extend(["--port", "0", "--log-format", "json"]);
    let mut child = fauxidc_cmd(&all)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let logs = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<Result<String, String>>();
    std::thread::spawn(move || {
        let mut tx = Some(tx);
        let mut seen = String::new();
        for line in std::io::BufReader::new(logs).lines() {
            let Ok(line) = line else { break };
            if let Some(sender) = &tx {
                let event: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                if event["fields"]["message"] == "listening" {
                    let addr = event["fields"]["addr"].as_str().unwrap_or_default();
                    let _ = sender.send(Ok(addr.to_owned()));
                    tx = None;
                } else {
                    seen.push_str(&line);
                    seen.push('\n');
                }
            }
        }
        if let Some(sender) = tx {
            let _ = sender.send(Err(seen));
        }
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(addr)) => (child, addr),
        other => {
            let _ = child.kill();
            panic!("server did not start: {other:?}");
        }
    }
}

/// Starts the binary with the config file `text` and returns the child, the bound address and
/// the config path.
#[cfg(unix)]
fn start_with_config(text: &str) -> (Child, String, PathBuf) {
    let file = write_tmp(text);
    let (child, addr) = start_server(&["--config", file.to_str().unwrap()]);
    (child, addr, file)
}

/// Replaces `file` with `text` in one step, with the modification time set to `mtime`: a
/// sibling file gets the text and the time, then a rename puts it in place. The poller never
/// sees a new time.
#[cfg(unix)]
fn replace_keeping_mtime(file: &std::path::Path, text: &str, mtime: std::time::SystemTime) {
    let tmp = file.with_extension("toml.new");
    std::fs::write(&tmp, text).unwrap();
    std::fs::File::options()
        .write(true)
        .open(&tmp)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    std::fs::rename(&tmp, file).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn sighup_reloads_config() {
    let text = "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\n\n[user.alice]\nlabel = \"Alice\"\n\n[user.bob]\nlabel = \"Bob\"\n";
    let (mut child, addr, file) = start_with_config(text);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{addr}");
    let old_mtime = std::fs::metadata(&file).unwrap().modified().unwrap();
    replace_keeping_mtime(&file, &text.replace("[user.bob]", "[user.cob]"), old_mtime);
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

#[cfg(not(feature = "tls"))]
#[test]
fn tls_config_without_the_feature_exits_2() {
    let dir = env!("CARGO_MANIFEST_DIR");
    let f = write_tmp(&format!(
        "[issuer.auth0]\nissuer_url = \"http://localhost:9000/auth0/\"\n\n[server.tls]\n\
         cert_file = \"{dir}/tests/fixtures/tls/cert.pem\"\nkey_file = \"{dir}/tests/fixtures/tls/key.pem\"\n"
    ));
    let out = fauxidc_cmd(&["--config", f.to_str().unwrap(), "--port", "0"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("tls feature"), "{stderr}");
}

#[test]
fn schema_flag_reads_no_config() {
    let dir = std::env::temp_dir().join(format!("fauxidc-cli-schema-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("fauxidc.toml"), "this is = not [valid").unwrap();
    let out = fauxidc_cmd(&["config", "--schema"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/schema/fauxidc.schema.json"
    ))
    .unwrap();
    assert_eq!(String::from_utf8(out.stdout).unwrap(), committed);
}

#[test]
fn schema_conflicts_with_check() {
    let out = fauxidc_cmd(&["config", "--schema", "--check"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
