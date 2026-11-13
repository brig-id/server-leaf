// Integration tests for the `seedling` binary's startup/shutdown behaviour
// (phase-3 "seedling binary validation" checklist). These spawn the actual
// compiled binary as a subprocess rather than calling library functions
// directly, since the behaviour under test (CLI parsing, env handling,
// process exit codes, signal handling) only exists at that boundary.

mod common;

use std::{
    net::{SocketAddr, TcpListener},
    process::{Command, Stdio},
    time::Duration,
};

use common::{TEST_MASTER_KEY, free_port, seedling_bin, wait_until_listening};

fn output_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// 1. Startup without BRIGID_MASTER_KEY
// ---------------------------------------------------------------------------

#[test]
fn missing_master_key_fails_with_readable_message() {
    let output = Command::new(seedling_bin())
        .env_remove("BRIGID_MASTER_KEY")
        .env_remove("BRIGID_MASTER_KEY_FILE")
        .env("BRIGID_SERVER__DOMAIN", "localhost")
        .env("BRIGID_DATABASE__PATH", ":memory:")
        .output()
        .expect("spawn seedling");

    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = output_text(&output.stderr);
    assert!(
        stderr.contains("BRIGID_MASTER_KEY"),
        "stderr should mention BRIGID_MASTER_KEY, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// 2. --config pointing to a missing file
// ---------------------------------------------------------------------------

#[test]
fn missing_config_file_fails_with_clear_message() {
    let missing_path = "/nonexistent/seedling-test-config-does-not-exist.toml";
    let output = Command::new(seedling_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .arg("--config")
        .arg(missing_path)
        .output()
        .expect("spawn seedling");

    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = output_text(&output.stderr);
    assert!(
        stderr.contains("config file not found") && stderr.contains(missing_path),
        "stderr should clearly name the missing path, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// 3. Valid config + MASTER_KEY → listens on the configured port
// ---------------------------------------------------------------------------

#[test]
fn valid_config_listens_on_configured_port() {
    let port = free_port();
    let mut child = Command::new(seedling_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("BRIGID_SERVER__DOMAIN", "localhost")
        .env("BRIGID_SERVER__HOST", "127.0.0.1")
        .env("BRIGID_SERVER__PORT", port.to_string())
        .env("BRIGID_DATABASE__PATH", ":memory:")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn seedling");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listening = wait_until_listening(addr, Duration::from_secs(5));

    child.kill().ok();
    child.wait().ok();

    assert!(listening, "seedling did not start listening on port {port}");
}

// ---------------------------------------------------------------------------
// 4. Graceful shutdown (SIGTERM) → DB not corrupted, exit 0
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_on_sigterm_exits_cleanly() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db_path = dir.path().join("seedling-shutdown-test.db");
    let port = free_port();

    let mut child = Command::new(seedling_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("BRIGID_SERVER__DOMAIN", "localhost")
        .env("BRIGID_SERVER__HOST", "127.0.0.1")
        .env("BRIGID_SERVER__PORT", port.to_string())
        .env("BRIGID_DATABASE__PATH", db_path.display().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn seedling");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(
        wait_until_listening(addr, Duration::from_secs(5)),
        "seedling did not start listening before SIGTERM"
    );

    // Send a real SIGTERM (Child::kill() only sends SIGKILL on Unix) so the
    // graceful-shutdown path in main.rs actually runs.
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM");
    assert!(status.success(), "kill -TERM failed to send the signal");

    let exit = child.wait().expect("wait for seedling to exit");
    assert!(
        exit.success(),
        "expected clean exit (0) after SIGTERM, got {exit:?}"
    );

    // Re-opening (and migrating) the same encrypted store with the same
    // master key is the real proof the on-disk database isn't corrupted —
    // a truncated/torn write would fail here.
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());
    let master = brigid_crypto::MasterKey::from_hex(TEST_MASTER_KEY).expect("parse master key");
    brigid_store::EncryptedStore::new(&db_url, master)
        .await
        .expect("re-opening the DB after graceful shutdown should succeed");
}

// ---------------------------------------------------------------------------
// 5. Port already in use → non-zero exit + clear message
// ---------------------------------------------------------------------------

#[test]
fn port_already_in_use_fails_with_clear_message() {
    // Hold the port open ourselves so seedling's bind fails.
    let holder = TcpListener::bind("127.0.0.1:0").expect("bind holder");
    let port = holder.local_addr().unwrap().port();

    let output = Command::new(seedling_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("BRIGID_SERVER__DOMAIN", "localhost")
        .env("BRIGID_SERVER__HOST", "127.0.0.1")
        .env("BRIGID_SERVER__PORT", port.to_string())
        .env("BRIGID_DATABASE__PATH", ":memory:")
        .output()
        .expect("spawn seedling");

    drop(holder);

    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = output_text(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("address already in use") || stderr.contains("AddrInUse"),
        "stderr should clearly indicate the port conflict, got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// `seedling healthcheck` (Docker HEALTHCHECK) and the internal metrics listener
// ---------------------------------------------------------------------------

fn http_get(addr: SocketAddr, path: &str) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn healthcheck_fails_when_nothing_listens() {
    let status = Command::new(seedling_bin())
        .args(["healthcheck", "--port", &free_port().to_string()])
        .stderr(Stdio::null())
        .status()
        .expect("run healthcheck");
    assert_eq!(status.code(), Some(1));
}

#[test]
fn healthcheck_passes_and_metrics_count_requests() {
    let port = free_port();
    let metrics_port = free_port();
    let mut child = Command::new(seedling_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("BRIGID_SERVER__DOMAIN", "localhost")
        .env("BRIGID_SERVER__HOST", "127.0.0.1")
        .env("BRIGID_SERVER__PORT", port.to_string())
        .env("BRIGID_SERVER__METRICS_PORT", metrics_port.to_string())
        .env("BRIGID_DATABASE__PATH", ":memory:")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn seedling");
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let metrics_addr: SocketAddr = format!("127.0.0.1:{metrics_port}").parse().unwrap();
    assert!(wait_until_listening(addr, Duration::from_secs(5)));
    assert!(wait_until_listening(metrics_addr, Duration::from_secs(5)));

    // The probe reads the port from the same variable as the server.
    let status = Command::new(seedling_bin())
        .arg("healthcheck")
        .env("BRIGID_SERVER__PORT", port.to_string())
        .status()
        .expect("run healthcheck");

    let _ = http_get(addr, "/health");
    let metrics = http_get(metrics_addr, "/metrics");
    // /metrics is not on the public listener.
    let public = http_get(addr, "/metrics");

    child.kill().ok();
    child.wait().ok();

    assert_eq!(
        status.code(),
        Some(0),
        "healthcheck must pass on a live seedling"
    );
    assert!(metrics.starts_with("HTTP/1.1 200"), "{metrics}");
    assert!(
        metrics.contains(
            "brigid_http_requests_total{method=\"GET\",route=\"/health\",status=\"200\"}"
        ),
        "{metrics}"
    );
    assert!(!public.contains("brigid_http_requests_total"));
}

// ---------------------------------------------------------------------------
// `seedling rotate-oidc-key` (core#22): the new key signs, the previous one stays
// in the JWKS for its grace period
// ---------------------------------------------------------------------------

#[test]
fn rotate_oidc_key_publishes_both_keys() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("brigid.db");
    let start = |port: u16| {
        let child = Command::new(seedling_bin())
            .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
            .env("BRIGID_SERVER__DOMAIN", "localhost")
            .env("BRIGID_SERVER__HOST", "127.0.0.1")
            .env("BRIGID_SERVER__PORT", port.to_string())
            .env("BRIGID_DATABASE__PATH", &db)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn seedling");
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert!(wait_until_listening(addr, Duration::from_secs(5)));
        (child, addr)
    };
    let kids = |addr: SocketAddr| -> Vec<String> {
        let response = http_get(addr, "/.well-known/jwks.json");
        let body = response.split("\r\n\r\n").nth(1).unwrap_or_default();
        let json: serde_json::Value = serde_json::from_str(body).expect("JWKS JSON");
        json["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_string())
            .collect()
    };

    // First start stores the key earlier releases derived, under kid "v1".
    let (mut child, addr) = start(free_port());
    assert_eq!(kids(addr), ["v1"]);
    child.kill().ok();
    child.wait().ok();

    let status = Command::new(seedling_bin())
        .arg("rotate-oidc-key")
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("BRIGID_DATABASE__PATH", &db)
        .stderr(Stdio::null())
        .status()
        .expect("run rotate-oidc-key");
    assert!(status.success());

    let (mut child, addr) = start(free_port());
    let published = kids(addr);
    child.kill().ok();
    child.wait().ok();
    assert_eq!(published.len(), 2, "{published:?}");
    assert_ne!(published[0], "v1", "the new key comes first");
    assert_eq!(published[1], "v1", "the retired key stays published");
}
