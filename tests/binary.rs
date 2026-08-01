// Integration tests for the `leaf` binary's startup/shutdown behaviour
// (phase-3 "leaf binary validation" checklist). These spawn the actual
// compiled binary as a subprocess rather than calling library functions
// directly, since the behaviour under test (CLI parsing, env handling,
// process exit codes, signal handling) only exists at that boundary.

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

// Fixed, valid-looking 64-hex-char (32 byte) master key — deterministic so
// tests don't need a `rand`/`hex` dev-dependency just for fixtures.
const TEST_MASTER_KEY: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

fn leaf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_leaf"))
}

/// Binds an ephemeral port and immediately releases it. Small TOCTOU race
/// (something else could grab it before `leaf` does), acceptable for tests.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

fn wait_until_listening(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

fn output_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ---------------------------------------------------------------------------
// 1. Startup without BRIGID_MASTER_KEY
// ---------------------------------------------------------------------------

#[test]
fn missing_master_key_fails_with_readable_message() {
    let output = Command::new(leaf_bin())
        .env_remove("BRIGID_MASTER_KEY")
        .env_remove("BRIGID_MASTER_KEY_FILE")
        .env("LEAF_SERVER__DOMAIN", "localhost")
        .env("LEAF_DATABASE__PATH", ":memory:")
        .output()
        .expect("spawn leaf");

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
    let missing_path = "/nonexistent/leaf-test-config-does-not-exist.toml";
    let output = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .arg("--config")
        .arg(missing_path)
        .output()
        .expect("spawn leaf");

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
    let mut child = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("LEAF_SERVER__DOMAIN", "localhost")
        .env("LEAF_SERVER__HOST", "127.0.0.1")
        .env("LEAF_SERVER__PORT", port.to_string())
        .env("LEAF_DATABASE__PATH", ":memory:")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn leaf");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let listening = wait_until_listening(addr, Duration::from_secs(5));

    child.kill().ok();
    child.wait().ok();

    assert!(listening, "leaf did not start listening on port {port}");
}

// ---------------------------------------------------------------------------
// 4. Graceful shutdown (SIGTERM) → DB not corrupted, exit 0
// ---------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_on_sigterm_exits_cleanly() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db_path = dir.path().join("leaf-shutdown-test.db");
    let port = free_port();

    let mut child = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("LEAF_SERVER__DOMAIN", "localhost")
        .env("LEAF_SERVER__HOST", "127.0.0.1")
        .env("LEAF_SERVER__PORT", port.to_string())
        .env("LEAF_DATABASE__PATH", db_path.display().to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn leaf");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(
        wait_until_listening(addr, Duration::from_secs(5)),
        "leaf did not start listening before SIGTERM"
    );

    // Send a real SIGTERM (Child::kill() only sends SIGKILL on Unix) so the
    // graceful-shutdown path in main.rs actually runs.
    let pid = child.id().to_string();
    let status = Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .expect("send SIGTERM");
    assert!(status.success(), "kill -TERM failed to send the signal");

    let exit = child.wait().expect("wait for leaf to exit");
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
    // Hold the port open ourselves so leaf's bind fails.
    let holder = TcpListener::bind("127.0.0.1:0").expect("bind holder");
    let port = holder.local_addr().unwrap().port();

    let output = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("LEAF_SERVER__DOMAIN", "localhost")
        .env("LEAF_SERVER__HOST", "127.0.0.1")
        .env("LEAF_SERVER__PORT", port.to_string())
        .env("LEAF_DATABASE__PATH", ":memory:")
        .output()
        .expect("spawn leaf");

    drop(holder);

    assert!(!output.status.success(), "expected non-zero exit");
    let stderr = output_text(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("address already in use") || stderr.contains("AddrInUse"),
        "stderr should clearly indicate the port conflict, got: {stderr}"
    );
}
