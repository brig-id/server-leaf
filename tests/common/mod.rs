//! Shared helpers for integration tests that spawn the real `leaf` binary as
//! a subprocess (as opposed to `tests/static_files.rs`, which exercises
//! `apply_ui_fallback` in-process against a bare `axum::Router`).

use std::{
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    time::{Duration, Instant},
};

/// Fixed, valid-looking 64-hex-char (32 byte) master key — deterministic so
/// tests don't need a `rand`/`hex` dev-dependency just for fixtures.
pub const TEST_MASTER_KEY: &str =
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

pub fn leaf_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_leaf"))
}

/// Binds an ephemeral port and immediately releases it. Small TOCTOU race
/// (something else could grab it before `leaf` does), acceptable for tests.
pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr").port()
}

pub fn wait_until_listening(addr: SocketAddr, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}
