//! CLI-level integration test for `leaf rotate-key --old <path> --new <path>`
//! (phase-4 "Rotation MASTER_KEY" checklist).
//!
//! `EncryptedStore::rotate_master_key`'s own correctness (round-trip, old
//! key fails post-rotation, rollback on partial failure) is already
//! thoroughly tested in `brigid-store` (core repo) against real database
//! rows. What that can't cover is the CLI glue this repo owns: does
//! `leaf rotate-key` correctly read two key files, open the *real* SQLite
//! file a running `leaf` uses (not `:memory:`), and leave the database in a
//! state the server can actually serve logins from afterwards? This test
//! drives the full lifecycle — register against a running `leaf` with the
//! old key, stop it, rotate, restart with the new key, log in — over real
//! HTTP with a software passkey, the same way a real client would.

mod common;

use std::{
    net::SocketAddr,
    process::{Command, Stdio},
    time::Duration,
};

use common::{TEST_MASTER_KEY as OLD_KEY, free_port, leaf_bin, wait_until_listening};
use serde_json::json;
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const NEW_KEY: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

async fn start_leaf(master_key: &str, port: u16, db_path: &std::path::Path) -> std::process::Child {
    let child = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", master_key)
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
        "leaf did not start listening"
    );
    child
}

fn stop_leaf(mut child: std::process::Child) {
    child.kill().ok();
    child.wait().ok();
}

#[tokio::test]
async fn rotate_key_cli_round_trip_login_works_with_new_key() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db_path = dir.path().join("rotate.db");
    let old_key_path = dir.path().join("old.key");
    let new_key_path = dir.path().join("new.key");
    std::fs::write(&old_key_path, OLD_KEY).unwrap();
    std::fs::write(&new_key_path, NEW_KEY).unwrap();

    let port = free_port();
    let base_url = format!("http://localhost:{port}");
    let client = reqwest::Client::new();
    let username = "rotate-test-user@localhost";

    // -- Register a real user against a `leaf` running with the old key --
    let child = start_leaf(OLD_KEY, port, &db_path).await;

    let origin = url::Url::parse(&base_url).unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let resp = client
        .post(format!("{base_url}/auth/register/begin"))
        .json(&json!({ "username": username }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let begin: serde_json::Value = resp.json().await.unwrap();
    let ccr: CreationChallengeResponse =
        serde_json::from_value(begin["challenge"].clone()).unwrap();
    let credential = auth_client.do_registration(origin.clone(), ccr).unwrap();
    let resp = client
        .post(format!("{base_url}/auth/register/finish"))
        .json(&json!({ "session_id": begin["session_id"], "credential": credential }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "register/finish should succeed");

    stop_leaf(child);

    // -- Rotate: leaf is not running, only the CLI subcommand is --
    let output = Command::new(leaf_bin())
        .args(["rotate-key", "--old"])
        .arg(&old_key_path)
        .arg("--new")
        .arg(&new_key_path)
        .env("LEAF_DATABASE__PATH", db_path.display().to_string())
        .output()
        .expect("run leaf rotate-key");
    assert!(
        output.status.success(),
        "rotate-key should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // -- The old key must no longer work against the rotated database --
    let old_key_output = Command::new(leaf_bin())
        .args(["rotate-key", "--old"])
        .arg(&old_key_path)
        .arg("--new")
        .arg(&new_key_path)
        .env("LEAF_DATABASE__PATH", db_path.display().to_string())
        .output()
        .expect("run leaf rotate-key again with the now-stale old key");
    assert!(
        !old_key_output.status.success(),
        "rotating again with the already-rotated-away old key should fail \
         (proves the old key can no longer decrypt post-rotation)"
    );

    // -- Restart leaf with the new key and log in with the same passkey --
    let child = start_leaf(NEW_KEY, port, &db_path).await;

    // A fresh client: `client`'s connection pool may still hold a keep-alive
    // connection to the *first* leaf process on this same port, which is
    // now dead — reusing it here would race a stale pooled connection
    // against the just-restarted server instead of actually testing it.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base_url}/auth/login/begin"))
        .json(&json!({ "username": username, "client_id": "rotate-test-client" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "login/begin should find the user under the new key"
    );
    let begin: serde_json::Value = resp.json().await.unwrap();
    let rcr: RequestChallengeResponse = serde_json::from_value(begin["challenge"].clone()).unwrap();
    let assertion = auth_client.do_authentication(origin, rcr).unwrap();
    let resp = client
        .post(format!("{base_url}/auth/login/finish"))
        .json(&json!({ "session_id": begin["session_id"], "credential": assertion }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "login/finish should succeed with the passkey created before rotation"
    );

    stop_leaf(child);
}
