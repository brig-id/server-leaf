//! E2E smoke tests (phase-3 "E2E smoke tests (Rust + reqwest)" checklist).
//!
//! Unlike `tests/static_files.rs` (in-process `axum::Router`) and
//! `tests/binary.rs` (process lifecycle only), these spawn a real `leaf`
//! subprocess and drive it over real HTTP with `reqwest`, including a full
//! WebAuthn ceremony via a software passkey — the closest thing to what a
//! real client does, short of a browser.

mod common;

use std::{
    fs,
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};

use common::{TEST_MASTER_KEY, free_port, leaf_bin, wait_until_listening};
use serde_json::{Value, json};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

struct TestServer {
    child: Child,
    pub base_url: String,
    pub client: reqwest::Client,
    _db_dir: tempfile::TempDir,
    _ui_dir: Option<tempfile::TempDir>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Spawns `leaf` with a fresh temp DB and a minimal fake UI dist (so
/// `GET /login` has something to serve), waits for it to start listening,
/// and returns a client pointed at it. Each call gets its own process — and
/// so its own in-memory rate-limit bucket — which is what keeps
/// `rate_limit_21st_auth_request_returns_429` from bleeding into the other
/// tests here.
fn start_leaf() -> TestServer {
    let port = free_port();
    let db_dir = tempfile::TempDir::new().expect("tempdir for db");
    let db_path = db_dir.path().join("smoke.db");

    let ui_dir = tempfile::TempDir::new().expect("tempdir for ui dist");
    fs::write(
        ui_dir.path().join("index.html"),
        b"<!DOCTYPE html><html><body>smoke-test-ui</body></html>",
    )
    .expect("write fake index.html");

    let child = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("LEAF_SERVER__DOMAIN", "localhost")
        .env("LEAF_SERVER__HOST", "127.0.0.1")
        .env("LEAF_SERVER__PORT", port.to_string())
        .env("LEAF_DATABASE__PATH", db_path.display().to_string())
        .env(
            "LEAF_SERVER__UI_DIST_DIR",
            ui_dir.path().display().to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn leaf");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    assert!(
        wait_until_listening(addr, Duration::from_secs(5)),
        "leaf did not start listening"
    );

    TestServer {
        child,
        // WebAuthn strictly checks the ceremony's origin against the RP's
        // configured domain (`LEAF_SERVER__DOMAIN=localhost` above) — using
        // 127.0.0.1 here would mismatch and fail with a `Security` error.
        // "localhost" resolves to 127.0.0.1 via /etc/hosts either way.
        base_url: format!("http://localhost:{port}"),
        client: reqwest::Client::new(),
        _db_dir: db_dir,
        _ui_dir: Some(ui_dir),
    }
}

async fn json_body(resp: reqwest::Response) -> Value {
    resp.json().await.expect("valid JSON body")
}

// ---------------------------------------------------------------------------
// Health & discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_200() {
    let server = start_leaf();
    let resp = server
        .client
        .get(format!("{}/health", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = json_body(resp).await;
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn openid_configuration_has_issuer() {
    let server = start_leaf();
    let resp = server
        .client
        .get(format!(
            "{}/.well-known/openid-configuration",
            server.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = json_body(resp).await;
    assert!(
        body["issuer"].is_string(),
        "expected `issuer` field: {body}"
    );
}

#[tokio::test]
async fn did_document_has_id() {
    let server = start_leaf();
    let resp = server
        .client
        .get(format!("{}/.well-known/did.json", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = json_body(resp).await;
    assert!(body["id"].is_string(), "expected `id` field: {body}");
}

#[tokio::test]
async fn jwks_has_non_empty_keys() {
    let server = start_leaf();
    let resp = server
        .client
        .get(format!("{}/.well-known/jwks.json", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = json_body(resp).await;
    let keys = body["keys"].as_array().expect("`keys` should be an array");
    assert!(!keys.is_empty(), "expected at least one key: {body}");
}

#[tokio::test]
async fn login_page_returns_html() {
    let server = start_leaf();
    let resp = server
        .client
        .get(format!("{}/login", server.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(content_type.contains("text/html"), "got {content_type}");
}

// ---------------------------------------------------------------------------
// WebAuthn registration + login round trip, OIDC token claims
// ---------------------------------------------------------------------------

#[tokio::test]
async fn webauthn_register_and_login_round_trip_with_valid_oidc_token() {
    let server = start_leaf();
    let origin = url::Url::parse(&server.base_url).unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let username = "smoke-alice@localhost";
    let client_id = "smoke-test-client";

    // -- register/begin --
    let resp = server
        .client
        .post(format!("{}/auth/register/begin", server.base_url))
        .json(&json!({ "username": username }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "register/begin should succeed");
    let begin = json_body(resp).await;
    let session_id = begin["session_id"].clone();
    let ccr: CreationChallengeResponse = serde_json::from_value(begin["challenge"].clone())
        .expect("challenge should deserialize as CreationChallengeResponse");

    // -- perform the ceremony with a software passkey --
    let credential = auth_client
        .do_registration(origin.clone(), ccr)
        .expect("software passkey registration ceremony");

    // -- register/finish --
    let resp = server
        .client
        .post(format!("{}/auth/register/finish", server.base_url))
        .json(&json!({ "session_id": session_id, "credential": credential }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "register/finish should succeed");

    // -- login/begin --
    let resp = server
        .client
        .post(format!("{}/auth/login/begin", server.base_url))
        .json(&json!({ "username": username, "client_id": client_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login/begin should succeed");
    let begin = json_body(resp).await;
    let login_session_id = begin["session_id"].clone();
    let rcr: RequestChallengeResponse = serde_json::from_value(begin["challenge"].clone())
        .expect("challenge should deserialize as RequestChallengeResponse");

    let assertion = auth_client
        .do_authentication(origin, rcr)
        .expect("software passkey authentication ceremony");

    // -- login/finish --
    let resp = server
        .client
        .post(format!("{}/auth/login/finish", server.base_url))
        .json(&json!({ "session_id": login_session_id, "credential": assertion }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login/finish should succeed");
    let login = json_body(resp).await;
    let id_token = login["id_token"]
        .as_str()
        .expect("id_token should be a string");
    let user_id = login["user_id"]
        .as_str()
        .expect("user_id should be a string");

    // Signature verification of the OIDC issuer key is already covered by
    // core's own test suites; this is an HTTP-level smoke test, so decode
    // without verifying and just check the claims made it through intact.
    //
    // `sub` is the VSID — a per-relying-party pseudonymous identifier
    // (brigid_identity::derive_vsid_salt), deliberately *not* the same value
    // as `user_id` (the raw internal UUID used for API operations like
    // DELETE /auth/passkeys). They're expected to differ by design.
    let claims: jsonwebtoken::TokenData<Value> = jsonwebtoken::dangerous::insecure_decode(id_token)
        .expect("id_token should decode as a JWT");
    let sub = claims.claims["sub"]
        .as_str()
        .expect("`sub` claim should be a string");
    assert!(!sub.is_empty(), "`sub` (VSID) should not be empty");
    assert_ne!(
        sub, user_id,
        "`sub` (VSID) is a pseudonymous identifier and should differ from the raw user_id"
    );
    assert_eq!(
        claims.claims["aud"].as_str(),
        Some(client_id),
        "`aud` should be the client_id passed to login/begin"
    );
}

// ---------------------------------------------------------------------------
// Delete passkey after login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_passkey_after_login_returns_200() {
    let server = start_leaf();
    let origin = url::Url::parse(&server.base_url).unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let username = "smoke-bob@localhost";

    let resp = server
        .client
        .post(format!("{}/auth/register/begin", server.base_url))
        .json(&json!({ "username": username }))
        .send()
        .await
        .unwrap();
    let begin = json_body(resp).await;
    let ccr: CreationChallengeResponse =
        serde_json::from_value(begin["challenge"].clone()).unwrap();
    let credential = auth_client.do_registration(origin.clone(), ccr).unwrap();
    server
        .client
        .post(format!("{}/auth/register/finish", server.base_url))
        .json(&json!({ "session_id": begin["session_id"], "credential": credential }))
        .send()
        .await
        .unwrap();

    let resp = server
        .client
        .post(format!("{}/auth/login/begin", server.base_url))
        .json(&json!({ "username": username, "client_id": "smoke-test-client" }))
        .send()
        .await
        .unwrap();
    let begin = json_body(resp).await;
    let rcr: RequestChallengeResponse = serde_json::from_value(begin["challenge"].clone()).unwrap();
    let assertion = auth_client.do_authentication(origin, rcr).unwrap();
    let resp = server
        .client
        .post(format!("{}/auth/login/finish", server.base_url))
        .json(&json!({ "session_id": begin["session_id"], "credential": assertion }))
        .send()
        .await
        .unwrap();
    let login = json_body(resp).await;
    let token = login["id_token"].as_str().unwrap();
    let user_id = login["user_id"].as_str().unwrap();

    // List passkeys to get a real credential id to delete.
    let resp = server
        .client
        .get(format!(
            "{}/auth/passkeys?user_id={user_id}",
            server.base_url
        ))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let passkeys = json_body(resp).await;
    let passkey_id = passkeys[0]["id"]
        .as_str()
        .expect("expected at least one registered passkey")
        .to_string();

    // This is the 6th /auth/* call in this test (register begin/finish,
    // login begin/finish, list) against a burst of 5 (1 token/3s refill) —
    // a real rate-limit constraint, not a bug. Give it a moment to refill
    // rather than weakening the limiter to make the test faster.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let resp = server
        .client
        .delete(format!("{}/auth/passkeys/{passkey_id}", server.base_url))
        .bearer_auth(token)
        .json(&json!({ "user_id": user_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "delete should succeed after login");
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn twenty_first_auth_request_returns_429() {
    let server = start_leaf();
    // GovernorLayer wraps the whole /auth/* router ahead of the handlers, so
    // a request that 404s for an unknown user still consumes a token — no
    // need for a valid ceremony here, just enough distinct requests fired
    // fast enough that the bucket's 1-token/3s refill can't keep up.
    let mut last_status = reqwest::StatusCode::OK;
    for _ in 0..21 {
        last_status = server
            .client
            .post(format!("{}/auth/login/begin", server.base_url))
            .json(&json!({ "username": "nobody@localhost", "client_id": "smoke-test-client" }))
            .send()
            .await
            .unwrap()
            .status();
    }
    assert_eq!(
        last_status, 429,
        "21st rapid /auth/* request should be rate-limited"
    );
}
