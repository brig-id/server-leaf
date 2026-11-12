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
    _ui_dir: tempfile::TempDir,
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
    start_leaf_with(&[])
}

/// [`start_leaf`] with extra environment variables for the `leaf` process.
fn start_leaf_with(extra_env: &[(&str, &str)]) -> TestServer {
    let port = free_port();
    let db_dir = tempfile::TempDir::new().expect("tempdir for db");
    let db_path = db_dir.path().join("smoke.db");

    let ui_dir = tempfile::TempDir::new().expect("tempdir for ui dist");
    fs::write(
        ui_dir.path().join("index.html"),
        b"<!DOCTYPE html><html><body>smoke-test-ui</body></html>",
    )
    .expect("write fake index.html");

    let mut child = Command::new(leaf_bin())
        .env("BRIGID_MASTER_KEY", TEST_MASTER_KEY)
        .env("LEAF_SERVER__DOMAIN", "localhost")
        .env("LEAF_SERVER__HOST", "127.0.0.1")
        .env("LEAF_SERVER__PORT", port.to_string())
        .env("LEAF_DATABASE__PATH", db_path.display().to_string())
        .env(
            "LEAF_SERVER__UI_DIST_DIR",
            ui_dir.path().display().to_string(),
        )
        .envs(extra_env.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn leaf");

    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    if !wait_until_listening(addr, Duration::from_secs(5)) {
        // `child` isn't wrapped in `TestServer` yet, so its `Drop` (which
        // would kill it) never runs — without this, a failed startup leaks
        // the orphaned `leaf` process instead of just failing the test.
        child.kill().ok();
        child.wait().ok();
        panic!("leaf did not start listening");
    }

    TestServer {
        child,
        // WebAuthn strictly checks the ceremony's origin against the RP's
        // configured domain (`LEAF_SERVER__DOMAIN=localhost` above) — using
        // 127.0.0.1 here would mismatch and fail with a `Security` error.
        // "localhost" resolves to 127.0.0.1 via /etc/hosts either way.
        base_url: format!("http://localhost:{port}"),
        // A browser sends its page's origin on every request that changes
        // something, and the API refuses any other (ADR-005).
        client: reqwest::Client::builder()
            .default_headers(
                [(
                    reqwest::header::ORIGIN,
                    reqwest::header::HeaderValue::from_str(&format!("http://localhost:{port}"))
                        .unwrap(),
                )]
                .into_iter()
                .collect(),
            )
            .build()
            .unwrap(),
        _db_dir: db_dir,
        _ui_dir: ui_dir,
    }
}

/// The session cookie (`name=value`) a response sets; checks its attributes.
fn session_cookie(resp: &reqwest::Response) -> String {
    let set = resp
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("the response opens a session")
        .to_str()
        .unwrap();
    assert!(
        set.contains("HttpOnly") && set.contains("SameSite=Strict"),
        "{set}"
    );
    set.split(';').next().unwrap().to_string()
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
async fn no_openid_configuration_before_the_relying_party_flow() {
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
    // ADR-005 §3: it comes back with the Authorization Code flow. Unknown
    // paths fall back to the UI's HTML, never to a JSON configuration.
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        !content_type.contains("json"),
        "no OpenID configuration served: {content_type}"
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
async fn webauthn_register_and_login_round_trip_opens_a_session() {
    let server = start_leaf();
    let origin = url::Url::parse(&server.base_url).unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let username = "smoke-alice@localhost";

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
        .do_registration(origin.clone(), for_soft_passkey(ccr))
        .expect("software passkey registration ceremony");

    // -- register/finish --
    let resp = server
        .client
        .post(format!("{}/auth/register/finish", server.base_url))
        .json(&json!({ "session_id": session_id, "credential": credential }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "register/finish should succeed");

    // -- login/begin --
    let resp = server
        .client
        .post(format!("{}/auth/login/begin", server.base_url))
        .json(&json!({ "username": username }))
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
    // A session in an HttpOnly cookie, never a token (ADR-005).
    assert_eq!(resp.status(), 204, "login/finish should succeed");
    let cookie = session_cookie(&resp);
    assert!(
        resp.text().await.unwrap().is_empty(),
        "no token in the body"
    );
    let resp = server
        .client
        .get(format!("{}/auth/session", server.base_url))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the session cookie opens the account");
}

// ---------------------------------------------------------------------------
// Delete passkey after login
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deleting_the_only_passkey_is_refused() {
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
    let credential = auth_client
        .do_registration(origin.clone(), for_soft_passkey(ccr))
        .unwrap();
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
        .json(&json!({ "username": username, }))
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
    let cookie = session_cookie(&resp);

    // List passkeys to get a real credential id to delete.
    let resp = server
        .client
        .get(format!("{}/auth/passkeys", server.base_url))
        .header(reqwest::header::COOKIE, &cookie)
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
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    // brig·id is passkey-only: removing the account's last passkey would
    // lock it out, so the server refuses (core#41).
    assert_eq!(resp.status(), 409, "the only passkey must not be deletable");
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
            .json(&json!({ "username": "nobody@localhost", }))
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

/// Sends `count` rapid `/auth/login/begin` requests announcing `client_ip` in
/// `X-Forwarded-For`, as a reverse proxy would, and returns the last status.
async fn hammer_login_begin(server: &TestServer, client_ip: &str, count: usize) -> u16 {
    let mut last_status = 0;
    for _ in 0..count {
        last_status = server
            .client
            .post(format!("{}/auth/login/begin", server.base_url))
            .header("x-forwarded-for", client_ip)
            .json(&json!({ "username": "nobody@localhost", }))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
    }
    last_status
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_client_has_its_own_rate_limit() {
    let server = start_leaf_with(&[("LEAF_SECURITY__TRUST_FORWARDED_FOR", "true")]);
    assert_eq!(hammer_login_begin(&server, "203.0.113.1", 21).await, 429);
    // A second client behind the same proxy is not throttled by the first.
    assert_ne!(hammer_login_begin(&server, "203.0.113.2", 1).await, 429);
}

#[tokio::test]
async fn without_a_trusted_proxy_forwarded_for_does_not_split_the_rate_limit() {
    let server = start_leaf();
    assert_eq!(hammer_login_begin(&server, "203.0.113.1", 21).await, 429);
    // The header is ignored: forging it must not buy a fresh bucket.
    assert_eq!(hammer_login_begin(&server, "203.0.113.2", 1).await, 429);
}

/// The server asks for a discoverable passkey (`residentKey: required`);
/// `SoftPasskey` keeps no resident keys and would refuse. Check the request,
/// then relax it for the software authenticator.
fn for_soft_passkey(mut ccr: CreationChallengeResponse) -> CreationChallengeResponse {
    let selection = ccr
        .public_key
        .authenticator_selection
        .as_mut()
        .expect("registration states an authenticator selection");
    assert!(
        selection.require_resident_key,
        "discoverable passkey requested"
    );
    selection.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Discouraged);
    selection.require_resident_key = false;
    ccr
}
