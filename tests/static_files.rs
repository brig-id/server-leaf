// Integration tests for ServeDir-based UI static file serving.
//
// These tests construct a minimal axum Router (no brigid-api AppState needed)
// and call `apply_ui_fallback` with a temporary directory, verifying that:
//   - SPA routes (e.g. /login) resolve to index.html with Content-Type text/html
//   - Asset files (e.g. /assets/app.js) are served with the correct MIME type
//   - Defined API routes take priority over the static fallback
//   - Without a dist dir configured, unknown routes return 404

use std::fs;

use axum::{Router, body::Body, http::Request, routing::get};
use http_body_util::BodyExt;
use leaf::apply_ui_fallback;
use tempfile::TempDir;
use tower::ServiceExt;

fn make_dist() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    fs::write(
        dir.path().join("index.html"),
        b"<!DOCTYPE html><html><body>SPA</body></html>",
    )
    .expect("write index.html");
    let assets = dir.path().join("assets");
    fs::create_dir_all(&assets).expect("mkdir assets");
    fs::write(assets.join("q-chunk.js"), b"console.log('qwik');").expect("write js");
    dir
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ---------------------------------------------------------------------------
// SPA fallback: unknown paths → index.html
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_login_returns_index_html() {
    let dist = make_dist();
    let app = apply_ui_fallback(Router::new(), Some(dist.path()));

    let resp = app
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap();
    assert!(ct.contains("text/html"), "expected text/html, got {ct}");
    let body = body_string(resp).await;
    assert!(body.contains("SPA"), "body should contain index.html content");
}

#[tokio::test]
async fn get_register_returns_index_html() {
    let dist = make_dist();
    let app = apply_ui_fallback(Router::new(), Some(dist.path()));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/register")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap();
    assert!(ct.contains("text/html"), "expected text/html, got {ct}");
}

// ---------------------------------------------------------------------------
// Static assets are served with correct MIME types
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_js_asset_returns_javascript() {
    let dist = make_dist();
    let app = apply_ui_fallback(Router::new(), Some(dist.path()));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/assets/q-chunk.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp.headers()["content-type"].to_str().unwrap();
    assert!(ct.contains("javascript"), "expected javascript, got {ct}");
    let body = body_string(resp).await;
    assert!(body.contains("qwik"), "body should contain JS content");
}

// ---------------------------------------------------------------------------
// API routes take priority over the static fallback
// ---------------------------------------------------------------------------

#[tokio::test]
async fn api_route_takes_priority_over_static_fallback() {
    let dist = make_dist();

    let base = Router::new().route(
        "/api/health",
        get(|| async { axum::http::StatusCode::NO_CONTENT }),
    );
    let app = apply_ui_fallback(base, Some(dist.path()));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // The API route (204) must win over ServeDir (which would return 200 + HTML).
    assert_eq!(resp.status(), 204);
}

// ---------------------------------------------------------------------------
// Without ui_dist_dir → default axum 404 for unknown paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn without_dist_unknown_path_returns_404() {
    let app = apply_ui_fallback(Router::new(), None);

    let resp = app
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

// ---------------------------------------------------------------------------
// Security headers (CSP, X-Frame-Options, HSTS, nosniff) reach every
// response — including the UI fallback, not just routes defined before
// apply_ui_fallback is called. Regression test for the gap where a
// pre-existing `.layer()` (like brigid-api's own security_headers) silently
// stopped covering the fallback once axum's `.fallback_service()` was
// attached afterwards.
// ---------------------------------------------------------------------------

fn assert_has_security_headers(resp: &axum::response::Response) {
    let headers = resp.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(headers.contains_key("strict-transport-security"));
    let csp = headers
        .get("content-security-policy")
        .expect("content-security-policy header missing")
        .to_str()
        .unwrap();
    assert!(
        csp.contains("script-src 'self'"),
        "expected script-src 'self' in CSP, got: {csp}"
    );
}

#[tokio::test]
async fn ui_fallback_response_carries_security_headers() {
    let dist = make_dist();
    let app = apply_ui_fallback(Router::new(), Some(dist.path()));

    let resp = app
        .oneshot(Request::builder().uri("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    assert_has_security_headers(&resp);
}

#[tokio::test]
async fn api_route_response_also_carries_security_headers() {
    let dist = make_dist();
    let base = Router::new().route(
        "/api/health",
        get(|| async { axum::http::StatusCode::NO_CONTENT }),
    );
    let app = apply_ui_fallback(base, Some(dist.path()));

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), 204);
    assert_has_security_headers(&resp);
}
