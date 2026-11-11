pub mod metrics;
pub mod probe;

use std::path::Path;

use axum::Router;
use axum::http::{HeaderName, HeaderValue};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

/// Attach the Qwik UI static files to `router` as a fallback service, then
/// (re-)apply the security header set to the *whole* router — routes and
/// fallback alike.
///
/// When `dist` is `Some(path)`, every request that does not match an existing
/// route is handled by `ServeDir`: real files (JS chunks, CSS, icons) are
/// served directly, and everything else falls back to `index.html` so that
/// Qwik City's client-side router can handle deep-link URLs (SPA fallback).
///
/// When `dist` is `None` the router's routes are unchanged (the security
/// header layer below still applies) and unknown routes produce the default
/// axum 404.
///
/// `brigid_api::build_router` already applies a version of this same header
/// set, but only around the routes it defines *before* returning — in axum
/// 0.8, a `.layer()` wraps whatever routes/fallback exist at the time it's
/// called, not ones added afterwards. Since `server-leaf` always calls
/// `fallback_service` *after* `build_router` returns, that inner layer
/// silently never reached the UI responses (`/login`, `/register`, static
/// assets, …), leaving them with no CSP/X-Frame-Options/HSTS at all.
/// Re-applying the same headers here — genuinely last, after the fallback is
/// attached — is what actually covers every response `leaf` serves.
/// `if_not_present` makes this a no-op for API routes, which already carry
/// these headers from the inner layer (whose CSP value has since diverged
/// from this one: see [`ui_csp`]).
pub fn apply_ui_fallback(router: Router, dist: Option<&Path>) -> Router {
    let router = match dist {
        Some(path) => {
            let serve = ServeDir::new(path).fallback(ServeFile::new(path.join("index.html")));
            router.fallback_service(serve)
        }
        None => router,
    };

    router
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_str(&ui_csp(dist)).expect("CSP is ASCII"),
        ))
}

/// The hashes `app`'s build writes to `dist/csp-hashes.json` (app#3): the
/// `'sha256-…'` source of each inline `<script>` and `<style>` it emitted.
#[derive(serde::Deserialize)]
struct CspHashes {
    script: Vec<String>,
    style: Vec<String>,
}

/// A CSP hash source as the manifest writes it: `'sha256-<base64>'`.
/// Anything else is dropped rather than injected into the header.
fn is_hash_source(s: &str) -> bool {
    s.strip_prefix("'sha256-")
        .and_then(|rest| rest.strip_suffix('\''))
        .is_some_and(|b64| {
            !b64.is_empty()
                && b64
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
        })
}

/// The CSP of UI responses (core#20).
///
/// With `dist/csp-hashes.json`, inline scripts and styles are allowed by
/// hash only: no `'unsafe-inline'`, so an injected script does not run.
/// Without it (an older UI build, or no UI), falls back to the previous
/// `'unsafe-inline'` policy and says so in the log.
///
/// `fonts.bunny.net` is the external font host the UI loads from; img-src and
/// connect-src allow Unsplash, whose daily background photo the login and
/// register pages fetch straight from the browser (app/src/lib/unsplash.ts).
pub fn ui_csp(dist: Option<&Path>) -> String {
    let hashes = dist.and_then(|d| {
        let path = d.join("csp-hashes.json");
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<CspHashes>(&text) {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "unreadable CSP hash manifest");
                None
            }
        }
    });
    let (script, style) = match hashes {
        Some(h) => {
            let keep = |v: Vec<String>| {
                v.into_iter()
                    .filter(|s| is_hash_source(s))
                    .collect::<Vec<_>>()
                    .join(" ")
            };
            (keep(h.script), keep(h.style))
        }
        None => {
            if dist.is_some() {
                tracing::warn!(
                    "no dist/csp-hashes.json: UI served with 'unsafe-inline' (rebuild the UI)"
                );
            }
            ("'unsafe-inline'".to_string(), "'unsafe-inline'".to_string())
        }
    };
    format!(
        "default-src 'self'; \
         script-src 'self' {script}; \
         style-src 'self' {style} https://fonts.bunny.net; \
         img-src 'self' data: https://images.unsplash.com; \
         font-src 'self' https://fonts.bunny.net; \
         connect-src 'self' https://api.unsplash.com; \
         frame-ancestors 'none'; \
         object-src 'none'; \
         base-uri 'self'"
    )
}

#[cfg(test)]
mod csp_tests {
    use super::*;

    #[test]
    fn hashes_replace_unsafe_inline() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("csp-hashes.json"),
            r#"{"script":["'sha256-AAAA'","'unsafe-eval'","x; script-src *"],"style":["'sha256-BB+/='"],"pages":[]}"#,
        )
        .unwrap();
        let csp = ui_csp(Some(dir.path()));
        assert!(csp.contains("script-src 'self' 'sha256-AAAA';"), "{csp}");
        assert!(csp.contains("style-src 'self' 'sha256-BB+/=' https://fonts.bunny.net;"));
        assert!(!csp.contains("unsafe-inline"));
        assert!(!csp.contains("unsafe-eval"), "only hash sources are copied");
        assert!(!csp.contains("script-src *"));
    }

    #[test]
    fn without_a_manifest_falls_back_to_unsafe_inline() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ui_csp(Some(dir.path())).contains("script-src 'self' 'unsafe-inline'"));
        assert!(ui_csp(None).contains("script-src 'self' 'unsafe-inline'"));
    }
}
