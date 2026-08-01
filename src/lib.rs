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
/// `brigid_api::build_router` already applies this same header set, but only
/// around the routes it defines *before* returning — in axum 0.8, a `.layer()`
/// wraps whatever routes/fallback exist at the time it's called, not ones
/// added afterwards. Since `server-leaf` always calls `fallback_service`
/// *after* `build_router` returns, that inner layer silently never reached
/// the UI responses (`/login`, `/register`, static assets, …), leaving them
/// with no CSP/X-Frame-Options/HSTS at all. Re-applying the same headers here
/// — genuinely last, after the fallback is attached — is what actually
/// covers every response `leaf` serves. `if_not_present` makes this a no-op
/// for API routes, which already carry these headers from the inner layer.
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
            // Matches brigid-api's policy (see the comment above): Qwik's
            // static/SSG build emits no inline scripts, so `script-src
            // 'self'` holds with no nonce needed.
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self'; \
                 img-src 'self' data:; \
                 font-src 'self'; \
                 connect-src 'self'; \
                 frame-ancestors 'none'; \
                 object-src 'none'; \
                 base-uri 'self'",
            ),
        ))
}
