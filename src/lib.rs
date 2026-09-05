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
/// from this one — see the `'unsafe-inline'` TODO below).
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
            // TODO(phases/backlog.md "CSP allows unsafe-inline — temporary"):
            // `'unsafe-inline'` here is a known, tracked stopgap, not a
            // considered security posture. Confirmed by loading the app in a
            // real browser with this CSP actually enforced (it wasn't, until
            // the fix this comment is part of): Qwik's static/SSG build DOES
            // emit inline `<script>`/`<style>` tags (its resumability
            // bootstrap) — contrary to what an earlier version of this
            // comment (and brigid-api's copy of it) assumed. Without
            // `unsafe-inline` the browser blocks them outright and the app
            // never becomes interactive. `fonts.bunny.net` is the actual
            // external font host `web` loads from. See the backlog entry for
            // the real fix (build-time hash allowlist).
            // img-src/connect-src additionally allow Unsplash: the login/
            // register pages fetch a daily background photo directly from
            // the browser (app/src/lib/unsplash.ts) — there's no app-side
            // server to proxy it through, this binary serves the UI as
            // static files.
            HeaderValue::from_static(
                "default-src 'self'; \
                 script-src 'self' 'unsafe-inline'; \
                 style-src 'self' 'unsafe-inline' https://fonts.bunny.net; \
                 img-src 'self' data: https://images.unsplash.com; \
                 font-src 'self' https://fonts.bunny.net; \
                 connect-src 'self' https://api.unsplash.com; \
                 frame-ancestors 'none'; \
                 object-src 'none'; \
                 base-uri 'self'",
            ),
        ))
}
