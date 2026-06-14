use std::path::Path;

use axum::Router;
use tower_http::services::{ServeDir, ServeFile};

/// Attach the Qwik UI static files to `router` as a fallback service.
///
/// When `dist` is `Some(path)`, every request that does not match an existing
/// route is handled by `ServeDir`: real files (JS chunks, CSS, icons) are
/// served directly, and everything else falls back to `index.html` so that
/// Qwik City's client-side router can handle deep-link URLs (SPA fallback).
///
/// When `dist` is `None` the router is returned unchanged and unknown routes
/// produce the default axum 404.
pub fn apply_ui_fallback(router: Router, dist: Option<&Path>) -> Router {
    match dist {
        Some(path) => {
            let serve = ServeDir::new(path)
                .fallback(ServeFile::new(path.join("index.html")));
            router.fallback_service(serve)
        }
        None => router,
    }
}
