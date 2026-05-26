//! brig·id `leaf` — single-server deployment binary.
//!
//! # Startup sequence
//!
//! 1. Parse CLI arguments (config file path).
//! 2. Load and validate configuration (TOML + env).
//! 3. Load `BRIGID_MASTER_KEY` from environment (mandatory).
//! 4. Derive VSID salt from master key.
//! 5. Open and migrate the SQLite database.
//! 6. Build the Axum application (router + state).
//! 7. Start TLS (if cert/key configured) or plain HTTP server.
//! 8. Await graceful shutdown on `SIGTERM` / `CTRL-C`.

mod config;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use clap::Parser;
use tracing_subscriber::{EnvFilter, fmt};
use url::Url;

use brigid_api::{AppState, build_router};
use brigid_crypto::MasterKey;
use brigid_identity::derive_vsid_salt;
use brigid_oidc::OidcSigningKey;
use brigid_store::EncryptedStore;
use brigid_webauthn::WebauthnService;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "leaf", about = "brig·id single-server deployment")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "leaf.toml")]
    config: PathBuf,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Structured JSON logs — verbosity controlled by RUST_LOG.
    fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // -- Configuration -------------------------------------------------------
    let cfg = config::load(&cli.config).expect("configuration error");

    // -- MASTER_KEY ----------------------------------------------------------
    // Must come from the environment — never from the config file.
    let master = MasterKey::from_env()
        .expect("BRIGID_MASTER_KEY must be set to a 64-character hex string (32 bytes)");

    // Derive VSID salt before master is moved into the store.
    let vsid_salt = derive_vsid_salt(&master);

    // -- OIDC signing key ---------------------------------------------------
    // Derived from master key so it is stable across process restarts.
    // Tokens issued before a restart remain valid.
    let oidc_raw =
        brigid_crypto::hkdf::derive_user_key(&master, b"oidc-signing-key", b"oidc-ed25519")
            .expect("HKDF key derivation failed");
    let oidc_key = OidcSigningKey::from_raw_bytes("v1".to_string(), &oidc_raw);

    // -- Database ------------------------------------------------------------
    let db_url = if cfg.database.path == ":memory:" {
        "sqlite::memory:".to_string()
    } else {
        format!("sqlite://{}?mode=rwc", cfg.database.path)
    };

    let store = EncryptedStore::new(&db_url, master)
        .await
        .expect("failed to open or migrate database");

    // -- Application state --------------------------------------------------
    let scheme = if cfg.server.tls_cert.is_some() {
        "https"
    } else {
        "http"
    };
    let base_url: Url = format!("{}://{}:{}", scheme, cfg.server.domain, cfg.server.port)
        .parse()
        .expect("invalid domain/port in configuration");

    let webauthn = WebauthnService::new(cfg.server.domain.as_str(), &base_url)
        .expect("failed to build WebAuthn service (check `domain` in config)");

    let cors_origins: Vec<Url> = cfg
        .security
        .cors_origins
        .iter()
        .filter_map(|s| s.parse::<Url>().ok())
        .collect();

    let state = Arc::new(AppState::new(
        store, webauthn, oidc_key, base_url, vsid_salt,
    ));
    let router = build_router(state, &cors_origins);

    // -- Server --------------------------------------------------------------
    let addr: SocketAddr = format!("{}:{}", cfg.server.host, cfg.server.port)
        .parse()
        .expect("invalid host/port in configuration");

    let handle = axum_server::Handle::new();

    // Spawn graceful-shutdown task.
    {
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            tracing::info!("shutdown signal received — draining connections (10 s grace)");
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        });
    }

    match (cfg.server.tls_cert, cfg.server.tls_key) {
        (Some(cert), Some(key)) => {
            tracing::info!(
                %addr,
                domain = %cfg.server.domain,
                tls = true,
                session_ttl_secs = cfg.security.session_ttl_seconds,
                "brig·id leaf starting"
            );
            let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                .await
                .expect("failed to load TLS certificate/key — check tls_cert/tls_key paths");
            axum_server::bind_rustls(addr, tls_config)
                .handle(handle)
                .serve(router.into_make_service())
                .await
                .expect("TLS server error");
        }
        _ => {
            tracing::warn!(
                %addr,
                domain = %cfg.server.domain,
                tls = false,
                session_ttl_secs = cfg.security.session_ttl_seconds,
                "TLS not configured — running plain HTTP (use Caddy or configure tls_cert/tls_key)"
            );
            axum_server::bind(addr)
                .handle(handle)
                .serve(router.into_make_service())
                .await
                .expect("HTTP server error");
        }
    }
}

// ---------------------------------------------------------------------------
// Graceful shutdown signal handler
// ---------------------------------------------------------------------------

async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c().await.expect("CTRL-C handler failed");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler registration failed")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
