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

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use leaf::apply_ui_fallback;

use clap::{Parser, Subcommand};
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
    ///
    /// Optional — if omitted, configuration is read entirely from `LEAF_*`
    /// environment variables (the recommended setup for container deployments).
    /// Used both to start the server and to locate the database for
    /// `rotate-key`, hence `global = true` so it's accepted on either side
    /// of a subcommand.
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Re-encrypt every row under a new master key, replacing the old one.
    ///
    /// Reads the database path from `--config`/`LEAF_DATABASE__PATH` like a
    /// normal run — `BRIGID_MASTER_KEY` is intentionally *not* read from the
    /// environment for this subcommand, since both keys are needed
    /// simultaneously and only one can live in a single env var.
    RotateKey {
        /// Path to a file containing the current master key (64 hex chars).
        #[arg(long)]
        old: PathBuf,
        /// Path to a file containing the new master key (64 hex chars).
        #[arg(long)]
        new: PathBuf,
    },
}

/// Builds the sqlx connection URL for a database path.
fn db_url(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else {
        // Use the path-only form `sqlite:{path}` rather than `sqlite://{path}`.
        // The double-slash form is a URL where everything after `://` is
        // host+path; for an absolute path like `/data/brigid.db` that yields
        // `sqlite:///data/brigid.db` (three slashes) which is correct but
        // easy to miscount as `sqlite:////…` in code review and is fragile
        // when the path contains characters that would otherwise need URL
        // encoding. The single-slash form is unambiguously a filename and
        // sqlx parses it the same way for both absolute and relative paths.
        format!("sqlite:{path}?mode=rwc")
    }
}

/// Handles `leaf rotate-key --old <path> --new <path>`.
async fn rotate_key(db: &config::DatabaseConfig, old_path: &Path, new_path: &Path) {
    let old_master = MasterKey::from_file(old_path)
        .expect("failed to read the old master key file (64 hex chars expected)");
    let new_master = MasterKey::from_file(new_path)
        .expect("failed to read the new master key file (64 hex chars expected)");

    let mut store = EncryptedStore::new(&db_url(&db.path), old_master)
        .await
        .expect("failed to open or migrate database");

    store
        .rotate_master_key(new_master)
        .await
        .expect("key rotation failed — the transaction was rolled back, the database is unchanged");

    eprintln!("✓ MASTER_KEY rotated successfully.");
    eprintln!();
    eprintln!("This has consequences beyond re-encrypting the database:");
    eprintln!("  - Every user's VSID (the OIDC `sub` claim) changed for every relying party —");
    eprintln!("    any relying party correlating users by VSID loses that continuity across");
    eprintln!("    this rotation. There is no way to preserve it.");
    eprintln!("  - The OIDC signing key is derived from BRIGID_MASTER_KEY, so every id_token");
    eprintln!("    issued before this rotation is invalid now, not just after its natural expiry.");
    eprintln!();
    eprintln!("Update BRIGID_MASTER_KEY to the new key before starting leaf again.");
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // `axum-server`'s `tls-rustls` feature and `reqwest`'s TLS backend each
    // pull in a different rustls crypto provider (`aws-lc-rs` and `ring`
    // respectively) — Cargo unifies both onto the one `rustls` crate in the
    // dependency graph, so rustls refuses to auto-select either and panics
    // the first time a TLS handshake is attempted. Installing one explicitly
    // up front resolves the ambiguity; which of the two is picked doesn't
    // matter functionally, so this matches axum-server's own default pairing.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no CryptoProvider should be installed yet — this runs once at startup");

    let cli = Cli::parse();

    // Structured JSON logs — verbosity controlled by RUST_LOG.
    fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // -- Configuration -------------------------------------------------------
    // figment's TOML file provider treats a missing file as "no data" rather
    // than an error, so an explicit --config typo would otherwise fall
    // through silently to an unrelated "missing field `server`" error with
    // no mention of the path that was actually looked up.
    if let Some(path) = cli.config.as_deref() {
        if !path.exists() {
            panic!("config file not found: {}", path.display());
        }
    }

    // rotate-key only ever needs the database path — extracting the full
    // `Config` here would demand `server.domain` (required, no default) for
    // no reason, since rotate-key never touches server/TLS/CORS settings.
    if let Some(Command::RotateKey { old, new }) = cli.command {
        let db = config::load_database(cli.config.as_deref()).expect("configuration error");
        rotate_key(&db, &old, &new).await;
        return;
    }

    let cfg = config::load(cli.config.as_deref()).expect("configuration error");

    // -- MASTER_KEY ----------------------------------------------------------
    // Must come from the environment or a Docker-secrets file — never from
    // the config file. BRIGID_MASTER_KEY_FILE takes precedence so a mounted
    // secret (see deploy/compose.yaml) is preferred over a plaintext env var
    // when both happen to be present.
    let master = match std::env::var_os("BRIGID_MASTER_KEY_FILE") {
        Some(path) => MasterKey::from_file(Path::new(&path)).expect(
            "BRIGID_MASTER_KEY_FILE must point to a file containing a 64-character hex string (32 bytes)",
        ),
        None => MasterKey::from_env()
            .expect("BRIGID_MASTER_KEY (or BRIGID_MASTER_KEY_FILE) must be set to a 64-character hex string (32 bytes)"),
    };

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
    let store = EncryptedStore::new(&db_url(&cfg.database.path), master)
        .await
        .expect("failed to open or migrate database");

    // -- Application state --------------------------------------------------
    let base_url: Url = match cfg.server.public_url {
        Some(ref u) => u
            .parse()
            .expect("invalid `server.public_url` in configuration"),
        None => {
            let scheme = if cfg.server.tls_cert.is_some() && cfg.server.tls_key.is_some() {
                "https"
            } else {
                "http"
            };
            format!("{}://{}:{}", scheme, cfg.server.domain, cfg.server.port)
                .parse()
                .expect("invalid domain/port in configuration")
        }
    };

    let webauthn = WebauthnService::new(cfg.server.domain.as_str(), &base_url)
        .expect("failed to build WebAuthn service (check `domain` in config)");

    let cors_origins: Vec<Url> = cfg
        .security
        .cors_origins
        .iter()
        .map(|s| {
            s.parse::<Url>()
                .unwrap_or_else(|e| panic!("invalid CORS origin '{s}' in configuration: {e}"))
        })
        .collect();

    let state = Arc::new(AppState::new(
        store, webauthn, oidc_key, base_url, vsid_salt,
    ));
    let api_router = build_router(state, &cors_origins);

    // Optionally serve the pre-built Qwik UI from the configured directory.
    // API routes always take priority; any unmatched path is handled by
    // ServeDir, which falls back to `index.html` for SPA client-side routing.
    if let Some(ref dir) = cfg.server.ui_dist_dir {
        tracing::info!(path = %dir.display(), "serving UI static files");
    }
    let app = apply_ui_fallback(api_router, cfg.server.ui_dist_dir.as_deref());

    // -- Server --------------------------------------------------------------
    // Parse the host as an IpAddr first so that IPv6 addresses are bracketed
    // correctly in the resulting SocketAddr (e.g. `::1` → `[::1]:8080`).
    let ip: std::net::IpAddr = cfg
        .server
        .host
        .parse()
        .expect("invalid `server.host` in configuration");
    let addr = SocketAddr::new(ip, cfg.server.port);

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
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("TLS server error");
        }
        (None, None) => {
            tracing::warn!(
                %addr,
                domain = %cfg.server.domain,
                tls = false,
                session_ttl_secs = cfg.security.session_ttl_seconds,
                "TLS not configured — running plain HTTP (use Caddy or configure tls_cert/tls_key)"
            );
            axum_server::bind(addr)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("HTTP server error");
        }
        // Refuse to start when only one of (tls_cert, tls_key) is set.
        // Falling back to plain HTTP in this case (the previous behaviour)
        // would silently disable TLS in production whenever an operator
        // typo'd a single path, defeating the entire transport-security
        // guarantee. A hard failure forces the misconfiguration to surface
        // at startup rather than after public exposure.
        (Some(_), None) => {
            panic!(
                "server.tls_cert is set but server.tls_key is missing — \
                 both must be set together (HTTPS) or both omitted (plain HTTP)"
            );
        }
        (None, Some(_)) => {
            panic!(
                "server.tls_key is set but server.tls_cert is missing — \
                 both must be set together (HTTPS) or both omitted (plain HTTP)"
            );
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
