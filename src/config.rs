//! Configuration loading for `leaf`.
//!
//! Configuration is assembled from up to two sources, in this order
//! (later entries override earlier ones):
//! 1. A TOML file, **only when** an explicit `--config <path>` is supplied
//!    on the command line (`load(Some(path))`). There is **no** auto-discovery
//!    of `leaf.toml` from the working directory.
//! 2. Environment variables with the `LEAF_` prefix, using `__` as the
//!    nesting separator (e.g. `LEAF_SERVER__PORT=9000` → `server.port`).
//!
//! When `--config` is omitted, the configuration comes entirely from
//! `LEAF_*` environment variables (plus the `#[serde(default)]` defaults).
//!
//! `BRIGID_MASTER_KEY` is **always** read separately from the environment —
//! it must never appear in `leaf.toml`.

use std::path::PathBuf;

use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;

/// Top-level configuration struct.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub security: SecurityConfig,
}

/// HTTP/TLS server settings.
#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Bind host (e.g. `"0.0.0.0"` or `"127.0.0.1"`).
    #[serde(default = "default_host")]
    pub host: String,

    /// Bind port (e.g. `8080`).
    #[serde(default = "default_port")]
    pub port: u16,

    /// Public domain name — used as the WebAuthn RP ID and OIDC issuer.
    pub domain: String,

    /// Override for the public base URL (e.g. `"https://example.com"`).
    ///
    /// When set, this is used as the OIDC issuer and WebAuthn origin instead
    /// of the value inferred from `domain` and `port`. Use this when the leaf
    /// binary runs behind a reverse proxy that handles TLS and serves on a
    /// different public port (e.g. Caddy on 443 → leaf on 8080).
    pub public_url: Option<String>,

    /// Path to the TLS certificate PEM file. Required for HTTPS.
    pub tls_cert: Option<PathBuf>,

    /// Path to the TLS private key PEM file. Required for HTTPS.
    pub tls_key: Option<PathBuf>,
}

/// Database settings.
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// SQLite database file path (e.g. `"/data/brigid.db"`).
    /// Use `":memory:"` for in-memory databases (tests only).
    #[serde(default = "default_db_path")]
    pub path: String,
}

/// Security settings.
#[derive(Debug, Deserialize)]
pub struct SecurityConfig {
    /// ID token lifetime in seconds (default: 3600).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,

    /// Allowed CORS origins (e.g. `["https://example.com"]`).
    #[serde(default)]
    pub cors_origins: Vec<String>,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_db_path() -> String {
    "/data/brigid.db".to_string()
}

fn default_session_ttl() -> u64 {
    3600
}

/// Load the merged configuration.
///
/// `config_path` is optional — when `None`, configuration is read entirely
/// from `LEAF_*` environment variables (intended for container deployments
/// where TOML files complicate secret management).
#[allow(clippy::result_large_err)] // figment::Error is inherently large; not reducible.
pub fn load(config_path: Option<&std::path::Path>) -> Result<Config, figment::Error> {
    let mut figment = Figment::new();
    if let Some(path) = config_path {
        figment = figment.merge(Toml::file(path));
    }
    figment.merge(Env::prefixed("LEAF_").split("__")).extract()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::Serialized;

    fn minimal() -> serde_json::Value {
        serde_json::json!({
            "server": { "domain": "localhost" },
            "database": {},
            "security": {}
        })
    }

    fn load_value(v: serde_json::Value) -> Config {
        Figment::new()
            .merge(Serialized::defaults(v))
            .extract()
            .expect("config parse failed")
    }

    #[test]
    fn defaults_are_applied() {
        let cfg = load_value(minimal());
        assert_eq!(cfg.server.host, "0.0.0.0");
        assert_eq!(cfg.server.port, 8080);
        assert_eq!(cfg.security.session_ttl_seconds, 3600);
        assert!(cfg.security.cors_origins.is_empty());
        assert!(cfg.server.tls_cert.is_none());
        assert!(cfg.server.tls_key.is_none());
    }

    #[test]
    fn domain_is_required() {
        let result: Result<Config, _> = Figment::new()
            .merge(Serialized::defaults(serde_json::json!({
                "server": {},
                "database": {},
                "security": {}
            })))
            .extract();
        assert!(result.is_err(), "missing domain must produce an error");
    }

    #[test]
    fn custom_values_are_respected() {
        let cfg = load_value(serde_json::json!({
            "server": {
                "host": "127.0.0.1",
                "port": 9090,
                "domain": "example.com",
                "tls_cert": "/certs/cert.pem",
                "tls_key": "/certs/key.pem"
            },
            "database": { "path": "/data/brigid.db" },
            "security": {
                "session_ttl_seconds": 7200,
                "cors_origins": ["https://example.com"]
            }
        }));
        assert_eq!(cfg.server.host, "127.0.0.1");
        assert_eq!(cfg.server.port, 9090);
        assert_eq!(cfg.server.domain, "example.com");
        assert_eq!(cfg.security.session_ttl_seconds, 7200);
        assert_eq!(cfg.security.cors_origins, ["https://example.com"]);
        assert!(cfg.server.tls_cert.is_some());
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail closure must return figment::Error.
    fn env_vars_override_toml_defaults() {
        // Validates that environment variables in the LEAF_SECTION__KEY format
        // correctly override TOML defaults via figment's Env provider.
        // Jail serialises env-var access to prevent interference with parallel tests.
        figment::Jail::expect_with(|jail| {
            jail.set_env("LEAF_SERVER__HOST", "10.0.0.1");
            jail.set_env("LEAF_SERVER__PORT", "9999");
            jail.set_env("LEAF_SERVER__DOMAIN", "env.example.com");
            jail.set_env("LEAF_DATABASE__PATH", "/tmp/env-test.db");
            jail.set_env("LEAF_SECURITY__SESSION_TTL_SECONDS", "7200");

            let cfg: Config = Figment::new()
                .merge(Serialized::defaults(minimal()))
                .merge(figment::providers::Env::prefixed("LEAF_").split("__"))
                .extract()?;

            assert_eq!(cfg.server.host, "10.0.0.1");
            assert_eq!(cfg.server.port, 9999);
            assert_eq!(cfg.server.domain, "env.example.com");
            assert_eq!(cfg.database.path, "/tmp/env-test.db");
            assert_eq!(cfg.security.session_ttl_seconds, 7200);
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::result_large_err)] // figment::Jail closure must return figment::Error.
    fn cors_origins_can_be_set_via_env() {
        // `cors_origins` is a `Vec<String>`. Figment's Env provider with
        // `split("__")` accepts a TOML-array-literal-encoded string for
        // sequence fields (e.g. `["https://a","https://b"]`); the
        // `deploy/compose.yaml` template relies on this encoding to push the
        // production origin list through `LEAF_SECURITY__CORS_ORIGINS`.
        figment::Jail::expect_with(|jail| {
            jail.set_env(
                "LEAF_SECURITY__CORS_ORIGINS",
                "[\"https://a.example\",\"https://b.example\"]",
            );
            let cfg: Config = Figment::new()
                .merge(Serialized::defaults(minimal()))
                .merge(figment::providers::Env::prefixed("LEAF_").split("__"))
                .extract()?;

            assert_eq!(
                cfg.security.cors_origins,
                vec![
                    "https://a.example".to_string(),
                    "https://b.example".to_string(),
                ]
            );
            Ok(())
        });
    }
}
