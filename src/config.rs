//! Configuration loading for `leaf`.
//!
//! Configuration is merged in this order (later entries win):
//! 1. `leaf.toml` (path overridable via `--config`)
//! 2. Environment variables with the `LEAF_` prefix, using `__` as the
//!    nesting separator (e.g. `LEAF_SERVER__PORT=9000` → `server.port`).
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

/// Load the merged configuration from `config_path` + environment variables.
#[allow(clippy::result_large_err)] // figment::Error is inherently large; not reducible.
pub fn load(config_path: &std::path::Path) -> Result<Config, figment::Error> {
    Figment::new()
        .merge(Toml::file(config_path))
        .merge(Env::prefixed("LEAF_").split("__"))
        .extract()
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
    fn cors_origins_default_empty() {
        let cfg = load_value(minimal());
        assert!(cfg.security.cors_origins.is_empty());
    }
}
