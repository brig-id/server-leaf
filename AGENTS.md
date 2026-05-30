# AGENTS.md — brig·id `server-leaf`

This repository contains the **single-server deployment binary** for brig·id.
It wires together all `core` crates into a production-ready executable.

## Language

**All content must be in English** — code, comments, doc-comments, commit messages,
issues, pull requests. No exceptions.

## Scope

- Binary `leaf` (`src/main.rs`) — the only entry point
- Configuration loading (`leaf.toml` + env vars via `figment`)
- Docker multi-stage build + distroless image
- Docker Compose deploy setup (`deploy/`)
- E2E smoke tests (`tests/e2e/`)

This repository contains **no business logic**. All logic lives in `brig-id/core`.

## Current phase

**Phase 7** — see `/workspaces/.dev/phases/phase-7.md` for the full checklist.

## Hard security constraints

- **`BRIGID_MASTER_KEY` must never appear in `leaf.toml`** — env var or separate secret file only.
- **Refuse to start** if `MASTER_KEY` is absent or decodes to fewer than 32 bytes.
- **TLS 1.3 minimum** — configured via rustls `ServerConfig`; no OpenSSL
  for TLS. The build container does install `libssl-dev` for
  `webauthn-rs`'s attestation chain validator only (see `core/AGENTS.md`
  for the documented scope of that exception); attestation never touches
  the TLS stack.
- **Distroless Docker image** (`gcr.io/distroless/cc-debian12`) — no shell, no package manager.
- **Non-root user** — `USER nonroot:nonroot` in the final Docker stage.
- **Read-only container filesystem** — `read_only: true` + tmpfs on `/tmp` in compose.yaml.
- **Docker secrets** for `BRIGID_MASTER_KEY` — never a plaintext value in compose files.
- **Graceful shutdown** — handle `SIGTERM`/`SIGINT`; SQLite must not be left in a corrupt state.

## Configuration file shape

```toml
[server]
host   = "0.0.0.0"
port   = 8080
domain = "example.com"   # RP ID (WebAuthn) + issuer (OIDC)
tls_cert = "/certs/cert.pem"
tls_key  = "/certs/key.pem"

[database]
path = "/data/brigid.db"

[security]
# BRIGID_MASTER_KEY comes from env — never here
session_ttl_seconds = 3600
cors_origins = ["https://example.com"]
```

## Key crates

- `brigid-api` (core git dep) — Axum application
- `brigid-store` (core git dep) — SQLite init + migrations
- `brigid-crypto` (crypto git dep) — MASTER_KEY loading
- `clap` — CLI argument parsing
- `figment` — config merging (TOML + env)
- `tokio` (full), `tracing-subscriber` (JSON logs)

## Commands

```bash
cargo build --release -p leaf
docker build -t brigid/leaf .
docker compose -f deploy/compose.dev.yaml up
curl http://localhost:8080/health
```
