# AGENTS.md — brig·id `server-leaf`

This repository contains the **single-server deployment binary** for brig·id.
It wires together all `core` crates into a production-ready executable.

## Language

**All content must be in English** — code, comments, doc-comments, commit messages,
issues, pull requests. No exceptions.

## Scope

- Binary `leaf` (`src/main.rs`) — the only entry point
- Configuration loading (`leaf.toml` + env vars via `figment`)
- Serving the pre-built `web` UI as static files (`server.ui_dist_dir`, SPA fallback) —
  the reference mechanism `server-grove`/`server-forest` are expected to follow
- Docker multi-stage build + distroless image
- Docker Compose deploy setup (`deploy/`)
- E2E smoke tests (`tests/e2e/`)

This repository contains **no business logic**. All logic lives in `brig-id/core`.

## Current phase

**Phase 3** — Integration & E2E. See `/workspaces/.dev/phases/phase-3.md`.

## Hard security constraints

- **`BRIGID_MASTER_KEY` must never appear in `leaf.toml`** — env var or separate secret file only.
- **Refuse to start** if `MASTER_KEY` is absent or decodes to fewer than 32 bytes.
- **TLS 1.3 minimum** — configured via rustls `ServerConfig`; no OpenSSL for TLS.
  The build container installs `libssl-dev` for `webauthn-rs`'s attestation chain
  validator only (see `core/AGENTS.md` for the documented scope of that exception);
  attestation never touches the TLS stack.
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

## Commit conventions

Format: `type(scope): <emoji> description`

| Type | Emoji | When |
| --- | --- | --- |
| `feat` | ✨ | New feature |
| `fix` | 🐛 | Bug fix |
| `docs` | 📝 | Documentation only |
| `chore` | 🔧 | Maintenance, config |
| `test` | ✅ | Tests |
| `refactor` | ♻️ | Restructuring, no behaviour change |
| `perf` | ⚡️ | Performance |
| `ci` | 👷 | CI/CD |
| `security` | 🔒 | Security fix or hardening |
| `build` | 📦 | Build system, dependencies |
| `revert` | ⏪ | Reverts a previous commit |

### Allowed scopes

| Scope | Maps to |
| --- | --- |
| `leaf` | `src/main.rs`, binary entry point |
| `config` | Configuration loading (`src/config.rs`) |
| `docker` | `Dockerfile`, `deploy/` |
| `ci` | `.github/workflows/` |
| `deps` | Dependency bumps |

**Do not use a scope outside this list.** If a new source file or concern is added,
update this table and `.vscode/settings.json`.

```text
feat(leaf): ✨ serve Qwik static assets from ui/dist/
fix(config): 🐛 reject partial TLS config at startup
ci(ci): 👷 add conventional commit check
chore(deps): 📦 bump brigid-api to latest core rev
```

## Commands

```bash
cargo build --release -p leaf
docker build -t brigid/leaf .
docker compose -f deploy/compose.dev.yaml up
curl http://localhost:8080/health
```

## Local dev without Docker (paired with `web`'s HTTPS setup)

Faster inner loop than `compose.dev.yaml` when iterating on `leaf` itself — run the
binary directly against the `web` dev server instead of a prebuilt `dist/`. Must match
`web`'s dev origin (`brigid.localhost:5173`, see `web/README.md`'s "HTTPS in dev"
section) or WebAuthn ceremonies fail with an origin/RP-ID mismatch.

```bash
export BRIGID_MASTER_KEY=$(openssl rand -hex 32)   # one-time per shell/machine — any 64 hex chars
export LEAF_DATABASE__PATH=./brigid-dev.db          # gitignored, auto-created on first run
export LEAF_SERVER__DOMAIN=brigid.localhost         # must equal web's dev host (WebAuthn RP ID)
export LEAF_SERVER__PUBLIC_URL=https://brigid.localhost:5173  # https — see web/README.md

cargo build -p leaf
"$CARGO_TARGET_DIR"/debug/leaf
```

Then in `web`: generate the mkcert cert once (`web/README.md`'s "HTTPS in dev"), and
`pnpm dev`. Open `https://brigid.localhost:5173/register/`.

**Currently all manual, no persistence across shells/rebuilds** — `BRIGID_MASTER_KEY`
must be re-exported every session, and the mkcert cert is regenerated per clone. Tracked
as a candidate for automation (a `dev.sh` script, or wiring into the devcontainer's
`postCreateCommand`) in `.dev/phases/backlog.md`.
