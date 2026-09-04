# Changelog

All notable changes to `server-leaf` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-09-04

### Fixed

- `Dockerfile`'s `gcr.io/distroless/cc-debian12` base and `deploy/compose.yaml`'s
  `caddy:2-alpine` image were both pinned to single-platform (amd64) manifest
  digests instead of the multi-arch index, so the arm64 leg of the multi-arch
  release build silently used amd64 base content — `leaf` crashed with
  `exec: no such file or directory` (missing aarch64 interpreter) and `caddy`
  with `exec format error` on arm64 hosts (found deploying to an Oracle
  Ampere A1 instance). Re-pinned to the correct index digests.
- `deploy/compose.yaml` never actually worked under `docker stack deploy`
  despite declaring a Swarm-only `secrets: external: true` — fixed
  `networks.internal.driver` (`bridge` → `overlay`, required for Swarm
  services) and `caddy.depends_on`'s long form (rejected by Swarm's stack
  schema) to the short list form.

## [0.1.0] - 2026-09-04

First tagged release, alongside `crypto`, `core`, and `app`.

### Added

- `leaf` binary: single-server brig·id deployment — loads TOML +
  `LEAF_*` env config via `figment`, requires `BRIGID_MASTER_KEY` (or
  `BRIGID_MASTER_KEY_FILE`) to start, opens/migrates the SQLite database,
  builds the `brigid-api` router, and serves it over TLS 1.3 (or plain
  HTTP for local dev) with graceful `SIGTERM`/Ctrl-C shutdown.
- `leaf rotate-key --old <path> --new <path>`: re-encrypts the entire
  database under a new master key via `brigid-store::rotate_master_key`,
  reading both keys from files only (never `argv`, an env var, or stdin).
  Prints the VSID- and OIDC-signing-key consequences of rotation to
  stderr on success.
- Serves the `brig-id/web` Qwik static (SSG) build as the UI, via
  `ServeDir` with SPA-style fallback for client-side routes.
- Security headers (`X-Content-Type-Options`, `X-Frame-Options`,
  `Strict-Transport-Security`, `Content-Security-Policy`) applied as the
  outermost layer, covering both the API and the static UI fallback.
- Docker: multi-stage build (Rust builder + `gcr.io/distroless/cc-debian12`
  runtime), non-root (`nonroot:nonroot`), read-only-filesystem-compatible,
  with a pre-chowned `/data` directory for the SQLite file.
- `docker-compose` deployment with a Caddy reverse proxy in front, TLS
  termination, and a smoke-test script (`smoke.sh`) exercising the
  discovery/health endpoints end to end.
- E2E smoke tests (`tests/smoke.rs`): spawn a real `leaf` subprocess and
  drive it over HTTP with a software WebAuthn authenticator — register,
  login, list/delete passkeys, and rate-limit enforcement (the 21st
  `/auth/*` request in a window returns `429`).
- `tests/rotate_key.rs`: full CLI lifecycle test — register under the old
  key over real HTTP, stop the server, run `rotate-key`, confirm the old
  key file no longer works, restart under the new key, and log in again.
- `tests/binary.rs`: startup/shutdown behavior — missing `MASTER_KEY`,
  missing config file, a valid config actually listens, graceful
  `SIGTERM` shutdown, and the port-already-in-use case.

### Fixed

- `SetResponseHeaderLayer`-based security headers previously missed the
  static-UI fallback route because they were applied before
  `.fallback_service()` in the Axum 0.8 layer stack (layers only cover
  routes that exist at the time `.layer()` is called); now applied after.
- A missing `--config` file was silently treated as "no config" by
  `figment` instead of failing loudly; `leaf` now checks the path exists
  before attempting to load it.
- `rotate-key`'s database-path extraction was reading from a figment tree
  shaped for the full `Config`, silently falling back to the default path
  instead of `LEAF_DATABASE__PATH`; fixed via an explicit `.focus("database")`.
- Distroless runtime's fresh named Docker volume for `/data` inherited
  `root:root` ownership, which the non-root container user couldn't write
  to; fixed by pre-creating and chowning `/data` in the builder stage and
  copying it into the runtime stage.
- `rust:1.85-slim` was too old to build the pinned `time@0.3.47`;
  repinned to `rust:1.88-slim` (last Debian bookworm tag), matching the
  distroless runtime's glibc.

### Security

- CSP currently allows `'unsafe-inline'` for `script-src`/`style-src` as a
  tracked stopgap — the Qwik SSG build emits inline scripts/styles that a
  strict CSP would otherwise block. Tracked in `.dev/phases/backlog.md`;
  the real fix is a build-time SHA-256 hash allowlist.
- `/auth/*` is rate-limited to a sustained 20 requests/minute per IP
  (burst 5, refill every 3s), keyed on the real TCP peer address unless a
  trusted reverse proxy is configured to set `x-forwarded-for`.
