# Changelog

All notable changes to `server-seedling` (named `server-leaf` up to 0.3.0) are documented
in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **This edition is named seedling** (was leaf). The repository is
  `server-seedling`, the binary and its commands `seedling`, the image
  `ghcr.io/brig-id/seedling`, the metrics `brigid_http_*`.
- **Settings are read under the `BRIGID_` prefix** (`BRIGID_SERVER__DOMAIN`…),
  the same for the three editions. The earlier `LEAF_` prefix is still read
  for now, below it, with a warning at start that names the settings to rename.
- **Licence: AGPL-3.0-or-later** (was LGPL-3.0-or-later). Released versions
  keep the licence they were published under.
- The server's DID document (`/.well-known/did.json`) is no longer served.
- **The Content Security Policy of the interface names no other origin**:
  the font host and the photo API it used to allow are gone, with the
  interface that needed them (brig-id/app#63). `form-action 'self'` is added.
  A test fails if a scheme, a host or a wildcard comes back into it.
- The image is built with no secret: the interface no longer needs a
  registry token nor an API key.

### Added

- `security.signup_open` (default `true`): `false` closes the creation of
  accounts; sign-in and recovery are untouched.

- Websites can sign people in through `seedling` (brig-id/core#92):
  `/authorize`, `/token` and `/.well-known/openid-configuration` are served.
  Authorization Code flow with PKCE (`S256`, mandatory), ID tokens signed
  with EdDSA whose only statement about the person is an identifier for that
  site.
- `seedling client add --name <name> --redirect-uri <uri> [--public]`,
  `seedling client list` and `seedling client remove <client_id>` register the sites
  that may do so. `add` prints the `client_id` and, for a site with a secret,
  the `client_secret`, once: only its hash is stored.

## [0.3.0] - 2026-11-13

### Added

- Account recovery with a recovery code (`/account/recovery-code`,
  `/auth/recovery/*`), and passkey-only signup with a generated, hidden
  username, signed in by the same ceremony (brig-id/core#78).
- `security.session_lifetime_seconds` (default 43200, 12 h): an account
  session ends this long after sign-in, used or not.
- The bundled UI is app's current `main`: sign-in with the passkey alone
  (this server or another by domain), one-button signup with an onboarding
  page (passkey name from its provider, recovery code), "I lost my passkeys",
  and no session data in the browser's storage.

### Changed

- **Account sessions live in an HttpOnly cookie** (ADR-005 §1, brig-id/core#80):
  `__Host-brigid_session` over HTTPS, server-side session, no token in the
  browser's storage and no account id in URLs. `security.session_ttl_seconds`
  is now the idle timeout of a session. Requests that change something must
  come from the server's own origin. No token is issued for a caller-supplied
  `client_id` anymore, and `/.well-known/openid-configuration` is gone until
  the relying-party flow exists (ADR-005 §3).
- Registration asks for discoverable passkeys (`residentKey: required`):
  signing in takes no username, so the passkey must name the account.
- Identities and accounts are identified by UUIDs (ADR-007): the database
  migration drops the account and identity DID columns, and VSIDs are derived
  from the identity UUID. No relying party holds a VSID yet.
- `core` update: generic code comes from helpers4. Three checks are stricter:
  the `Bearer` scheme is matched case-insensitively and only RFC 6750 token
  characters are accepted; the server part of a username cannot be an IP
  address; an icon name cannot start or end with a hyphen.

### Upgrading

- Three database migrations run at start (recovery codes, DID columns
  dropped, sessions). **Every session in progress ends: users sign in again.**

## [0.2.1] - 2026-11-11

### Fixed

- The v0.2.0 image did not start: the binary was built on Debian trixie
  (`rust:1.89-slim`, glibc 2.41) for a bookworm runtime (glibc 2.36). The
  builder is pinned to `rust:1.89-slim-bookworm`, and CI now starts the binary
  in the built image.

### Changed

- The VSID secret is stored in the database instead of derived from the
  master key at each start (ADR-006 in the spec). `leaf rotate-key`
  re-encrypts it: **a master key rotation no longer changes every VSID**. An
  existing database keeps the value it was using, so no `sub` changes at the
  upgrade; a new one gets a random secret.

### Fixed

- Accounts can only be registered under this server's own domain, the account
  pages are no longer throttled right after signing in (their rate limit is
  separate from the sign-in ceremonies', 60 requests per minute), and an
  internal error logs its cause (`core` update).
- Rate limiting behind a reverse proxy. Every request reaches `leaf` from the
  proxy's address, so all clients shared one rate-limit bucket (20 requests
  per minute for the whole instance). `security.trust_forwarded_for`
  (`LEAF_SECURITY__TRUST_FORWARDED_FOR`) makes the limit apply per client IP
  read from `X-Forwarded-For`; `deploy/compose.yaml` turns it on. Off by
  default, since a directly reachable `leaf` must not trust that header.

## [0.2.0] - 2026-11-11

### Added

- `leaf healthcheck`: the binary probes its own `/health` (exit 0 on 200, 1
  otherwise), so the distroless image gets a Docker `HEALTHCHECK` without a
  shell or curl. The image and `deploy/compose.yaml` use it; Swarm now sees a
  crash-looping or hung leaf as unhealthy instead of only Caddy's 502s.
- `server.metrics_port` (`LEAF_SERVER__METRICS_PORT`): an internal listener
  serving Prometheus metrics at `/metrics` (request counts by method, matched
  route and status; latency histograms). Off by default; port 9100 on the
  internal overlay network in `deploy/compose.yaml`, never published.
- `leaf rotate-oidc-key`: makes a new OIDC signing key current. Signing keys
  are now stored (encrypted) in the database instead of derived from the
  master key; the previous key keeps verifying and stays in the JWKS for two
  hours, then is removed at a later start. On upgrade the derived key is
  stored under its old `kid` (`v1`), so issued tokens stay valid.
- Identities, templates, passkey names, username-less login, session check and
  refresh, identity tokens: from brig-id/core#72.
- The bundled UI is app's current `main`: signed-in shell with navigation,
  Identities page with an icon library, passkey names, passkey autofill and
  username-less sign-in, clearer unsupported-browser message (brig-id/app#32).

### Changed

- `leaf rotate-key` no longer invalidates issued tokens: the OIDC keys are
  re-encrypted, not re-derived.
- Rust 1.89 (MSRV and the image's builder), as core requires.
- Deleting an account's only passkey is refused (`409`), from core.

### Security

- The UI's Content-Security-Policy allows inline scripts and styles by hash,
  read from the `dist/csp-hashes.json` the UI build now writes, instead of
  `'unsafe-inline'` (core#20, app#3). An older UI build without the manifest
  falls back to `'unsafe-inline'` with a warning in the log.
- `ctutils` 0.4.8 (RUSTSEC-2026-0385, non-constant-time comparisons).

## [0.1.2] - 2026-09-05

### Fixed

- `deploy/compose.yaml`'s `restart: unless-stopped` is plain-Compose-only and
  silently ignored under `docker stack deploy` (Swarm mode); with no
  `deploy.restart_policy`, Swarm fell back to infinite retries every ~5s, so
  a broken deploy crash-looped forever instead of failing loudly. Added a
  bounded `restart_policy` (5 attempts, 5min window) to `leaf` and `caddy`.
- `main.rs` only ever called `MasterKey::from_env()`, never
  `MasterKey::from_file()`, even though `deploy/compose.yaml`'s Docker
  secrets setup (`BRIGID_MASTER_KEY_FILE`) — the only production path
  allowed by this repo's hard security constraints — depended on it. Every
  Docker-secrets deployment failed at startup with "master key environment
  variable not set". `BRIGID_MASTER_KEY_FILE` now takes precedence when set.

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
