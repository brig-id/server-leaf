# ---------------------------------------------------------------------------
# brig·id leaf — multi-stage production image
#
# Three stages:
#   1. ui-builder  — Node.js: build the Qwik UI → dist/
#   2. rust-builder — Rust: compile the leaf binary (release)
#   3. runtime     — distroless: leaf binary + UI static files
#
# Prepare the UI source before building (option A — local copy):
#   cp -r /workspaces/app ./ui   # or: ln -sf ../app ui
#   docker build -t brigid/leaf:dev .
#
# Named-context variant (BuildKit, recommended for CI):
#   docker buildx build \
#     --build-context ui-src=/path/to/brig-id-app \
#     -t brigid/leaf:dev .
#
# For local development without rebuilding the image, use:
#   docker compose -f deploy/compose.dev.yaml up
# (the compose file bind-mounts a pre-built ui/dist from the host).
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Stage 1 — UI Build
# ---------------------------------------------------------------------------
# The `ui/` directory in the build context must contain the brig-id/app
# source (package.json, src/, public/, …). A placeholder `ui/.gitkeep` is
# committed to the repo; populate it before running `docker build`.
#
# If no package.json is found (placeholder only), the stage creates an empty
# dist/ so that the runtime stage still copies a valid (though empty) path.
# In that case, set LEAF_SERVER__UI_DIST_DIR to an actual dist in production.
#
# The app repo depends on the private Web Awesome Pro npm registry. Pass its
# token via a BuildKit secret mount — never a --build-arg, which would land
# the token in the image's build history:
#   docker buildx build --secret id=npm_token,env=WEBAWESOME_NPM_TOKEN ...
#
# UNSPLASH_ACCESS_KEY is the opposite case: it's Unsplash's own public/
# client-facing key (their docs show it embedded client-side in "Demo" apps)
# and is *meant* to ship inside the built JS bundle (app/src/lib/unsplash.ts
# fetches Unsplash directly from the browser). A plain ARG is correct here —
# a --secret mount would keep it out of the image, which is the wrong
# property for a value that must end up in client-visible output anyway.
FROM node:22-slim AS ui-builder
WORKDIR /ui
# Pin the pnpm version matching the app repo's packageManager field.
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable
ARG UNSPLASH_ACCESS_KEY=""
ENV UNSPLASH_ACCESS_KEY=$UNSPLASH_ACCESS_KEY
COPY ui/ ./
RUN --mount=type=secret,id=npm_token \
    if [ -f package.json ]; then \
      if [ -f /run/secrets/npm_token ]; then \
        echo "//npm.cloudsmith.io/fortawesome/webawesome-pro/:_authToken=$(cat /run/secrets/npm_token)" >> /root/.npmrc; \
      fi && \
      pnpm install --frozen-lockfile && \
      pnpm build; \
    else \
      mkdir -p dist; \
    fi

# ---------------------------------------------------------------------------
# Stage 2 — Build the Rust binary
# ---------------------------------------------------------------------------
# Pin the builder image to an immutable digest so rebuilds are deterministic
# and supply-chain risk from upstream tag movement is bounded. Bump the
# digest together with the human-readable tag when upgrading Rust.
FROM rust:1.88-slim@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS rust-builder

WORKDIR /build

# Cap parallel codegen jobs. This is a separate BuildKit build environment
# from the devcontainer's own shell — the devcontainer's CARGO_BUILD_JOBS
# setting (see roots/.devcontainer/devcontainer.json) does not reach here,
# and this workspace's dependency graph (sqlx macros, tonic/prost codegen,
# ml-kem/ml-dsa, rustls, axum, ...) can spawn enough concurrent rustc
# processes to exhaust a host's memory during `cargo build --release`
# below, which is a plausible trigger for host-level instability on a
# memory-constrained Docker Desktop setup.
ENV CARGO_BUILD_JOBS=4

# Pre-create an empty, nonroot-owned /data directory to copy into the
# runtime stage below. The distroless image has no shell, so `RUN mkdir`
# can't happen there — and without this, a fresh named volume mounted at
# /data inherits root:root ownership from Docker's default volume
# initialization, which the `nonroot` runtime user (UID 65532) can't write
# to, so SQLite fails with "unable to open database file" on first start.
RUN mkdir -p /data

# Install build-time dependencies:
#   - pkg-config + libssl-dev: required because `webauthn-rs`'s attestation
#     CA chain validator (`webauthn-attestation-ca`) pulls in `openssl-sys`
#     transitively. This is the single documented OpenSSL exception to the
#     "no OpenSSL" rule in `core/AGENTS.md` §"Hard security constraints"
#     and is scoped to attestation chain verification only — TLS, KEM, DSA
#     and KDF stay on rustls / RustCrypto. `Cargo.lock` does not contain
#     `openssl-src`, so the build links against the system OpenSSL headers
#     at compile time. The resulting binary is dynamically linked against
#     `libssl` / `libcrypto`; the distroless runtime stage below
#     (`gcr.io/distroless/cc-debian12`) ships matching `libssl3` /
#     `libcrypto3` shared libraries from the same Debian 12 (bookworm) base
#     used by `rust:1.88-slim`, so the binary loads cleanly in the final
#     image. `rust:1.89-slim` and later move to Debian 13 (trixie) — do not
#     bump past 1.88 without also re-checking this ABI match. If the runtime
#     base ever drifts off Debian 12, pin
#     `openssl = { version = "0.10", features = ["vendored"] }` in
#     `Cargo.toml` (and add `perl`, `make` here) to statically embed
#     OpenSSL. A bounded `0.10` requirement is mandatory: a wildcard `"*"`
#     would trip `cargo-deny`'s `[bans].wildcards = "warn"` policy and
#     remove version control over a security-sensitive crate.
#   - ca-certificates: needed for `cargo` to fetch git dependencies over HTTPS
#     during the dependency-resolution step.
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy manifests first so dependency layers are cached separately from source.
COPY Cargo.toml Cargo.lock ./

# Build a dummy binary to cache all dependencies.
RUN mkdir src && echo 'fn main() {}' > src/main.rs && \
    echo 'pub fn dummy() {}' > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

# Copy real source files.
COPY src/ ./src/

# Force recompile of the application code (preserve cached deps).
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --locked

# ---------------------------------------------------------------------------
# Stage 3 — Runtime (distroless, minimal attack surface)
# ---------------------------------------------------------------------------
# Pin runtime image to an immutable digest — same rationale as the builder:
# deterministic rebuilds and bounded supply-chain exposure. The `cc-debian12`
# variant ships `libssl3`/`libcrypto3` matching the `rust:1.88-slim` builder
# above (see the libssl comment), so the dynamically-linked binary loads
# cleanly. Re-pin whenever the runtime base is refreshed.
#
# This MUST be the multi-arch index digest (mediaType
# application/vnd.oci.image.index.v1+json), not a single-platform manifest
# digest — pinning the latter silently locks this FROM to one architecture
# regardless of `--platform` during a multi-arch buildx build, so an arm64
# leaf binary gets copied into an amd64 base and fails at container start
# with "exec: no such file or directory" (missing aarch64 interpreter).
# Verify with: docker manifest inspect gcr.io/distroless/cc-debian12@sha256:<digest>
# and check "mediaType" at the top level before trusting a re-pin.
FROM gcr.io/distroless/cc-debian12@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa AS runtime

# Copy the compiled binary from the Rust build stage.
COPY --from=rust-builder /build/target/release/leaf /leaf

# Copy the pre-built Qwik UI static files from the Node.js build stage.
# These are served by the leaf binary under LEAF_SERVER__UI_DIST_DIR.
COPY --from=ui-builder /ui/dist /ui/dist

# Nonroot-owned mount point for the SQLite database (see the /data comment
# in the rust-builder stage). Numeric UID:GID avoids relying on name
# resolution across stages.
COPY --from=rust-builder --chown=65532:65532 /data /data

# Run as non-root user (UID 65532 = nonroot in distroless).
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/leaf"]
