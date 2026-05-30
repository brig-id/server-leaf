# ---------------------------------------------------------------------------
# Stage 1 — Build
# ---------------------------------------------------------------------------
# Pin the builder image to an immutable digest so rebuilds are deterministic
# and supply-chain risk from upstream tag movement is bounded. Bump the
# digest together with the human-readable tag when upgrading Rust.
FROM rust:1.85-slim@sha256:3490aa77d179a59d67e94239cca96dd84030b564470859200f535b942bdffedf AS builder

WORKDIR /build

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
#     used by `rust:1.85-slim`, so the binary loads cleanly in the final
#     image. If the runtime base ever drifts off Debian 12, pin
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
    cargo build --release --locked && \
    rm -rf src

# Copy real source files.
COPY src/ ./src/

# Force recompile of the application code (preserve cached deps).
RUN touch src/main.rs && \
    cargo build --release --locked

# ---------------------------------------------------------------------------
# Stage 2 — Runtime (distroless, minimal attack surface)
# ---------------------------------------------------------------------------
# Pin runtime image to an immutable digest — same rationale as the builder:
# deterministic rebuilds and bounded supply-chain exposure. The `cc-debian12`
# variant ships `libssl3`/`libcrypto3` matching the `rust:1.85-slim` builder
# above (see the libssl comment), so the dynamically-linked binary loads
# cleanly. Re-pin whenever the runtime base is refreshed.
FROM gcr.io/distroless/cc-debian12@sha256:5882a8b7d32186f9366147e7d6908c0628db04675476caf7afe3d5794cb6e1b6

# Copy the compiled binary from the build stage.
COPY --from=builder /build/target/release/leaf /leaf

# Run as non-root user (UID 65532 = nonroot in distroless).
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/leaf"]
