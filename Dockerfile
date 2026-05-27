# ---------------------------------------------------------------------------
# Stage 1 — Build
# ---------------------------------------------------------------------------
FROM rust:1.85-slim AS builder

WORKDIR /build

# Install pkg-config (required by the bundled libsqlite3-sys build to locate
# compile-time dependencies during the Rust build stage).
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config && \
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
FROM gcr.io/distroless/cc-debian12

# Copy the compiled binary from the build stage.
COPY --from=builder /build/target/release/leaf /leaf

# Run as non-root user (UID 65532 = nonroot in distroless).
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/leaf"]
