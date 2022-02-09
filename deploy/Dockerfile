FROM lukemathwalker/cargo-chef:latest-rust-bullseye AS chef
WORKDIR /app

# Prepare deps
FROM chef AS planner
COPY ./server .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY ./server .
RUN cargo build --release --locked

FROM debian:buster-slim AS runtime
RUN apt-get update && apt-get upgrade -y && apt-get --no-install-recommends install -y libpq5 && apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=builder /app/target/release/server /app/server

EXPOSE 8080
ENTRYPOINT ["/app/server", "--config-path", "/app/config.toml"]
