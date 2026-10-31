FROM rust:latest AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY static ./static
RUN cargo build --release --locked

FROM debian:bookworm-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 appuser && mkdir -p /app/data && chown -R appuser:appuser /app
COPY --from=builder /app/target/release/retone /usr/local/bin/retone
COPY --from=builder /app/static /app/static
USER appuser
ENV DATABASE_URL=sqlite://data/retone.db?mode=rwc
EXPOSE 3000
CMD ["retone"]

