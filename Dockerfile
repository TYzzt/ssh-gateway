FROM rust:1.93-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home gateway
COPY --from=builder /src/target/release/sshmcp /usr/local/bin/sshmcp
USER gateway
ENV SSHMCP_CONFIG_PATH=/config/profiles.yaml
ENV XDG_DATA_HOME=/data
EXPOSE 8765
ENTRYPOINT ["sshmcp"]
CMD ["serve"]
