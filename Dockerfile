FROM rust:1.88-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home gateway
COPY --from=builder /src/target/release/ssh-gateway /usr/local/bin/ssh-gateway
USER gateway
ENV ARRT_CONFIG_PATH=/config/profiles.yaml
ENV XDG_DATA_HOME=/tmp/ssh-gateway-data
EXPOSE 8765
ENTRYPOINT ["ssh-gateway"]
CMD ["serve"]
