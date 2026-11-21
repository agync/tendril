FROM docker.io/library/rust:1.97.1-slim-trixie@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock README.md ./
COPY crates/ crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p tendril-relay --bin tendril-relay \
    && install -D -m 0755 target/release/tendril-relay /out/tendril-relay

FROM docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r -g 65532 tendril \
    && useradd -r -u 65532 -g 65532 -s /sbin/nologin tendril
COPY --from=builder /out/tendril-relay /usr/local/bin/tendril-relay
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/tendril-relay"]
CMD ["--listen", "0.0.0.0:8443"]
