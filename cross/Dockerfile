FROM ghcr.io/cross-rs/aarch64-unknown-linux-gnu:edge

RUN dpkg --add-architecture arm64
RUN dpkg --add-architecture amd64

RUN apt-get update && apt-get install --assume-yes \
    libssl-dev:arm64 \
    libzstd-dev:arm64 \
    libssl-dev:amd64 \
    libzstd-dev:amd64

