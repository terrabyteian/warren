# syntax=docker/dockerfile:1
#
# warren's container images, for linux/amd64 and linux/arm64. The binary is
# compiled on the build platform and cross-compiled for the other, so a
# multi-platform build never runs the compiler under emulation. Two targets
# share that one build:
#
#   warren            (default) distroless, nonroot: the `warren` binary and
#                     CA certificates. The control plane and the relay.
#   warren-connector  the same binary on Debian slim with iproute2 and
#                     nftables, which kernel-mode forwarding runs (`ip`,
#                     `nft`) to set up the TUN device and NAT.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -t warren .
#   docker buildx build --target warren-connector -t warren-connector .
#
# Base images are pinned by digest. cargo reads only vendor/
# (.cargo/config.toml) and never the network, as in CI.

ARG RUST_IMAGE=docker.io/library/rust:1.99.0-slim-trixie@sha256:2752b332db73fdbb7dc576f06c82ed1f312005784ef913d7e04a28f5f55dc581
ARG DISTROLESS_IMAGE=gcr.io/distroless/cc-debian13:nonroot@sha256:e792ab3d241a468a4fd7519ddbbebe66b49b5f365771716ea688ad40b6c6f1c2
ARG DEBIAN_IMAGE=docker.io/library/debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

FROM --platform=$BUILDPLATFORM ${RUST_IMAGE} AS build
ARG BUILDARCH
ARG TARGETARCH
# The image's toolchain is the one rust-toolchain.toml names; pinning it here
# keeps rustup from fetching the file's extra components.
ENV RUSTUP_TOOLCHAIN=1.99.0 CARGO_INCREMENTAL=0
# /env names the Rust target and, when cross-compiling, its C toolchain.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) target=x86_64-unknown-linux-gnu gnu=x86_64-linux-gnu ;; \
      arm64) target=aarch64-unknown-linux-gnu gnu=aarch64-linux-gnu ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    echo "target=$target" >/env; \
    if [ "$TARGETARCH" != "$BUILDARCH" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends "gcc-$(echo "$gnu" | tr _ -)" "libc6-dev-$TARGETARCH-cross"; \
      rm -rf /var/lib/apt/lists/*; \
      rustup target add "$target"; \
      t=$(echo "$target" | tr - _); \
      T=$(echo "$t" | tr a-z A-Z); \
      { echo "export CARGO_TARGET_${T}_LINKER=$gnu-gcc"; \
        echo "export CC_$t=$gnu-gcc"; \
        echo "export AR_$t=$gnu-ar"; } >>/env; \
    fi
WORKDIR /src
COPY . .
RUN set -eu; \
    . /env; \
    cargo build --release -p warren --no-default-features \
      --features control-plane,relay,connector --target "$target" --locked --offline; \
    install -D -m 0755 "target/$target/release/warren" /out/usr/bin/warren; \
    install -D -m 0644 LICENSE /out/usr/share/doc/warren/LICENSE

FROM ${DEBIAN_IMAGE} AS warren-connector
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates iproute2 nftables \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /
ENTRYPOINT ["/usr/bin/warren"]

FROM ${DISTROLESS_IMAGE} AS warren
COPY --from=build /out/ /
USER nonroot
ENTRYPOINT ["/usr/bin/warren"]
