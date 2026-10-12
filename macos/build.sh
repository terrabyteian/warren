#!/usr/bin/env bash
# Builds the macOS menu-bar app and its packet tunnel system extension,
# linking the client core's C interface (crates/warren-ffi), with swiftc
# and the Apple SDKs only. The result is unsigned: running a system
# extension needs a signature from an Apple Developer team, which the
# project does not have yet (docs/macos.md), so this proves the app builds
# and links and keeps it ready to sign.
#
# Usage: macos/build.sh [--release] [OUT_DIR]   (default: target/macos)
set -euo pipefail

cd "$(dirname "$0")/.."

profile=debug
cargo_profile=()
if [ "${1:-}" = "--release" ]; then
  profile=release
  cargo_profile=(--release)
  shift
fi
out=${1:-target/macos}

case "$(uname -m)" in
  arm64) arch=arm64 ;;
  x86_64) arch=x86_64 ;;
  *)
    echo "unsupported architecture $(uname -m)" >&2
    exit 1
    ;;
esac

# The app runs on macOS 13 and later (MenuBarExtra); the core's C parts
# must be built for the same minimum. A target directory of its own keeps
# that from rebuilding the normal build.
export MACOSX_DEPLOYMENT_TARGET=13.0
CARGO_TARGET_DIR="$out/cargo" cargo build -p warren-ffi ${cargo_profile[@]+"${cargo_profile[@]}"} --locked --offline
lib="$out/cargo/$profile"

app="$out/Warren.app"
ext_id=dev.warren.client.tunnel
ext="$app/Contents/Library/SystemExtensions/$ext_id.systemextension"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$ext/Contents/MacOS"

# The libraries the static library needs, from
# `cargo rustc -p warren-ffi --crate-type staticlib -- --print native-static-libs`.
common=(
  -target "$arch-apple-macos13.0"
  -swift-version 5
  -I macos/Shared
  -L "$lib"
  -framework Security
  -framework CoreFoundation
  -liconv
)
if [ "$profile" = release ]; then
  common+=(-O)
fi

swiftc "${common[@]}" -module-name WarrenTunnel -framework NetworkExtension \
  macos/Shared/WarrenCore.swift macos/Tunnel/PacketTunnelProvider.swift macos/Tunnel/main.swift \
  -o "$ext/Contents/MacOS/$ext_id"
cp macos/Tunnel/Info.plist "$ext/Contents/Info.plist"

swiftc "${common[@]}" -module-name Warren -parse-as-library \
  -framework SwiftUI -framework NetworkExtension -framework SystemExtensions \
  macos/Shared/WarrenCore.swift macos/App/WarrenApp.swift \
  -o "$app/Contents/MacOS/Warren"
cp macos/App/Info.plist "$app/Contents/Info.plist"

plutil -lint "$app/Contents/Info.plist" "$ext/Contents/Info.plist" \
  macos/App/Warren.entitlements macos/Tunnel/Tunnel.entitlements >/dev/null
echo "built $app (unsigned; $arch)"
