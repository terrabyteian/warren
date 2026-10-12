#!/usr/bin/env bash
# Installs the CI-only tools for the chart in charts/warren: Helm (lint,
# template tests, the end-to-end test) and kind (the end-to-end test's
# cluster), each a pinned release verified against a pinned SHA-256 digest.
# These tools are never product dependencies. Linux x86_64 (CI) and macOS
# arm64 (local runs); kubectl comes from the system.
#
# Usage: scripts/install-kube-tools.sh DEST_DIR
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 DEST_DIR" >&2
  exit 2
fi
dest=$1

helm_version=3.22.0
kind_version=0.33.0
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    platform=linux-amd64
    helm_sha256=1e4ab49e429626cf6c6958d914248b78c9730803c2751b87627e171dc800e7bb
    kind_sha256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
    ;;
  Darwin-arm64)
    platform=darwin-arm64
    helm_sha256=4c9982a6cdeb458b60258df66b55398ca5b19293f6877faffe2909ad6f23dfe0
    kind_sha256=0c8c7dbe5e23594a198b786c4bc13dacc101fa6196b0cb0b23a1ca44e61f4b4f
    ;;
  *)
    echo "error: pinned binaries exist for Linux x86_64 and macOS arm64 only" >&2
    exit 1
    ;;
esac

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$dest"

fetch() {
  local url=$1 sha=$2 out=$3
  curl --proto '=https' --tlsv1.2 -sSfL -o "$out" "$url"
  if [ "$(uname -s)" = Linux ]; then
    echo "$sha  $out" | sha256sum --check --strict --quiet
  else
    echo "$sha  $out" | shasum -a 256 --check --strict --quiet
  fi
}

fetch "https://get.helm.sh/helm-v$helm_version-$platform.tar.gz" "$helm_sha256" "$work/helm.tar.gz"
tar -xzf "$work/helm.tar.gz" -C "$work"
install -m 0755 "$work/$platform/helm" "$dest/helm"

fetch "https://github.com/kubernetes-sigs/kind/releases/download/v$kind_version/kind-$platform" \
  "$kind_sha256" "$work/kind"
install -m 0755 "$work/kind" "$dest/kind"

"$dest/helm" version --short
"$dest/kind" version
