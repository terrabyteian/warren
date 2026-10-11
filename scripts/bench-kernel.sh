#!/usr/bin/env bash
# Kernel-mode benchmarks in network namespaces: ordinary TCP from a client
# namespace to an app namespace through warren (TUN on both ends, through
# the relay, connector forwarding with NAT), against TLS over TCP and plain
# TCP over the same links with ordinary routing, and WireGuard over the
# same links when the kernel and tools offer it. Prints one JSON line per
# run and, with --summary FILE, appends a Markdown table.
#
# Linux only; needs root. Benchmarks are informative, never a gate.
# Usage: sudo scripts/bench-kernel.sh [BIN_DIR] [SECONDS] [--summary FILE]
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/netns-lib.sh
. scripts/netns-lib.sh

BIN=${1:-target/release}
SECONDS_PER_RUN=${2:-5}
SUMMARY=""
if [ "${3:-}" = "--summary" ]; then
  SUMMARY=${4:?--summary needs a file}
fi

cleanup() {
  netns_cleanup
  [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
}
trap cleanup EXIT

netns_setup
start_deployment "$BIN"
results="$WORK/results.jsonl"

# warren over QUIC and over the HTTP/2 fallback.
for transport in quic h2; do
  client --transport "$transport" --tun wc0 --route 10.77.0.0/24 \
    --bench-echo 10.77.0.10:7 --bench-sink 10.77.0.10:9 --seconds "$SECONDS_PER_RUN" |
    jq -c --arg t "$transport" 'select(.bench == "warren") | { name: ("warren (" + $t + ")"), setup_ms, results }' >>"$results"
done

# Baselines over the same links with plain IP forwarding to 10.77.0.11.
for ns in "$NS_RELAY" "$NS_CONN"; do
  in_ns "$ns" sysctl -qw net.ipv4.ip_forward=1
done
in_ns "$NS_CLI" ip route add 10.77.0.11/32 via 172.31.2.1
in_ns "$NS_RELAY" ip route add 10.77.0.11/32 via 172.31.1.2
in_ns "$NS_CONN" ip route add 172.31.2.0/24 via 172.31.1.1
in_ns "$NS_APP" ip route add 172.31.2.0/24 via 10.77.0.1
in_ns "$NS_CLI" "$HARNESS" bench --mode tls --target 10.77.0.11:8443 --server-name relay.lab.test \
  --ca "$WORK/pki/trust/root-ca.pem" --seconds "$SECONDS_PER_RUN" |
  jq -c '{ name: "TLS 1.3 over TCP", results }' >>"$results"
in_ns "$NS_CLI" "$HARNESS" bench --mode tcp --echo 10.77.0.11:7 --sink 10.77.0.11:9 --seconds "$SECONDS_PER_RUN" |
  jq -c '{ name: "plain TCP (no encryption)", results }' >>"$results"

# WireGuard from the client to the connector namespace, when available.
if command -v wg >/dev/null && in_ns "$NS_CLI" ip link add wgbench type wireguard 2>/dev/null; then
  in_ns "$NS_CLI" ip link del wgbench
  ck=$(wg genkey)
  sk=$(wg genkey)
  cp=$(printf '%s' "$ck" | wg pubkey)
  sp=$(printf '%s' "$sk" | wg pubkey)
  in_ns "$NS_CONN" ip link add wg0 type wireguard
  in_ns "$NS_CONN" bash -c "wg set wg0 listen-port 51820 private-key <(printf '%s' '$sk') peer '$cp' allowed-ips 10.99.0.2/32"
  in_ns "$NS_CONN" ip addr add 10.99.0.1/24 dev wg0
  in_ns "$NS_CONN" ip link set wg0 mtu 1420 up
  in_ns "$NS_CLI" ip link add wg0 type wireguard
  in_ns "$NS_CLI" bash -c "wg set wg0 private-key <(printf '%s' '$ck') peer '$sp' allowed-ips 10.77.0.12/32,10.99.0.1/32 endpoint 172.31.1.2:51820"
  in_ns "$NS_CLI" ip addr add 10.99.0.2/24 dev wg0
  in_ns "$NS_CLI" ip link set wg0 mtu 1420 up
  in_ns "$NS_CLI" ip route add 10.77.0.12/32 dev wg0
  in_ns "$NS_CLI" ip route add 172.31.1.0/24 via 172.31.2.1
  in_ns "$NS_APP" ip addr add 10.77.0.12/24 dev eth0
  in_ns "$NS_APP" ip route add 10.99.0.0/24 via 10.77.0.1
  in_ns "$NS_CLI" "$HARNESS" bench --mode tcp --echo 10.77.0.12:7 --sink 10.77.0.12:9 --seconds "$SECONDS_PER_RUN" 2>/dev/null |
    jq -c '{ name: "WireGuard (kernel)", results }' >>"$results" ||
    echo '{"name":"WireGuard (kernel)","skipped":"benchmark failed"}' >>"$results"
else
  echo '{"name":"WireGuard (kernel)","skipped":"wireguard unavailable"}' >>"$results"
fi

cat "$results"
if [ -n "$SUMMARY" ]; then
  {
    echo "### Kernel-mode benchmarks (${SECONDS_PER_RUN}s runs, $(uname -r), $(nproc) CPUs)"
    echo
    echo "| path | tunnel setup p50 (ms) | TCP connect p50 (ms) | RTT 64 B p50 / p99 (ms) | TCP throughput (Mbit/s) |"
    echo "| --- | --- | --- | --- | --- |"
    jq -r 'if .skipped then "| \(.name) | skipped: \(.skipped) | | | |"
      else "| \(.name) | \(.setup_ms // "n/a" | if type == "number" then (. * 100 | round / 100) else . end) | \(.results.connect.p50_ms) | \(.results.rtt_64b.p50_ms) / \(.results.rtt_64b.p99_ms) | \(.results.throughput_mbps | round) |" end' "$results"
  } >>"$SUMMARY"
fi
