#!/usr/bin/env bash
# In-process benchmarks: a relay, a connector (userspace test backend) and
# clients in one process on loopback, against TLS over TCP on loopback.
# Runs anywhere without privileges. Prints the JSON result and, with
# --summary FILE, appends a Markdown table.
#
# Usage: scripts/bench-inprocess.sh [BIN_DIR] [SECONDS] [--summary FILE]
set -euo pipefail

cd "$(dirname "$0")/.."

BIN=${1:-target/release}
SECS=${2:-5}
SUMMARY=""
if [ "${3:-}" = "--summary" ]; then
  SUMMARY=${4:?--summary needs a file}
fi

out=$("$BIN/warren-harness" bench --mode inprocess --seconds "$SECS" --label in-process)
printf '%s\n' "$out"
if [ -n "$SUMMARY" ]; then
  printf '%s\n' "$out" | jq -r '.results as $r |
    "### In-process benchmarks (\($r.os) \($r.arch), loopback)\n",
    "| path | setup p50 (ms) | RTT 64 B p50 / p99 (ms) | throughput (Mbit/s) |",
    "| --- | --- | --- | --- |",
    "| warren, UDP through relay and connector | \($r.warren.tunnel_setup.p50_ms) | \($r.warren.rtt_udp_64b.p50_ms) / \($r.warren.rtt_udp_64b.p99_ms) | \($r.warren.throughput_udp_1280b_mbps | round) (1280-byte packets, echoed) |",
    "| UDP direct to the same app | n/a | \($r.direct_udp.rtt_udp_64b.p50_ms) / \($r.direct_udp.rtt_udp_64b.p99_ms) | n/a |",
    "| TLS 1.3 over TCP | \($r.tls_over_tcp.connect.p50_ms) | \($r.tls_over_tcp.rtt_64b.p50_ms) / \($r.tls_over_tcp.rtt_64b.p99_ms) | \($r.tls_over_tcp.throughput_mbps | round) |",
    ""' >>"$SUMMARY"
fi
