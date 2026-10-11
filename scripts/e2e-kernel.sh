#!/usr/bin/env bash
# Kernel-mode end-to-end tests: the real `warren relay` and
# `warren connector` binaries and the test client, in network namespaces,
# with the connector forwarding through a TUN device and NAT. Covers a TCP
# and a UDP app through the relay, a name app, a deny with its reason code,
# the HTTP/2 fallback when UDP is blocked, the 1280-byte path MTU floor,
# server-initiated flows and the audit trail.
#
# Linux only; needs root (CI runs it with sudo).
# Usage: sudo scripts/e2e-kernel.sh [BIN_DIR]   (default: target/debug)
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=scripts/netns-lib.sh
. scripts/netns-lib.sh

BIN=${1:-target/debug}
failures=0

cleanup() {
  netns_cleanup
  if [ "$failures" -ne 0 ] && [ -n "${WORK:-}" ]; then
    echo "--- relay log" >&2
    tail -n 40 "$WORK/relay.log" >&2 || true
    echo "--- connector log" >&2
    tail -n 40 "$WORK/connector.log" >&2 || true
  fi
  [ -n "${WORK:-}" ] && rm -rf -- "$WORK"
}
trap cleanup EXIT

check() {
  local name=$1 filter=$2 file=$3
  if jq -e -s "$filter" "$file" >/dev/null; then
    echo "ok   $name"
  else
    echo "FAIL $name" >&2
    cat "$file" >&2
    failures=$((failures + 1))
  fi
}

netns_setup
start_deployment "$BIN"
out="$WORK/client.jsonl"

# 0. The relay and the connector joined with single-use tokens.
if grep -q 'joined the deployment' "$WORK/relay.log" && grep -q 'joined the deployment' "$WORK/connector.log"; then
  echo "ok   relay and connector joined with tokens"
else
  echo "FAIL relay and connector joined with tokens" >&2
  failures=$((failures + 1))
fi

# 1. QUIC: TCP, UDP and ICMP apps, a name app, and a deny with its reason.
client --transport quic --tun wc0 --route 10.77.0.0/24 --route 100.80.0.0/16 \
  --bind grafana.lab.test=grafana@100.80.0.5 \
  --probe tcp-echo=10.77.0.10:7 --probe udp-echo=10.77.0.10:7 \
  --probe tcp-echo=100.80.0.5:7 --probe tcp-deny=10.77.0.20:7 >"$out" || true
check "QUIC carrier" 'map(select(.event == "connected"))[0].carrier | test("Http3")' "$out"
check "TCP app through the relay (100 kB echoed over a 1280-byte path)" \
  'map(select(.probe == "tcp-echo" and .target == "10.77.0.10:7"))[0].ok' "$out"
check "UDP app through the relay" 'map(select(.probe == "udp-echo"))[0].ok' "$out"
check "name app bound and translated" \
  'map(select(.bind == "grafana.lab.test"))[0].ok and map(select(.probe == "tcp-echo" and .target == "100.80.0.5:7"))[0].ok' "$out"
check "deny fails fast with reason no_rule" \
  'map(select(.probe == "tcp-deny"))[0] | .ok and .reason == "no_rule" and .refused_ms < 1000' "$out"

# 2. UDP blocked on the client's network: the HTTP/2 fallback carries it.
in_ns "$NS_CLI" nft -f - <<'EOF'
table inet blockudp {
  chain out { type filter hook output priority 0; policy accept; udp dport 443 drop; }
}
EOF
client --transport auto --fallback-delay-ms 300 --tun wc0 --route 10.77.0.0/24 \
  --probe tcp-echo=10.77.0.10:7 --probe udp-echo=10.77.0.10:7 --probe tcp-deny=10.77.0.20:7 >"$out" || true
check "HTTP/2 fallback when UDP is blocked" 'map(select(.event == "connected"))[0].carrier | test("Http2")' "$out"
check "TCP and UDP over the fallback" 'map(select(.probe == "tcp-echo" or .probe == "udp-echo")) | all(.ok)' "$out"
check "deny reason over the fallback" 'map(select(.probe == "tcp-deny"))[0].reason == "no_rule"' "$out"
in_ns "$NS_CLI" nft delete table inet blockudp

# 3. The MTU floor: a tunnel MTU below 1280 is refused.
client --transport quic --tunnel-mtu 1200 >"$out" 2>/dev/null || true
check "tunnel MTU below the floor is refused" \
  'map(select(.event == "connect_failed"))[0].error | test("1280")' "$out"

# 4. Server-initiated flows are refused without an opt-in.
client --transport quic --tun wc0 --route 10.77.0.0/24 --hold 3 >"$out" &
held=$!
sleep 1.5
in_ns "$NS_APP" bash -c 'echo knock >/dev/udp/100.96.0.2/5555' || true
wait "$held" || true
sleep 0.5
check "server-initiated flow blocked and audited" \
  'map(select(.status_code == "server_initiated_blocked")) | length >= 1' "$WORK/audit.jsonl"

# 5. The audit trail: allowed and denied decisions, and finished flows.
check "allowed decisions audited" \
  'map(select(.class_uid == 4001 and .action == "Allowed")) | length >= 3' "$WORK/audit.jsonl"
check "denied decisions audited with their reason" \
  'map(select(.action == "Denied" and .status_code == "no_rule" and .unmapped.warren.app == "secret")) | length >= 2' "$WORK/audit.jsonl"
check "flow records with traffic counters" \
  'map(select(.metadata.log_name == "flow" and .traffic.bytes > 0)) | length >= 1' "$WORK/audit.jsonl"
check "name binding audited" \
  'map(select(.dst_endpoint.hostname == "grafana.lab.test")) | length >= 1' "$WORK/audit.jsonl"

# 6. Revocation: a reloaded bundle (SIGHUP) cuts a live session and its
# flows at once.
client --transport quic --tun wc0 --route 10.77.0.0/24 --probe tcp-echo=10.77.0.10:7 --hold 6 >"$out" 2>&1 &
held=$!
sleep 2
write_bundle "$WORK/bundle.json" 2 '"mac-1"'
kill -HUP "$CONNECTOR_PID"
sleep 1
if grep -q 'session revoked' "$WORK/connector.log"; then
  echo "ok   revoked session cut on SIGHUP"
else
  echo "FAIL revoked session cut on SIGHUP" >&2
  failures=$((failures + 1))
fi
wait "$held" || true
check "flows cut by revocation are recorded" \
  'map(select(.metadata.log_name == "flow" and .unmapped.warren.end_reason == "revoked")) | length >= 1' "$WORK/audit.jsonl"

if [ "$failures" -ne 0 ]; then
  echo "kernel e2e: $failures check(s) FAILED" >&2
  exit 1
fi
echo "kernel e2e: all checks passed"
