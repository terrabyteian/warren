#!/usr/bin/env bash
# Shared network-namespace topology for the kernel-mode tests and
# benchmarks (sourced, not run). Linux only; needs root.
#
#   client ns            relay ns              connector ns          app ns
#   172.31.2.2 --- 172.31.2.1 | 172.31.1.1 --- 172.31.1.2 | 10.77.0.1 --- 10.77.0.10 (echo, sink)
#     TUN wc0                  warren relay       warren connector          10.77.0.20 (no rule)
#                                                 TUN warren0 + NAT         10.77.0.11 (baselines)
#                                                                           10.77.0.12 (WireGuard)
#
# The client and the connector can reach each other only through the
# relay. The client link runs at a 1280-byte MTU, the narrowest path the
# profile must work on.

NS_CLI="wcli$$"
NS_RELAY="wrly$$"
NS_CONN="wcon$$"
NS_APP="wapp$$"
PIDS=()

in_ns() {
  local ns=$1
  shift
  ip netns exec "$ns" "$@"
}

netns_cleanup() {
  local pid ns
  for pid in "${PIDS[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  for ns in "$NS_CLI" "$NS_RELAY" "$NS_CONN" "$NS_APP"; do
    ip netns del "$ns" 2>/dev/null || true
    rm -rf "/etc/netns/$ns"
  done
}

veth() {
  # veth NS_A IF_A ADDR_A NS_B IF_B ADDR_B [MTU]
  local mtu=${7:-1500}
  ip link add "$2" netns "$1" mtu "$mtu" type veth peer name "$5" netns "$4" mtu "$mtu"
  in_ns "$1" ip addr add "$3" dev "$2"
  in_ns "$4" ip addr add "$6" dev "$5"
  in_ns "$1" ip link set "$2" up
  in_ns "$4" ip link set "$5" up
}

netns_setup() {
  local ns
  for ns in "$NS_CLI" "$NS_RELAY" "$NS_CONN" "$NS_APP"; do
    ip netns add "$ns"
    in_ns "$ns" ip link set lo up
  done
  veth "$NS_CLI" eth0 172.31.2.2/24 "$NS_RELAY" cli0 172.31.2.1/24 1280
  veth "$NS_CONN" eth0 172.31.1.2/24 "$NS_RELAY" con0 172.31.1.1/24
  veth "$NS_CONN" app0 10.77.0.1/24 "$NS_APP" eth0 10.77.0.10/24
  in_ns "$NS_APP" ip addr add 10.77.0.20/24 dev eth0
  in_ns "$NS_APP" ip addr add 10.77.0.11/24 dev eth0
  in_ns "$NS_APP" ip addr add 10.77.0.12/24 dev eth0
  # Return path for traffic the connector does not masquerade (server-
  # initiated tests and baselines).
  in_ns "$NS_APP" ip route add 100.96.0.0/16 via 10.77.0.1
}

# Writes the node bundle for the test deployment.
write_bundle() {
  local path=$1 version=$2 revoked=${3:-}
  cat >"$path" <<EOF
{
  "version": $version,
  "trustDomain": "lab.test",
  "connectorGroups": [{
    "name": "homelab",
    "destinations": { "cidrs": ["10.77.0.0/24"], "domains": ["*.lab.test"] },
    "clientNames": ["*.lab.test"]
  }],
  "apps": [
    { "name": "echo", "connectorGroup": "homelab",
      "destinations": [{ "cidr": "10.77.0.10/32", "ports": [7, 9], "protocol": "tcp" },
                       { "cidr": "10.77.0.10/32", "ports": [7], "protocol": "udp" },
                       { "cidr": "10.77.0.10/32", "protocol": "icmp" }] },
    { "name": "secret", "connectorGroup": "homelab",
      "destinations": [{ "cidr": "10.77.0.20/32", "protocol": "any" }] },
    { "name": "grafana", "connectorGroup": "homelab",
      "destinations": [{ "host": "grafana.lab.test", "target": "10.77.0.10", "ports": [7], "protocol": "tcp" }] }
  ],
  "users": [{ "id": "alice", "groups": ["eng"] }],
  "devices": [{ "id": "mac-1", "approved": true }],
  "rules": [{ "id": "lab/eng", "who": { "groups": ["eng"] }, "what": { "apps": ["echo", "grafana"] } }],
  "revoked": { "devices": [${revoked}] }
}
EOF
}

# Starts a stand-in control-plane join endpoint, the apps, and a relay and a
# connector that join the deployment with single-use tokens on first
# start. Sets WORK, HARNESS, WARREN, CLIENT_ARGS and CONNECTOR_PID.
start_deployment() {
  local bin=$1
  WARREN="$bin/warren"
  HARNESS="$bin/warren-harness"
  WORK=$(mktemp -d)
  CLIENT_ARGS=(--relay relay.lab.test@172.31.2.1:443 --group homelab
    --cert "$WORK/cp/client-alice-mac-1.pem" --key "$WORK/cp/client-alice-mac-1.key"
    --trust-bundle "$WORK/cp/trust" --trust-domain lab.test)
  # A separate PKI serves the TLS-over-TCP baseline.
  "$HARNESS" pki --dir "$WORK/pki" --trust-domain bench.test --relay-dns relay.lab.test \
    --group homelab >/dev/null
  write_bundle "$WORK/bundle.json" 1 ""

  # The join endpoint answers as cp.lab.test from the relay namespace,
  # where the relay and the connector both reach it. `ip netns exec`
  # mounts /etc/netns/NS/hosts over /etc/hosts.
  local ns
  for ns in "$NS_RELAY" "$NS_CONN"; do
    mkdir -p "/etc/netns/$ns"
    printf '127.0.0.1 localhost\n172.31.1.1 cp.lab.test\n' >"/etc/netns/$ns/hosts"
  done
  ip netns exec "$NS_RELAY" "$HARNESS" join-serve --dir "$WORK/cp" --trust-domain lab.test \
    --listen 172.31.1.1:8443 --name cp.lab.test --relay-dns relay.lab.test --group homelab \
    --client "alice,mac-1,100.96.0.2,fd00:7761:7272:6e00::2" >"$WORK/join.log" 2>&1 &
  PIDS+=($!)
  local tries=0
  while [ ! -s "$WORK/cp/tokens.json" ] && [ "$tries" -lt 100 ]; do
    tries=$((tries + 1))
    sleep 0.1
  done

  # Background processes run through `ip netns exec` directly (not the
  # in_ns function, which would fork a subshell) so $! is the process
  # itself and signals reach it.
  ip netns exec "$NS_APP" "$HARNESS" serve --tcp-echo 10.77.0.10:7 --udp-echo 10.77.0.10:7 \
    --tcp-sink 10.77.0.10:9 --tcp-echo 10.77.0.20:7 --tcp-echo 10.77.0.11:7 --tcp-sink 10.77.0.11:9 \
    --tcp-echo 10.77.0.12:7 --tcp-sink 10.77.0.12:9 \
    --tls 10.77.0.11:8443 --tls-cert "$WORK/pki/tls.pem" --tls-key "$WORK/pki/tls.key" \
    >"$WORK/apps.log" 2>&1 &
  PIDS+=($!)
  ip netns exec "$NS_RELAY" "$WARREN" relay --listen 0.0.0.0:443 \
    --join-token "$(jq -r .relay "$WORK/cp/tokens.json")" --state-dir "$WORK/relay-state" \
    --bundle "$WORK/bundle.json" --metrics 127.0.0.1:9090 2>"$WORK/relay.log" &
  PIDS+=($!)
  ip netns exec "$NS_CONN" "$WARREN" connector --group homelab --relay relay.lab.test@172.31.1.1:443 \
    --join-token "$(jq -r .connector "$WORK/cp/tokens.json")" --state-dir "$WORK/connector-state" \
    --bundle "$WORK/bundle.json" --audit "$WORK/audit.jsonl" --tun-name warren0 \
    --metrics 127.0.0.1:9091 2>"$WORK/connector.log" &
  CONNECTOR_PID=$!
  PIDS+=("$CONNECTOR_PID")

  tries=0
  while [ "$tries" -lt 100 ]; do
    if relay_metric warren_relay_attachments | grep -qx 1; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 0.1
  done
  echo "error: the connector did not attach to the relay" >&2
  tail -n 20 "$WORK/join.log" "$WORK/relay.log" "$WORK/connector.log" >&2
  return 1
}

relay_metric() {
  in_ns "$NS_RELAY" bash -c 'exec 3<>/dev/tcp/127.0.0.1/9090; printf "GET /metrics HTTP/1.0\r\n\r\n" >&3; cat <&3' 2>/dev/null |
    awk -v m="$1" '$1 == m { print $2 }'
}

client() {
  in_ns "$NS_CLI" "$HARNESS" client "${CLIENT_ARGS[@]}" "$@"
}

# Starts the test client in the background and sets CLIENT_PID.
client_bg() {
  ip netns exec "$NS_CLI" "$HARNESS" client "${CLIENT_ARGS[@]}" "$@" &
  CLIENT_PID=$!
  PIDS+=("$CLIENT_PID")
}
