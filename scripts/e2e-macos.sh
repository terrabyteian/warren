#!/usr/bin/env bash
# End-to-end test of the macOS command-line client on one Mac: a control
# plane with a test IdP, a relay, a connector stand-in and two stand-in
# apps, then `warren login` through a scripted browser, `sudo warren up`, a
# TCP and a UDP app through the tunnel, a block with its reason, the
# HTTP/2 carrier, a revocation, an entitlement update, `warren status` and
# `warren down`.
#
# The connector runs Linux kernel forwarding in production; here a
# stand-in (`warren-harness connector`) runs the same connector code and
# forwards through a second utun interface with address translation, so
# this Mac's own TCP and UDP stacks serve the apps. Relays and connectors
# load policy from a static bundle until they consume the control plane's,
# so the script writes one naming the enrolled user and device.
#
# macOS only. Needs passwordless sudo (GitHub's macOS runners have it) for
# the tunnel interfaces and an /etc/hosts entry for the relay's name; with
# E2E_NO_SUDO=1 it runs only the unprivileged part (sign-in, enrollment,
# approval, status).
#
# Usage: scripts/e2e-macos.sh [BIN_DIR]   (default: target/debug)
set -euo pipefail

cd "$(dirname "$0")/.."
BIN=$(cd "${1:-target/debug}" && pwd)
WARREN="$BIN/warren"
HARNESS="$BIN/warren-harness"
NO_SUDO=${E2E_NO_SUDO:-0}
WORK=$(mktemp -d)
HOME_DIR="$WORK/home"
CP_PORT=18443
IDP_PORT=19443
ORG="https://localhost:$CP_PORT"
PIDS=()
SUDO_PIDS=()
failures=0
hosts_added=0
keychain=""
old_keychain=""
old_search=()

cleanup() {
  local pid
  # bash 3.2 treats an empty array as unset under `set -u`.
  for pid in ${SUDO_PIDS[@]+"${SUDO_PIDS[@]}"}; do
    sudo -n kill "$pid" 2>/dev/null || true
  done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill "$pid" 2>/dev/null || true
  done
  for pid in ${SUDO_PIDS[@]+"${SUDO_PIDS[@]}"} ${PIDS[@]+"${PIDS[@]}"}; do
    wait "$pid" 2>/dev/null || true
  done
  if [ "$hosts_added" -eq 1 ]; then
    sudo -n sed -i '' '/relay\.lab\.test/d' /etc/hosts || true
  fi
  if [ -n "$keychain" ]; then
    if [ -n "$old_keychain" ]; then security default-keychain -s "$old_keychain" || true; fi
    security list-keychains -d user -s ${old_search[@]+"${old_search[@]}"} || true
    security delete-keychain "$keychain" 2>/dev/null || true
  fi
  if [ "$failures" -ne 0 ]; then
    for log in idp cp relay connector apps up; do
      if [ -f "$WORK/$log.log" ]; then
        echo "--- $log log" >&2
        tail -n 40 "$WORK/$log.log" >&2 || true
      fi
    done
  fi
  if [ "$NO_SUDO" = 1 ]; then rm -rf -- "$WORK"; else sudo -n rm -rf -- "$WORK"; fi
}
trap cleanup EXIT

ok() { echo "ok   $1"; }
fail() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}
check() {
  # check NAME COMMAND...: passes when the command succeeds.
  local name=$1
  shift
  if "$@"; then ok "$name"; else fail "$name"; fi
}
wait_for() {
  # wait_for SECONDS COMMAND...: retries the command until it succeeds.
  local tries=$(($1 * 10))
  shift
  while [ "$tries" -gt 0 ]; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    tries=$((tries - 1))
    sleep 0.1
  done
  return 1
}
contains() { grep -q -- "$2" "$1"; }
admin() { "$WARREN" admin --socket "$WORK/cp/admin.sock" "$@"; }

# The policy the control plane serves: an echo app with TCP and UDP, and a
# discoverable billing app the user may only request.
mkdir -p "$WORK/policy"
cat >"$WORK/policy/lab.yaml" <<'EOF'
apiVersion: warren.dev/v1alpha1
kind: ConnectorGroup
metadata: { name: homelab }
spec:
  destinations:
    cidrs: ["10.77.0.0/24"]
  clientNames: ["*.lab.test"]
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: echo }
spec:
  connectorGroup: homelab
  destinations:
    - { cidr: 10.77.0.10/32, ports: [7], protocol: tcp }
    - { cidr: 10.77.0.10/32, ports: [7], protocol: udp }
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: billing }
spec:
  connectorGroup: homelab
  discoverable: true
  destinations:
    - { cidr: 10.77.0.30/32, protocol: any }
---
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: lab }
spec:
  rules:
    - name: eng-echo
      who: { groups: [eng] }
      what: { apps: [echo] }
---
apiVersion: warren.dev/v1alpha1
kind: AccessRequestPolicy
metadata: { name: billing-requests }
spec:
  who: { groups: [eng] }
  what: { apps: [billing] }
  approval:
    approvers: { groups: [finance] }
  maxDuration: 1h
EOF

# The static bundle relays and connectors load (see above).
write_bundle() {
  local version=$1 user=${2:-} device=${3:-} revoked=${4:-}
  local users="" devices=""
  [ -n "$user" ] && users="{ \"id\": \"$user\", \"groups\": [\"eng\"] }"
  [ -n "$device" ] && devices="{ \"id\": \"$device\", \"approved\": true }"
  cat >"$WORK/bundle.json" <<EOF
{
  "version": $version,
  "trustDomain": "lab.test",
  "connectorGroups": [{ "name": "homelab", "destinations": { "cidrs": ["10.77.0.0/24"] }, "clientNames": ["*.lab.test"] }],
  "apps": [
    { "name": "echo", "connectorGroup": "homelab",
      "destinations": [{ "cidr": "10.77.0.10/32", "ports": [7], "protocol": "tcp" },
                       { "cidr": "10.77.0.10/32", "ports": [7], "protocol": "udp" }] },
    { "name": "billing", "connectorGroup": "homelab", "discoverable": true,
      "destinations": [{ "cidr": "10.77.0.30/32", "protocol": "any" }] }
  ],
  "users": [$users],
  "devices": [$devices],
  "rules": [{ "id": "lab/eng-echo", "who": { "groups": ["eng"] }, "what": { "apps": ["echo"] } }],
  "revoked": { "devices": [$revoked] }
}
EOF
}

# 1. The test IdP and the control plane.
"$HARNESS" idp --listen "127.0.0.1:$IDP_PORT" --host localhost \
  --user "00u-ada,ada@example.com,eng,pwd+mfa" --dir "$WORK/idp" >"$WORK/idp.log" 2>&1 &
PIDS+=($!)
wait_for 10 test -s "$WORK/idp/ca.pem" || {
  fail "test IdP started"
  exit 1
}
cat >"$WORK/cp.yaml" <<EOF
trustDomain: lab.test
publicUrl: $ORG
listen: 127.0.0.1:$CP_PORT
dataDir: $WORK/cp
policyDir: $WORK/policy
idp:
  issuer: https://localhost:$IDP_PORT
  clientId: warren
  caFile: $WORK/idp/ca.pem
devices:
  approval: manual
audit:
  file: $WORK/cp-audit.jsonl
EOF
"$WARREN" control-plane --config "$WORK/cp.yaml" >"$WORK/cp.log" 2>&1 &
PIDS+=($!)
wait_for 30 admin deployment || {
  fail "control plane started"
  exit 1
}
fingerprint=$(admin deployment | jq -r .root_fingerprint)
check "the admin reads the root fingerprint" test "${fingerprint#sha256:}" != "$fingerprint"

# The scripted browser follows the sign-in redirects through the control
# plane and the IdP back to the client's loopback listener, as a person's
# browser would after a click.
curl -fsS -k "$ORG/.well-known/warren" | jq -r .trust_bundle >"$WORK/cas.pem"
cat "$WORK/idp/ca.pem" >>"$WORK/cas.pem"
cat >"$WORK/browser" <<EOF
#!/bin/sh
exec curl -fsS -L --max-redirs 5 --cacert "$WORK/cas.pem" -o "$WORK/browser.html" "\$1"
EOF
chmod +x "$WORK/browser"

# CI runners get a keychain of their own for the software device key: they
# have no Secure Enclave, and their login keychain belongs to the image.
if [ -n "${CI:-}" ]; then
  old_keychain=$(security default-keychain | tr -d ' "')
  while IFS= read -r k; do
    old_search+=("$k")
  done < <(security list-keychains -d user | tr -d ' "')
  keychain="$WORK/e2e.keychain-db"
  security create-keychain -p e2e "$keychain"
  security set-keychain-settings "$keychain"
  security unlock-keychain -p e2e "$keychain"
  security list-keychains -d user -s "$keychain" ${old_search[@]+"${old_search[@]}"}
  security default-keychain -s "$keychain"
fi

# 2. Sign in and enroll.
BROWSER="$WORK/browser" "$WARREN" login "$ORG" --fingerprint "$fingerprint" \
  --home "$HOME_DIR" --timeout 30 >"$WORK/login.out" 2>&1 || true
check "warren login signs in through the browser" contains "$WORK/login.out" "Signed in to $ORG as ada@example.com"
check "the device waits for approval, with its ID" contains "$WORK/login.out" "waiting for an administrator to approve it"
check "the browser saw the success page" contains "$WORK/browser.html" "Signed in to warren"
"$WARREN" status --home "$HOME_DIR" --json >"$WORK/status.json"
device=$(jq -r .device "$WORK/status.json")
storage=$(jq -r .key_storage "$WORK/status.json")
check "status names the device and its key storage ($storage)" test -n "$device" -a "$storage" != null
reported=$(admin devices list | jq -r --arg d "$device" '.[] | select(.id == $d) | .key_storage')
check "enrollment reported where the key lives ($reported)" test "$reported" = secure-enclave -o "$reported" = software
if "$WARREN" up --home "$HOME_DIR" >"$WORK/up-user.out" 2>&1; then
  fail "warren up without sudo is refused"
else
  check "warren up without sudo says to use sudo" contains "$WORK/up-user.out" "sudo warren up"
fi
admin devices approve "$device" >/dev/null
approved=$(admin devices list | jq -r --arg d "$device" '.[] | select(.id == $d) | .status')
check "the admin approves the device" test "$approved" = approved
user=$(admin users list | jq -r '.[] | select(.email == "ada@example.com") | .id')

if [ "$NO_SUDO" = 1 ]; then
  [ "$failures" -eq 0 ] && echo "macOS e2e (without sudo): all checks passed" || exit 1
  exit 0
fi

# 3. The relay, the connector stand-in and the apps.
echo "127.0.0.1 relay.lab.test" | sudo tee -a /etc/hosts >/dev/null
hosts_added=1
sudo dscacheutil -flushcache || true
sudo killall -HUP mDNSResponder 2>/dev/null || true
write_bundle 1 "$user" "$device"
relay_token=$(admin join-token create --role relay --name relay-1 --dns-name relay.lab.test | jq -r .token)
connector_token=$(admin join-token create --role connector --group homelab --name lab-1 | jq -r .token)
"$WARREN" relay --listen 0.0.0.0:443 --join-token "$relay_token" --state-dir "$WORK/relay" \
  --bundle "$WORK/bundle.json" --metrics 127.0.0.1:19090 2>"$WORK/relay.log" &
RELAY_PID=$!
PIDS+=("$RELAY_PID")
# shellcheck disable=SC2024 # the log is the test's, written as the user
sudo "$HARNESS" connector --group homelab --relay relay.lab.test@127.0.0.1:443 \
  --join-token "$connector_token" --bundle "$WORK/bundle.json" --audit "$WORK/audit.jsonl" \
  --map 10.77.0.10=10.88.0.1 --peers 10.88.0.0/24 >"$WORK/connector.log" 2>&1 &
CONNECTOR_PID=$!
SUDO_PIDS+=("$CONNECTOR_PID")
relay_attached() {
  exec 3<>/dev/tcp/127.0.0.1/19090
  printf 'GET /metrics HTTP/1.0\r\n\r\n' >&3
  awk '$1 == "warren_relay_attachments" { found = ($2 >= 1) } END { exit !found }' <&3
}
if wait_for 30 relay_attached; then ok "the connector attached to the relay"; else
  fail "the connector attached to the relay"
  exit 1
fi
"$HARNESS" serve --tcp-echo 0.0.0.0:7 --udp-echo 0.0.0.0:7 >"$WORK/apps.log" 2>&1 &
PIDS+=($!)
wait_for 10 contains "$WORK/apps.log" udp-echo

# 4. Up: the tunnel, the routes, and the apps through them.
start_up() {
  : >"$WORK/up.log"
  # shellcheck disable=SC2024 # the log is the test's, written as the user
  sudo "$WARREN" up --home "$HOME_DIR" "$@" >"$WORK/up.log" 2>&1 &
  UP_PID=$!
  SUDO_PIDS+=("$UP_PID")
  wait_for 30 contains "$WORK/up.log" "connected to homelab"
}
tcp_echo() {
  # tcp_echo HOST: sends a line and expects it back.
  local reply
  exec 5<>"/dev/tcp/$1/7" || return 1
  printf 'hello warren\n' >&5
  read -r -t 5 reply <&5 || true
  exec 5>&-
  [ "$reply" = "hello warren" ]
}
udp_echo() {
  local reply
  exec 6<>"/dev/udp/$1/7" || return 1
  printf 'hi' >&6
  read -r -t 5 -n 2 reply <&6 || true
  exec 6>&-
  [ "$reply" = "hi" ]
}
if start_up; then ok "sudo warren up connects through the relay"; else
  fail "sudo warren up connects through the relay"
  exit 1
fi
check "up says it is up, with its apps and routes" contains "$WORK/up.log" "warren is up: 2 apps, 2 routes"
check "only the apps' ranges are routed into the tunnel" sh -c "route -n get 10.77.0.10 | grep -q 'interface: utun' && ! route -n get 1.1.1.1 | grep -q 'interface: utun'"
check "TCP app through the tunnel" tcp_echo 10.77.0.10
check "UDP app through the tunnel" udp_echo 10.77.0.10
start=$(perl -MTime::HiRes=time -e 'printf "%d", time * 1000')
if (exec 7<>/dev/tcp/10.77.0.30/7) 2>/dev/null; then
  fail "a requestable app is blocked"
else
  elapsed=$(($(perl -MTime::HiRes=time -e 'printf "%d", time * 1000') - start))
  check "a blocked connection fails fast (${elapsed} ms)" test "$elapsed" -lt 2000
fi
check "the block is shown with its reason" wait_for 5 contains "$WORK/up.log" "blocked tcp 10.77.0.30:7 (billing).*request_access"
"$WARREN" status --home "$HOME_DIR" >"$WORK/status.out"
check "status shows the tunnel" contains "$WORK/status.out" "homelab     connected through relay.lab.test over QUIC"
check "status shows the recent block" contains "$WORK/status.out" "request_access"
check "the connector audited the decisions" sh -c "jq -e -s 'map(select(.action == \"Allowed\")) | length >= 2' '$WORK/audit.jsonl' >/dev/null && jq -e -s 'map(select(.status_code == \"request_access\")) | length >= 1' '$WORK/audit.jsonl' >/dev/null"

# 5. An entitlement change reaches the running client: a new app range is
# routed without restarting.
cat >>"$WORK/policy/lab.yaml" <<'EOF'
---
apiVersion: warren.dev/v1alpha1
kind: App
metadata: { name: wiki }
spec:
  connectorGroup: homelab
  destinations:
    - { cidr: 10.77.0.40/32, ports: [80], protocol: tcp }
---
apiVersion: warren.dev/v1alpha1
kind: AccessPolicy
metadata: { name: wiki }
spec:
  rules:
    - name: eng-wiki
      who: { groups: [eng] }
      what: { apps: [wiki] }
EOF
admin policy reload >/dev/null
check "new entitlements are routed without a restart" wait_for 75 contains "$WORK/up.log" "entitlements updated: 3 apps, 3 routes"
check "the new app's range is routed" sh -c "route -n get 10.77.0.40 | grep -q 'interface: utun'"

# 6. Down, and the routes go with the interface.
"$WARREN" down --home "$HOME_DIR" >"$WORK/down.out"
check "warren down disconnects" contains "$WORK/down.out" "warren is down"
wait "$UP_PID" 2>/dev/null || true
check "the routes are gone" sh -c "! route -n get 10.77.0.10 2>/dev/null | grep -q 'interface: utun'"
"$WARREN" status --home "$HOME_DIR" >"$WORK/status.out"
check "status says it is down" contains "$WORK/status.out" "down (run \`sudo warren up\` to connect)"

# 7. The HTTP/2 carrier carries the same tunnel.
if start_up --transport h2; then ok "up over the HTTP/2 carrier"; else fail "up over the HTTP/2 carrier"; fi
check "the tunnel runs over HTTP/2" contains "$WORK/up.log" "over HTTP/2"
check "TCP app over HTTP/2" tcp_echo 10.77.0.10
check "UDP app over HTTP/2" udp_echo 10.77.0.10

# 8. Revocation: the connector cuts the session and the client says why.
write_bundle 2 "$user" "$device" "\"$device\""
sudo kill -HUP "$CONNECTOR_PID"
kill -HUP "$RELAY_PID"
check "a revoked device is cut and told why" wait_for 15 grep -Eq "revoked|not connected" "$WORK/up.log"
check "the revoked device reaches nothing" sh -c "! (exec 8<>/dev/tcp/10.77.0.10/7; printf x >&8; read -r -t 3 r <&8; [ -n \"\$r\" ]) 2>/dev/null"
"$WARREN" down --home "$HOME_DIR" >/dev/null || true
wait "$UP_PID" 2>/dev/null || true

if [ "$failures" -ne 0 ]; then
  echo "macOS e2e: $failures check(s) FAILED" >&2
  exit 1
fi
echo "macOS e2e: all checks passed"
