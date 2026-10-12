#!/usr/bin/env bash
# Kubernetes end-to-end test of the chart in charts/warren, on a throwaway
# kind cluster: installs the control plane, creates relay and connector join
# tokens with `warren admin`, enables the relay and a kernel-mode connector,
# and checks that both joined, that the connector set up its TUN device and
# NAT table and attached to the relay, and that a restarted connector comes
# back on the credentials it kept instead of its spent token.
#
# Needs docker, kind, kubectl, helm and jq. The images must exist locally
# (`docker build` of the Dockerfile's two targets).
# Usage: scripts/e2e-kind.sh IMAGE CONNECTOR_IMAGE
#   KIND_CLUSTER=name   the cluster to create (default warren-e2e)
#   KEEP_CLUSTER=1      leave the cluster running afterwards
set -euo pipefail

if [ $# -ne 2 ]; then
  echo "usage: $0 IMAGE CONNECTOR_IMAGE" >&2
  exit 2
fi
cd "$(dirname "$0")/.."

image=$1
connector_image=$2
cluster=${KIND_CLUSTER:-warren-e2e}
ns=warren
release=e2e
cp=$release-warren-control-plane
relay=$release-warren-relay
connector=$release-warren-connector
failures=0
work=$(mktemp -d)

cleanup() {
  if [ "$failures" -ne 0 ]; then
    kubectl -n "$ns" get pods,svc,pvc -o wide >&2 || true
    for c in control-plane relay connector; do
      echo "--- $c log" >&2
      kubectl -n "$ns" logs -l "app.kubernetes.io/component=$c" --all-containers --tail=40 >&2 || true
    done
  fi
  if [ "${KEEP_CLUSTER:-}" != 1 ]; then
    kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

ok() { echo "ok   $1"; }
fail() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}
# wait_for SECONDS COMMAND...: retries COMMAND every two seconds.
wait_for() {
  local deadline=$((SECONDS + $1))
  shift
  until "$@" >/dev/null 2>&1; do
    [ "$SECONDS" -lt "$deadline" ] || return 1
    sleep 2
  done
}
admin() { kubectl -n "$ns" exec "$cp-0" -- warren admin "$@"; }
pod() { kubectl -n "$ns" get pods -l "app.kubernetes.io/component=$1" -o jsonpath='{.items[0].metadata.name}'; }
# logged ROLE TEXT: the role's current container logged TEXT. The logs are
# read whole first: `grep -q` stopping early would fail the pipe.
logged() {
  kubectl -n "$ns" logs "$(pod "$1")" -c "$1" >"$work/$1.log"
  grep -qF -- "$2" "$work/$1.log"
}
metric() {
  kubectl get --raw "/api/v1/namespaces/$ns/pods/$(pod "$1"):9090/proxy/metrics" |
    awk -v m="$2" '$1 == m { print $2 }'
}
attached() { [ "$(metric relay warren_relay_attachments)" -ge 1 ]; }

kind create cluster --name "$cluster" --wait 120s
kind load docker-image --name "$cluster" "$image" "$connector_image"
kubectl create namespace "$ns"
# The connector needs NET_ADMIN, a hostPath TUN device and a privileged init
# container.
kubectl label namespace "$ns" pod-security.kubernetes.io/enforce=privileged

# 1. The control plane, at its in-cluster Service name.
cat >"$work/values.yaml" <<EOF
image: { repository: "${image%:*}", tag: "${image##*:}", pullPolicy: Never }
connectorImage: { repository: "${connector_image%:*}", tag: "${connector_image##*:}", pullPolicy: Never }
controlPlane:
  trustDomain: lab.test
  publicUrl: https://$cp.$ns.svc
  # Discovery is fetched at the first sign-in, which this test never makes.
  idp: { issuer: "https://idp.lab.test", clientId: warren }
  policy:
    lab.yaml: |
      apiVersion: warren.dev/v1alpha1
      kind: ConnectorGroup
      metadata: { name: homelab }
      spec:
        destinations:
          cidrs: ["10.96.0.0/12"]
EOF
helm install "$release" charts/warren -n "$ns" -f "$work/values.yaml" --wait --timeout 5m
if admin deployment | jq -e '.root_fingerprint | startswith("sha256:")' >/dev/null; then
  ok "the control plane is up and answers warren admin"
else
  fail "the control plane is up and answers warren admin"
fi
if admin policy status | jq -e . >/dev/null; then
  ok "the control plane loaded the policy from the chart"
else
  fail "the control plane loaded the policy from the chart"
fi

# 2. Join tokens, as an operator would create them.
admin join-token create --role relay --name relay-1 --dns-name "$relay.$ns.svc" |
  jq -r .token >"$work/relay-token"
admin join-token create --role connector --group homelab --name lab-1 |
  jq -r .token >"$work/connector-token"
kubectl -n "$ns" create secret generic relay-join --from-file=token="$work/relay-token"
kubectl -n "$ns" create secret generic connector-join --from-file=token="$work/connector-token"

# 3. The relay and the connector, with the node bundle.
cat >"$work/nodes.yaml" <<EOF
nodes:
  logLevel: debug
  bundle:
    version: 1
    trustDomain: lab.test
    connectorGroups:
      - name: homelab
        destinations: { cidrs: ["10.96.0.0/12"] }
relay:
  enabled: true
  joinToken: { existingSecret: relay-join }
  service: { type: ClusterIP }
connector:
  enabled: true
  group: homelab
  relays: ["$relay.$ns.svc@$relay.$ns.svc:443"]
  joinToken: { existingSecret: connector-join }
EOF
helm upgrade "$release" charts/warren -n "$ns" -f "$work/values.yaml" -f "$work/nodes.yaml" --wait --timeout 5m

for role in relay connector; do
  if logged "$role" 'joined the deployment'; then
    ok "the $role joined with its token"
  else
    fail "the $role joined with its token"
  fi
done
if wait_for 60 attached; then
  ok "the connector attached to the relay"
else
  fail "the connector attached to the relay"
fi
cpod=$(pod connector)
if kubectl -n "$ns" exec "$cpod" -c connector -- ip link show warren0 >/dev/null; then
  ok "the connector created its TUN device"
else
  fail "the connector created its TUN device"
fi
if kubectl -n "$ns" exec "$cpod" -c connector -- nft list table ip warren >"$work/nat" &&
  grep -q masquerade "$work/nat"; then
  ok "the connector installed its NAT table"
else
  fail "the connector installed its NAT table"
fi

# 4. A new connector pod keeps the credentials from the first join; its
# token is spent.
kubectl -n "$ns" delete pod "$cpod" --wait=true
kubectl -n "$ns" rollout status "deployment/$connector" --timeout 3m
if logged connector 'using credentials from an earlier join'; then
  ok "a restarted connector uses the credentials it kept"
else
  fail "a restarted connector uses the credentials it kept"
fi
if wait_for 60 attached; then
  ok "the restarted connector attached to the relay again"
else
  fail "the restarted connector attached to the relay again"
fi

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
