#!/usr/bin/env bash
# Template tests for the chart in charts/warren: `helm lint --strict` over
# the values in charts/warren/ci/, then renders of chosen values checked for
# what each role must and must not get, and for the values the chart
# refuses. Needs helm (scripts/install-kube-tools.sh).
#
# Usage: scripts/test-chart.sh
set -euo pipefail

cd "$(dirname "$0")/.."
chart=charts/warren
failures=0
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

ok() { echo "ok   $1"; }
fail() {
  echo "FAIL $1" >&2
  failures=$((failures + 1))
}

# render NAME [helm template args...]: renders into $work/NAME.yaml.
render() {
  local name=$1
  shift
  helm template t "$chart" --namespace warren "$@" >"$work/$name.yaml"
}
# has NAME TEXT DESCRIPTION / lacks NAME TEXT DESCRIPTION: a fixed-string
# match in a render.
has() { if grep -qF -- "$2" "$work/$1.yaml"; then ok "$3"; else fail "$3"; fi; }
lacks() { if grep -qF -- "$2" "$work/$1.yaml"; then fail "$3"; else ok "$3"; fi; }
# refuses MESSAGE DESCRIPTION [helm template args...]: the render fails
# with MESSAGE.
refuses() {
  local message=$1 description=$2
  shift 2
  if helm template t "$chart" "$@" >/dev/null 2>"$work/err"; then
    fail "$description (rendered)"
  elif grep -qF -- "$message" "$work/err"; then
    ok "$description"
  else
    fail "$description (wrong error: $(cat "$work/err"))"
  fi
}

for values in "$chart"/ci/*.yaml; do
  if helm lint --strict "$chart" -f "$values" >"$work/lint" 2>&1; then
    ok "helm lint --strict with $(basename "$values")"
  else
    cat "$work/lint" >&2
    fail "helm lint --strict with $(basename "$values")"
  fi
done

base=(--set controlPlane.trustDomain=lab.test
  --set controlPlane.publicUrl=https://warren.lab.test
  --set controlPlane.idp.issuer=https://idp.lab.test
  --set controlPlane.idp.clientId=warren)

# The control plane alone.
render cp "${base[@]}"
has cp "kind: StatefulSet" "the control plane is a StatefulSet"
has cp "trustDomain: lab.test" "the configuration carries the trust domain"
has cp "listen: '[::]:8443'" "the control plane listens on 8443 inside the pod"
has cp "policyDir: /etc/warren/policy" "the policy directory is the mounted ConfigMap"
has cp "storage: 1Gi" "the database gets a 1Gi volume"
has cp "runAsNonRoot: true" "the control plane runs as nonroot"
has cp "readOnlyRootFilesystem: true" "the control plane's root filesystem is read-only"
has cp "image: ghcr.io/terrabyteian/warren:0.0.0" "the image tag defaults to the appVersion"
has cp "type: ClusterIP" "the control plane Service is ClusterIP by default"
lacks cp "tls:" "no operator certificate unless one is given"
lacks cp "keyEncryptionKeyFile" "the key-encryption key defaults to the data volume"
lacks cp "kind: Deployment" "no relay or connector unless enabled"
lacks cp "bundle.json" "no node bundle unless a node is enabled"

# Every Secret the control plane can use.
render cp-secrets "${base[@]}" \
  --set controlPlane.tls.existingSecret=warren-tls \
  --set controlPlane.keyEncryptionKey.existingSecret=warren-kek \
  --set controlPlane.idpClientSecret.existingSecret=warren-idp \
  --set controlPlane.bootstrapAdmin.existingSecret=warren-admin \
  --set 'controlPlane.dnsNames={nodes.warren.lab.test}' \
  --set controlPlane.config.devices.approval=automatic \
  --set controlPlane.service.type=LoadBalancer \
  --set-string 'controlPlane.policy.lab\.yaml=kind: AccessPolicy'
has cp-secrets "certFile: /etc/warren/tls/tls.crt" "the operator certificate comes from the TLS Secret"
has cp-secrets "keyEncryptionKeyFile: /etc/warren/kek/kek" "the key-encryption key comes from its Secret"
has cp-secrets "clientSecretFile: /etc/warren/idp/client-secret" "the IdP client secret comes from its Secret"
has cp-secrets "mountPath: /etc/warren/bootstrap-admin" "the bootstrap admin Secret is mounted"
has cp-secrets "- nodes.warren.lab.test" "dnsNames pass through"
has cp-secrets "approval: automatic" "more configuration merges in"
has cp-secrets "lab.yaml: |" "policy files land in the policy ConfigMap"
has cp-secrets "type: LoadBalancer" "the control plane Service type is configurable"

# Relay and connector.
nodes=("${base[@]}"
  --set nodes.bundle.version=1 --set nodes.bundle.trustDomain=lab.test
  --set relay.enabled=true --set relay.joinToken.existingSecret=relay-join
  --set connector.enabled=true --set connector.group=homelab
  --set connector.joinToken.existingSecret=connector-join
  --set 'connector.relays={relay.lab.test@t-warren-relay:443,relay2.lab.test}')
render nodes "${nodes[@]}"
has nodes '"trustDomain": "lab.test"' "the node bundle is rendered as JSON"
has nodes "protocol: UDP" "the relay Service carries QUIC on UDP"
has nodes "protocol: TCP" "the relay Service carries the HTTP/2 fallback on TCP"
has nodes "type: LoadBalancer" "the relay Service is a LoadBalancer by default"
has nodes "--join-token=\$(WARREN_JOIN_TOKEN)" "join tokens come from Secrets through the environment"
has nodes "--group=homelab" "the connector gets its group"
has nodes "--relay=relay.lab.test@t-warren-relay:443" "the connector gets its first relay"
has nodes "--relay=relay2.lab.test" "the connector gets every relay"
has nodes "add: [NET_ADMIN]" "the connector gets NET_ADMIN"
has nodes "path: /dev/net/tun" "the connector gets the TUN device"
has nodes "privileged: true" "IP forwarding is turned on by a privileged init container"
has nodes "image: ghcr.io/terrabyteian/warren-connector:0.0.0" "the connector runs the connector image"
has nodes "claimName: t-warren-connector" "the connector keeps its credentials on a volume"
has nodes "checksum/bundle:" "a bundle change restarts relays and connectors"

render nodes-options "${nodes[@]}" --set connector.forwardingInit=false \
  --set image.digest=sha256:0123 --set connector.persistence.enabled=false
lacks nodes-options "privileged: true" "the forwarding init container can be turned off"
has nodes-options "image: ghcr.io/terrabyteian/warren@sha256:0123" "an image digest pins the image"
has nodes-options "emptyDir: {}" "without persistence the connector state is an emptyDir"

# What the chart refuses.
refuses "controlPlane.trustDomain is required" "a missing trust domain is refused"
refuses "controlPlane.idp is required" "a missing identity provider is refused" \
  --set controlPlane.trustDomain=lab.test --set controlPlane.publicUrl=https://warren.lab.test
refuses "nodes.bundle" "a relay without a node bundle is refused" \
  "${base[@]}" --set relay.enabled=true --set relay.joinToken.existingSecret=relay-join
refuses "relay.joinToken.existingSecret is required" "a relay without a join token is refused" \
  "${base[@]}" --set relay.enabled=true --set nodes.bundle.version=1
refuses "connector.relays is required" "a connector without relays is refused" \
  "${base[@]}" --set connector.enabled=true --set nodes.bundle.version=1 \
  --set connector.group=homelab --set connector.joinToken.existingSecret=connector-join

if [ "$failures" -ne 0 ]; then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all chart checks passed"
