#!/usr/bin/env bash
# Template tests for the chart in charts/warren: `helm lint --strict` over
# the values in charts/warren/ci/, then renders of chosen values, parsed into
# objects and checked field by field for what each role must and must not
# get, and the values the chart refuses. Every render is also checked for a
# mapping that repeats a key. Needs helm
# (scripts/install-kube-tools.sh), jq, and Ruby for its standard YAML
# library.
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

# YAML documents on stdin to a JSON array of them on stdout.
# shellcheck disable=SC2016 # $stdin is Ruby's, not the shell's
yaml2json() { ruby -ryaml -rjson -e 'puts JSON.generate(YAML.load_stream($stdin.read).compact)'; }

# YAML documents on stdin: each mapping key repeated within its mapping, one
# per line on stdout. helm and yaml2json keep the last of them, but
# kustomize (and so Flux's post-renderer) and kubeconform -strict refuse the
# document.
# shellcheck disable=SC2016 # the #{} interpolations are Ruby's
repeated_keys() {
  ruby -ryaml -e '
    def walk(node)
      if node.is_a?(Psych::Nodes::Mapping)
        keys = node.children.each_slice(2).map(&:first).grep(Psych::Nodes::Scalar)
        keys.group_by(&:value).each_value do |same|
          same.drop(1).each { |k| puts "line #{k.start_line + 1}: #{k.value}" }
        end
      end
      node.children&.each { |c| walk(c) }
    end
    walk(Psych.parse_stream($stdin.read))'
}
# unique_keys DESCRIPTION FILE: no mapping in the YAML documents in FILE
# repeats a key.
unique_keys() {
  repeated_keys <"$2" >"$work/repeated"
  if [ -s "$work/repeated" ]; then
    cat "$work/repeated" >&2
    fail "$1"
  else
    ok "$1"
  fi
}

# The release is "t", so every object is named t-warren-<role>.
# shellcheck disable=SC2016 # the $ parameters are jq's
defs='
def obj($kind; $name): .[] | select(.kind == $kind and .metadata.name == ("t-warren-" + $name));
def pod($kind; $name): obj($kind; $name) | .spec.template.spec;
def container($kind; $name; $c): pod($kind; $name) | .containers[] | select(.name == $c);
def cp: container("StatefulSet"; "control-plane"; "control-plane");
def relay: container("Deployment"; "relay"; "relay");
def connector: container("Deployment"; "connector"; "connector");
def mounts($c): [$c | .volumeMounts[] | {(.name): .mountPath}] | add;
'

# render NAME [helm template args...]: renders into $work/NAME.json, an
# array of the objects, and the control plane's configuration file into
# $work/NAME.config.json, and checks that no mapping in it repeats a key.
render() {
  local name=$1
  shift
  helm template t "$chart" --namespace warren "$@" >"$work/$name.yaml"
  unique_keys "render $name repeats no mapping key" "$work/$name.yaml"
  yaml2json <"$work/$name.yaml" >"$work/$name.json"
  jq -r "$defs"' obj("ConfigMap"; "control-plane") | .data["control-plane.yaml"]' "$work/$name.json" |
    yaml2json | jq '.[0]' >"$work/$name.config.json"
}
# check NAME FILTER DESCRIPTION: FILTER, over the objects of render NAME, is
# true.
check() {
  if jq -e "$defs $2" "$work/$1.json" >/dev/null; then ok "$3"; else fail "$3"; fi
}
# config NAME FILTER DESCRIPTION: FILTER, over the control plane's
# configuration in render NAME, is true.
config() {
  if jq -e "$2" "$work/$1.config.json" >/dev/null; then ok "$3"; else fail "$3"; fi
}
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
  helm template t "$chart" -f "$values" >"$work/ci.yaml"
  unique_keys "the render with $(basename "$values") repeats no mapping key" "$work/ci.yaml"
done

base=(--set controlPlane.trustDomain=lab.test
  --set controlPlane.publicUrl=https://warren.lab.test
  --set controlPlane.idp.issuer=https://idp.lab.test
  --set controlPlane.idp.clientId=warren)

# The control plane alone.
render cp "${base[@]}"
check cp '[obj("StatefulSet"; "control-plane")] | length == 1' "the control plane is a StatefulSet"
config cp '.trustDomain == "lab.test" and .publicUrl == "https://warren.lab.test"' \
  "the configuration carries the trust domain and organization URL"
config cp '.idp == {issuer: "https://idp.lab.test", clientId: "warren"}' "the configuration carries the identity provider"
config cp '.listen == "[::]:8443"' "the control plane listens on 8443 inside the pod"
config cp '.policyDir == "/etc/warren/policy" and .dataDir == "/var/lib/warren"' \
  "the policy and data directories are the mounted ones"
check cp 'mounts(cp) | .policy == "/etc/warren/policy" and .data == "/var/lib/warren"' \
  "the policy ConfigMap and the data volume are mounted there"
check cp '([pod("StatefulSet"; "control-plane").volumes[] | select(.name == "policy") | .configMap.name] == ["t-warren-control-plane-policy"])
  and obj("ConfigMap"; "control-plane-policy").data == {}' "without policy files the policy ConfigMap is empty"
check cp 'obj("StatefulSet"; "control-plane") | .spec.volumeClaimTemplates
  | map({name: .metadata.name, storage: .spec.resources.requests.storage}) == [{name: "data", storage: "1Gi"}]' \
  "the database gets a 1Gi volume"
check cp 'cp.securityContext | .runAsNonRoot == true and .readOnlyRootFilesystem == true
  and .allowPrivilegeEscalation == false and .capabilities.drop == ["ALL"]' \
  "the control plane runs nonroot, unprivileged, on a read-only root filesystem"
check cp 'cp.image == "ghcr.io/terrabyteian/warren:0.0.0"' "the control plane image tag defaults to the appVersion"
check cp 'obj("Service"; "control-plane").spec | .type == "ClusterIP"
  and .ports == [{name: "https", port: 443, targetPort: "https", protocol: "TCP"}]' \
  "the control plane Service is ClusterIP on TCP 443 by default"
config cp 'has("tls") or has("keyEncryptionKeyFile") or (.idp | has("clientSecretFile")) or has("localAccounts") | not' \
  "no operator certificate, key-encryption key file, IdP secret or first admin unless given"
check cp '[pod("StatefulSet"; "control-plane").volumes[] | select(.secret)] == []' "no Secrets are mounted unless given"
check cp '[.[] | select(.kind == "Deployment")] == []' "no relay or connector unless enabled"
check cp '[obj("ConfigMap"; "bundle")] == []' "no node bundle unless a node is enabled"

# Every Secret the control plane can use.
render cp-secrets "${base[@]}" \
  --set controlPlane.tls.existingSecret=warren-tls \
  --set controlPlane.keyEncryptionKey.existingSecret=warren-kek \
  --set controlPlane.idpClientSecret.existingSecret=warren-idp \
  --set controlPlane.bootstrapAdmin.existingSecret=warren-admin \
  --set controlPlane.config.localAccounts.maxFailuresPerSource=0 \
  --set 'controlPlane.dnsNames={nodes.warren.lab.test}' \
  --set controlPlane.config.devices.approval=automatic \
  --set controlPlane.service.type=LoadBalancer \
  --set-string 'controlPlane.policy.lab\.yaml=kind: AccessPolicy'
config cp-secrets '.tls == {certFile: "/etc/warren/tls/tls.crt", keyFile: "/etc/warren/tls/tls.key"}' \
  "the operator certificate is read from the TLS Secret's mount"
config cp-secrets '.keyEncryptionKeyFile == "/etc/warren/kek/kek"' "the key-encryption key is read from its Secret's mount"
config cp-secrets '.idp.clientSecretFile == "/etc/warren/idp/client-secret"' "the IdP client secret is read from its Secret's mount"
config cp-secrets '.localAccounts == {maxFailuresPerSource: 0,
  bootstrapAdmin: {username: "admin", passwordFile: "/etc/warren/admin/password", groups: ["admins"]}}' \
  "the first admin's password is read from its Secret's mount, beside the other localAccounts settings"
check cp-secrets 'mounts(cp) | .tls == "/etc/warren/tls" and .kek == "/etc/warren/kek" and .idp == "/etc/warren/idp"
  and .admin == "/etc/warren/admin"' "each Secret is mounted where the configuration reads it"
check cp-secrets '[pod("StatefulSet"; "control-plane").volumes[] | select(.secret) | {(.name): .secret.secretName}] | add
  == {tls: "warren-tls", kek: "warren-kek", idp: "warren-idp", admin: "warren-admin"}' "the mounts are the named Secrets"
check cp-secrets '[pod("StatefulSet"; "control-plane").volumes[] | select(.name == "admin") | .secret]
  == [{secretName: "warren-admin", defaultMode: 256, items: [{key: "password", path: "password"}]}]' \
  "the first admin's Secret is mounted read-only to its owner"

# Built-in accounts only: no identity provider, a first admin with another
# name and groups.
render cp-local --set controlPlane.trustDomain=lab.test --set controlPlane.publicUrl=https://warren.lab.test \
  --set controlPlane.bootstrapAdmin.existingSecret=warren-admin --set controlPlane.bootstrapAdmin.key=pw \
  --set controlPlane.bootstrapAdmin.username=root-admin --set 'controlPlane.bootstrapAdmin.groups={admins,ops}'
config cp-local '(has("idp") | not) and .localAccounts.bootstrapAdmin
  == {username: "root-admin", passwordFile: "/etc/warren/admin/pw", groups: ["admins", "ops"]}' \
  "without an identity provider the configuration has none, and the first admin is as given"
config cp-secrets '.dnsNames == ["nodes.warren.lab.test"]' "dnsNames pass through"
config cp-secrets '.devices.approval == "automatic"' "more configuration merges in"
check cp-secrets 'obj("ConfigMap"; "control-plane-policy").data == {"lab.yaml": "kind: AccessPolicy\n"}' \
  "policy files land in the policy ConfigMap"
check cp-secrets 'obj("Service"; "control-plane").spec.type == "LoadBalancer"' "the control plane Service type is configurable"

# Relay and connector.
nodes=("${base[@]}"
  --set nodes.bundle.version=1 --set nodes.bundle.trustDomain=lab.test
  --set relay.enabled=true --set relay.joinToken.existingSecret=relay-join
  --set connector.enabled=true --set connector.group=homelab
  --set connector.joinToken.existingSecret=connector-join
  --set 'connector.relays={relay.lab.test@t-warren-relay:443,relay2.lab.test}')
render nodes "${nodes[@]}"
check nodes 'obj("ConfigMap"; "bundle").data["bundle.json"] | fromjson == {version: 1, trustDomain: "lab.test"}' \
  "the node bundle is rendered as JSON"
check nodes 'obj("Service"; "relay").spec | .type == "LoadBalancer" and .externalTrafficPolicy == "Local"
  and .ports == [{name: "quic", port: 443, targetPort: "quic", protocol: "UDP"},
                 {name: "https", port: 443, targetPort: "https", protocol: "TCP"}]' \
  "the relay Service is a LoadBalancer with QUIC on UDP 443 and the HTTP/2 fallback on TCP 443"
check nodes '[relay.ports[] | {name, containerPort, protocol}] | index([{name: "quic", containerPort: 8443, protocol: "UDP"},
  {name: "https", containerPort: 8443, protocol: "TCP"}]) == 0' "the relay serves both on 8443"
check nodes 'relay.image == "ghcr.io/terrabyteian/warren-relay:0.0.0"' "the relay runs the data-path relay image"
check nodes 'connector.image == "ghcr.io/terrabyteian/warren-connector:0.0.0"
  and (pod("Deployment"; "connector").initContainers | map(.image) == ["ghcr.io/terrabyteian/warren-connector:0.0.0"])' \
  "the connector runs the data-path connector image"
check nodes 'cp.image == "ghcr.io/terrabyteian/warren:0.0.0"' "only the control plane runs the full image"
check nodes 'relay.securityContext.runAsNonRoot == true and pod("Deployment"; "relay").securityContext.runAsUser == 65532' \
  "the relay runs as nonroot"
for role in relay connector; do
  # shellcheck disable=SC2016 # $(WARREN_JOIN_TOKEN) is Kubernetes' env syntax, kept literal
  check nodes "$role"' | (.args | index("--join-token=$(WARREN_JOIN_TOKEN)") != null)
    and .env == [{name: "WARREN_JOIN_TOKEN", valueFrom: {secretKeyRef: {name: "'"$role"'-join", key: "token"}}}]' \
    "the $role's join token comes from its Secret through the environment"
  check nodes "$role"' | .args | index("--bundle=/etc/warren/bundle/bundle.json") != null' "the $role reads the node bundle"
  check nodes 'mounts('"$role"').bundle == "/etc/warren/bundle"
    and ([pod("Deployment"; "'"$role"'").volumes[] | select(.name == "bundle") | .configMap.name] == ["t-warren-bundle"])' \
    "the $role mounts the bundle ConfigMap there"
done
check nodes 'connector.args | index("--group=homelab") != null' "the connector gets its group"
check nodes '[connector.args[] | select(startswith("--relay="))] == ["--relay=relay.lab.test@t-warren-relay:443", "--relay=relay2.lab.test"]' \
  "the connector gets every relay, in order"
check nodes 'connector.securityContext | .capabilities == {drop: ["ALL"], add: ["NET_ADMIN"]}
  and .allowPrivilegeEscalation == false and (.privileged // false) == false' \
  "the connector gets NET_ADMIN only, unprivileged"
check nodes 'mounts(connector).tun == "/dev/net/tun"
  and ([pod("Deployment"; "connector").volumes[] | select(.name == "tun") | .hostPath] == [{path: "/dev/net/tun", type: "CharDevice"}])' \
  "the connector gets the node's TUN device"
check nodes 'pod("Deployment"; "connector").initContainers | map({name, privileged: .securityContext.privileged})
  == [{name: "forwarding", privileged: true}]' "IP forwarding is turned on by a privileged init container"
check nodes '[pod("Deployment"; "connector").volumes[] | select(.name == "state") | .persistentVolumeClaim.claimName] == ["t-warren-connector"]
  and ([obj("PersistentVolumeClaim"; "connector")] | length == 1)' "the connector keeps its credentials on a volume"
check nodes '[obj("Deployment"; "relay", "connector") | .spec.template.metadata.annotations["checksum/bundle"]]
  | length == 2 and .[0] != null and .[0] == .[1]' "a bundle change restarts relays and connectors"

render nodes-options "${nodes[@]}" --set connector.forwardingInit=false \
  --set image.digest=sha256:0123 --set relayImage.digest=sha256:4567 --set connectorImage.digest=sha256:89ab \
  --set connector.persistence.enabled=false
check nodes-options 'pod("Deployment"; "connector").initContainers == null' "the forwarding init container can be turned off"
check nodes-options 'cp.image == "ghcr.io/terrabyteian/warren@sha256:0123"
  and relay.image == "ghcr.io/terrabyteian/warren-relay@sha256:4567"
  and connector.image == "ghcr.io/terrabyteian/warren-connector@sha256:89ab"' "an image digest pins each role's image"
check nodes-options '[pod("Deployment"; "connector").volumes[] | select(.name == "state")] == [{name: "state", emptyDir: {}}]
  and ([obj("PersistentVolumeClaim"; "connector")] == [])' "without persistence the connector state is an emptyDir"

# What the chart refuses.
refuses "controlPlane.trustDomain is required" "a missing trust domain is refused"
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
