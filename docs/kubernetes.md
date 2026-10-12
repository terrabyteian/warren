# Running warren on Kubernetes

warren publishes container images and a Helm chart for running the control
plane, a relay and a kernel-mode connector on a Kubernetes cluster, such as a
homelab one. This is the minimal deployment path: the operator, the CRDs and
publishing apps by annotating a Service come with milestone M2
([design.md section 9](design.md#9-kubernetes)).

| What | Where |
| --- | --- |
| Control plane image | `ghcr.io/terrabyteian/warren:X.Y.Z` |
| Relay image | `ghcr.io/terrabyteian/warren-relay:X.Y.Z` |
| Kernel-mode connector image | `ghcr.io/terrabyteian/warren-connector:X.Y.Z` |
| Helm chart | `oci://ghcr.io/terrabyteian/charts/warren`, version `X.Y.Z` |

Each release tag `vX.Y.Z` publishes all four, for linux/amd64 and
linux/arm64. The chart's default image tag is its own version.

## Images

- **`warren`** is the full `warren` binary (control plane, relay and
  connector roles, plus `warren admin`) on a distroless base: CA
  certificates and the C runtime, no shell, running as the nonroot user
  (UID 65532). The control plane runs it.
- **`warren-relay`** is the data-path build of the binary (the relay and
  connector roles only, `--no-default-features --features relay,connector`)
  on the same distroless base. It links no control-plane, console or
  Kubernetes crates ([dependencies.md](dependencies.md)). The relay runs it.
- **`warren-connector`** is the same data-path build on Debian slim with
  `iproute2` and `nftables`, because kernel-mode forwarding runs `ip` and
  `nft` to set up its TUN device, routes and NAT table.

All three are built from the [Dockerfile](../Dockerfile) with pinned base images,
from vendored sources without network access, and the binaries are compiled
natively or cross-compiled, never under emulation. The release workflow
signs each image with cosign and publishes two SBOMs for it: one of the
image's packages, attached by the build with a provenance attestation, and
an SPDX SBOM of the crates in `Cargo.lock` that the binaries are built from,
attested with cosign. To check the signature and read both:

```sh
id=https://github.com/terrabyteian/warren/.github/workflows/release.yml@refs/tags/vX.Y.Z
issuer=https://token.actions.githubusercontent.com
cosign verify ghcr.io/terrabyteian/warren:X.Y.Z \
  --certificate-identity "$id" --certificate-oidc-issuer "$issuer"
docker buildx imagetools inspect ghcr.io/terrabyteian/warren:X.Y.Z --format '{{ json .SBOM }}'
cosign verify-attestation ghcr.io/terrabyteian/warren:X.Y.Z --type spdxjson \
  --certificate-identity "$id" --certificate-oidc-issuer "$issuer"
```

The chart is signed the same way (`cosign verify
ghcr.io/terrabyteian/charts/warren:X.Y.Z ...`). To build the images yourself:

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t warren .
docker buildx build --target warren-relay -t warren-relay .
docker buildx build --target warren-connector -t warren-connector .
```

## Before you start

- **A cluster** running Kubernetes 1.27 or later with a default
  StorageClass.
- **A LoadBalancer implementation** (MetalLB, kube-vip, a cloud provider's)
  for the relay, whose Service carries UDP and TCP on port 443 at the same
  address, and for the control plane if browsers and clients outside the
  cluster reach it that way.
- **Two DNS names**, resolvable both outside and inside the cluster:
  the organization URL's host (for example `warren.home.example`) for the
  control plane's address, and a relay name (`relay.home.example`) for the
  relay's. Relays and connectors join and run at the control plane's name,
  so it must resolve inside the cluster too; a homelab router's DNS usually
  covers both.
- **An OpenID Connect identity provider.** Register warren as a web client
  with the redirect URI `https://<organization URL host>/v1/auth/callback`.
  For Google, create an OAuth client ID of type "Web application" in the
  Google Cloud console; the issuer is `https://accounts.google.com`. Google's
  ID tokens carry no groups and no MFA claim, so rules that need either
  cannot match Google sign-ins.
- **A namespace for warren** that allows the connector: it needs
  `NET_ADMIN`, the node's `/dev/net/tun` and a privileged init container
  (see [The connector](#4-add-a-connector)), so label the namespace for the
  `privileged` Pod Security level.

```sh
kubectl create namespace warren
kubectl label namespace warren pod-security.kubernetes.io/enforce=privileged
```

## 1. Install the control plane

Create the Secrets the control plane reads. The key-encryption key seals the
certificate authorities and signing keys in the database; keep a copy
somewhere safe, since without it the database cannot be opened.

```sh
head -c 32 /dev/urandom | base64 > kek
kubectl -n warren create secret generic warren-kek --from-file=kek=kek
kubectl -n warren create secret generic warren-idp --from-literal=client-secret='<IdP client secret>'
# Optional: a certificate for the organization URL that browsers trust,
# for example one issued by cert-manager into this Secret.
kubectl -n warren create secret tls warren-tls --cert=tls.crt --key=tls.key
```

Write `values.yaml`:

```yaml
controlPlane:
  trustDomain: home.example
  publicUrl: https://warren.home.example
  idp:
    issuer: https://accounts.google.com
    clientId: 1234-abcd.apps.googleusercontent.com
    scopes: [openid, email, profile]
  idpClientSecret: { existingSecret: warren-idp }
  keyEncryptionKey: { existingSecret: warren-kek }
  # With tls, add a second name for relays, connectors and enrolled
  # clients, which reach the control plane under its own certificate
  # (operating.md), and point it at the same address:
  # tls: { existingSecret: warren-tls }
  # dnsNames: [nodes.warren.home.example]
  service:
    type: LoadBalancer
  config:
    devices:
      approval: manual
  policy:
    homelab.yaml: |
      apiVersion: warren.dev/v1alpha1
      kind: ConnectorGroup
      metadata: { name: homelab }
      spec:
        destinations:
          cidrs: ["192.168.1.0/24"]
        clientNames: ["*.home.example"]
```

Then install, and point the organization URL's DNS name at the Service's
external address:

```sh
helm install warren oci://ghcr.io/terrabyteian/charts/warren --version X.Y.Z \
  -n warren -f values.yaml
kubectl -n warren get svc warren-control-plane
```

The control plane is a one-replica StatefulSet: its SQLite database, admin
socket and (without `keyEncryptionKey`) key-encryption key live on a 1 GiB
volume. It listens on port 8443 in the pod, behind the Service's port 443.
Every connection keeps its TLS end to end: put nothing in front of it that
terminates TLS (no Ingress that decrypts), since relays, connectors and
enrolled clients authenticate with certificates. Behind a load balancer that
hides client addresses, read [Behind a load balancer](operating.md#behind-a-load-balancer).

## 2. Reach the control plane and sign in

The organization URL, for example `https://warren.home.example`, is where
clients sign in and enroll, once its DNS name resolves to the control plane
Service's address. Without `controlPlane.tls`, it presents a certificate
from the deployment's own CA, which clients pin by its root fingerprint
(`warren admin deployment` prints it).

Without a load balancer address, forward the Service to your workstation on
port 443, so the URL and the IdP's redirect URI stay the same, and resolve
the name locally:

```sh
echo "127.0.0.1 warren.home.example" | sudo tee -a /etc/hosts
kubectl -n warren port-forward svc/warren-control-plane 443:443
```

macOS lets you bind port 443 without root. On Linux, a port below 1024 needs
root; run kubectl under sudo with your kubeconfig named explicitly, since
sudo usually resets `HOME`:

```sh
sudo kubectl --kubeconfig "${KUBECONFIG:-$HOME/.kube/config}" \
  -n warren port-forward svc/warren-control-plane 443:443
```

Sign in from a Mac with the warren client ([macos.md](macos.md#sign-in)),
which opens the identity provider in the browser and enrolls the Mac;
without `controlPlane.tls`, add `--fingerprint` with the root fingerprint:

```sh
warren login https://warren.home.example
```

This release has no web console yet. Administer the deployment with
`warren admin` inside the control plane's pod, which talks to its local admin
socket:

```sh
kubectl -n warren exec warren-control-plane-0 -- warren admin deployment
kubectl -n warren exec warren-control-plane-0 -- warren admin devices list
kubectl -n warren exec warren-control-plane-0 -- warren admin devices approve <device>
```

Policy files come from `controlPlane.policy` (or an existing ConfigMap in
`controlPlane.policyConfigMap`), mounted at `/etc/warren/policy`. After a
`helm upgrade` that changes them, Kubernetes updates the mounted files
within a minute or so; then load them:

```sh
kubectl -n warren exec warren-control-plane-0 -- warren admin policy reload
```

Other configuration changes (`controlPlane.config` and the settings above it)
restart the control plane. Every setting is described in
[examples/control-plane.yaml](examples/control-plane.yaml); the chart sets
`listen`, `dataDir`, `policyDir`, `tls` and `keyEncryptionKeyFile` itself.

## 3. Add a relay

Relays and connectors join the deployment with single-use join tokens and
keep the credentials they receive on a small volume, so a restarted or
rescheduled pod comes back without a new token. Create a token for the relay,
naming the DNS name clients and connectors reach it at:

```sh
kubectl -n warren exec warren-control-plane-0 -- \
  warren admin join-token create --role relay --name relay-1 --dns-name relay.home.example \
  | jq -r .token > relay-token
kubectl -n warren create secret generic relay-join --from-file=token=relay-token
```

Relays and connectors enforce a node bundle: the deployment's connector
groups, apps, users, devices, access rules and revocations, as JSON with the
same `trustDomain`. Until they consume the control plane's own bundles (M2),
the chart gives them a static one from `nodes.bundle`, and restarts them when
it changes. The format is in
[crates/warren-core/src/bundle.rs](../crates/warren-core/src/bundle.rs);
[scripts/e2e-macos.sh](../scripts/e2e-macos.sh) writes a complete one. Add to
`values.yaml`:

```yaml
nodes:
  bundle:
    version: 1
    trustDomain: home.example
    connectorGroups:
      - name: homelab
        destinations: { cidrs: ["192.168.1.0/24"] }
        clientNames: ["*.home.example"]
    apps:
      - name: nas
        connectorGroup: homelab
        destinations: [{ cidr: 192.168.1.10/32, ports: [443], protocol: tcp }]
    users: [{ id: "<user ID>", groups: [admins] }]
    devices: [{ id: "<device ID>", approved: true }]
    rules:
      - id: homelab/admins-nas
        who: { groups: [admins] }
        what: { apps: [nas] }
relay:
  enabled: true
  joinToken: { existingSecret: relay-join }
```

```sh
helm upgrade warren oci://ghcr.io/terrabyteian/charts/warren --version X.Y.Z \
  -n warren -f values.yaml
kubectl -n warren get svc warren-relay
```

Point `relay.home.example` at the relay Service's external address. The
Service carries QUIC on UDP 443 and the HTTP/2 fallback on TCP 443, at one
address; it keeps `externalTrafficPolicy: Local` by default so the relay sees
clients' real addresses. Clients pick the lowest-latency relay, so a second
region is another release (or another values file) with its own token.

## 4. Add a connector

The connector forwards admitted traffic into the network it can reach, using
a TUN device and NAT in its own pod's network namespace. It runs as root with
only the `NET_ADMIN` capability and the node's `/dev/net/tun`, and a
privileged init container turns on IP forwarding in the pod's network
namespace (a container cannot write `/proc/sys`). It never touches the node's
network configuration. Where IP forwarding is enabled another way (an allowed
unsafe sysctl, for example), set `connector.forwardingInit: false`.

Create a token for the connector's group, and add it to `values.yaml`:

```sh
kubectl -n warren exec warren-control-plane-0 -- \
  warren admin join-token create --role connector --group homelab --name homelab-1 \
  | jq -r .token > connector-token
kubectl -n warren create secret generic connector-join --from-file=token=connector-token
```

```yaml
connector:
  enabled: true
  group: homelab
  # The relay's DNS name, dialed at its in-cluster Service.
  relays: ["relay.home.example@warren-relay:443"]
  joinToken: { existingSecret: connector-join }
```

Each `relays` entry is `NAME[@HOST:PORT]`: the name in the relay's
certificate (its token's `--dns-name`) and, optionally, where to dial it. A
relay outside the cluster is just its name. Then `helm upgrade` as above.

The connector dials out to its relays and serves nothing, so it needs no
Service. Its metrics, like the relay's, are on port 9090 at `/metrics`.

## Values

The chart's [values.yaml](../charts/warren/values.yaml) documents every
value. The ones most installs set:

| Value | Default | What it is |
| --- | --- | --- |
| `controlPlane.trustDomain` | (required) | The deployment's name in identity URIs. |
| `controlPlane.publicUrl` | (required) | The organization URL, `https://host[:port]`. |
| `controlPlane.dnsNames` | `[]` | More names for the control plane's own certificate; with `tls`, the first is where nodes and clients reach it. |
| `controlPlane.idp` | (required) | The `idp` configuration section: `issuer`, `clientId`, `scopes`, `groupsClaim`, `mfaAmrValues`. |
| `controlPlane.idpClientSecret.existingSecret` | `""` | Secret with the IdP client secret (key `client-secret`). |
| `controlPlane.tls.existingSecret` | `""` | `kubernetes.io/tls` Secret for the organization URL. |
| `controlPlane.keyEncryptionKey.existingSecret` | `""` | Secret with the key-encryption key (key `kek`); empty keeps it on the data volume. |
| `controlPlane.config` | `{}` | More configuration merged into the control plane's file. |
| `controlPlane.policy` / `policyConfigMap` | `{}` / `""` | Policy files by name, or an existing ConfigMap of them. |
| `controlPlane.persistence.size` | `1Gi` | The database volume. |
| `controlPlane.service.type` | `ClusterIP` | `LoadBalancer` to reach it from outside the cluster. |
| `nodes.bundle` / `bundleConfigMap` | `{}` / `""` | The node bundle for relays and connectors, or an existing ConfigMap with `bundle.json`. |
| `relay.enabled` | `false` | Run a relay. |
| `relay.joinToken.existingSecret` | `""` | Secret with the relay's join token (key `token`). |
| `relay.service.type` | `LoadBalancer` | The relay's Service, UDP and TCP on `relay.service.port` (443). |
| `connector.enabled` | `false` | Run a kernel-mode connector. |
| `connector.group` | `""` | Its connector group, as in its token. |
| `connector.relays` | `[]` | Relays to attach to, each `NAME[@HOST:PORT]`. |
| `connector.joinToken.existingSecret` | `""` | Secret with the connector's join token (key `token`). |
| `connector.nat` | `masquerade` | `none` leaves NAT to you. |
| `connector.forwardingInit` | `true` | The privileged init container that turns on IP forwarding. |
| `image.tag`, `relayImage.tag`, `connectorImage.tag` | the chart version | The control plane's, relay's and connector's images; or `*.digest` to pin by digest. |

## Upgrades, backups and removal

- `helm upgrade` with a new chart version moves every role to that version's
  images. The control plane restarts in place on its volume.
- Back up the control plane's volume (`data-warren-control-plane-0`) and the
  key-encryption key: together they are the deployment's CA, keys, devices
  and audit state.
- `helm uninstall` leaves the control plane's volume (a StatefulSet volume
  claim) and the Secrets you created; the relay's and connector's volumes go
  with the release, and their nodes then need new tokens. Revoke nodes you
  remove with `warren admin nodes revoke`.

## What this chart does not do yet

- One control plane replica: SQLite has one writer. PostgreSQL for a
  highly available control plane comes later.
- One relay and one connector per release, since each join token makes one
  node; run more with more releases or values files.
- No operator, CRDs or Service annotations, no userspace (unprivileged)
  connector mode, and no Kubernetes API access through warren: M2.

## How it is tested

[scripts/test-chart.sh](../scripts/test-chart.sh) lints the chart, parses
renders of chosen values and checks each object's fields, and checks
refusals of incomplete values, on every pull request. CI checks that the
relay and connector images offer no control-plane role. [scripts/e2e-kind.sh](../scripts/e2e-kind.sh) installs the images
CI just built on a kind cluster: the control plane, join tokens created with
`warren admin`, then the relay and a kernel-mode connector, checking that
both join, that the connector creates its TUN device and NAT table and
attaches to the relay, and that a restarted connector comes back on the
credentials it kept.
