# Benchmarks

Performance is a feature (docs/design.md, principle 2), so the data path is
measured from the first milestone that moves packets. This document says
what is measured, how to run it, and what the numbers were when they were
last recorded. CI runs the same suites on every pull request and push to
`main` and publishes the results in the job summary; benchmarks never gate a
change.

## What is measured

Three quantities, for warren and for baselines over the same links:

| Quantity | warren | Baselines |
| --- | --- | --- |
| Setup time | `warren_client::connect`: outer QUIC handshake to the relay, CONNECT-UDP splice, inner QUIC handshake to the connector, CONNECT-IP and address assignment | TCP connect plus TLS 1.3 handshake (one round trip through an echo) |
| Latency | round trips of 64-byte messages through the tunnel | the same messages over TLS 1.3 over TCP, and over plain TCP or UDP |
| Throughput | one TCP stream through the tunnel into a sink (kernel suite), or a window of 1280-byte UDP packets echoed through it (in-process suite) | one TCP stream over TLS 1.3, and over plain TCP |

TCP connect time through an established tunnel is reported too: it is the
first-packet cost of flow admission (policy decision and audit record) on
top of the path.

### The two suites

- **In-process** ([`scripts/bench-inprocess.sh`](../scripts/bench-inprocess.sh),
  `warren-harness bench --mode inprocess`): a relay, a connector with the
  userspace test backend (it relays UDP to a loopback echo server) and
  clients in one process, against TLS 1.3 over TCP and plain UDP on
  loopback. It needs no privileges and runs on macOS and Linux. It measures
  the transport stack itself, not kernel forwarding.
- **Kernel** ([`scripts/bench-kernel.sh`](../scripts/bench-kernel.sh)): the
  real `warren relay` and `warren connector` binaries in network namespaces,
  as in the kernel-mode end-to-end tests: the client's TUN device, the
  relay, the connector's TUN device and NAT, and an app namespace with an
  echo and a sink. Ordinary TCP crosses it. The client link runs at a
  1280-byte MTU, the narrowest path the profile must support. The
  baselines (TLS 1.3 over TCP and plain TCP to the same app namespace) use
  the same links with ordinary IP forwarding instead of warren, and
  WireGuard between the client and connector namespaces is measured when the
  kernel and `wg` are available. Linux and root only.

Every TLS in both suites, warren's and the baselines', is rustls on aws-lc-rs
with the same TLS 1.3 provider.

## Running

```sh
cargo build --release -p warren -p warren-harness --locked --offline
scripts/bench-inprocess.sh target/release 5 --summary results.md
sudo scripts/bench-kernel.sh target/release 10 --summary results.md
```

Each prints one JSON object per run; `--summary` appends Markdown tables.

## Results

Recorded on 2026-10-11 on a development machine: an Apple Silicon Mac
(macOS), and an 18-CPU arm64 Linux virtual machine (kernel 7.0) on the same
machine for the Linux and kernel suites. These are not CI numbers; CI
publishes its own per run. Treat absolute values as indicative only:
virtualized loopback and veth links are faster and smoother than real
networks.

### In-process

| Platform | warren setup p50 | warren RTT p50 / p99 | warren UDP goodput | TLS over TCP setup p50 | TLS over TCP RTT p50 / p99 |
| --- | --- | --- | --- | --- | --- |
| macOS arm64 | 2.0 ms | 0.102 / 0.130 ms | 393 Mbit/s | 0.23 ms | 0.018 / 0.033 ms |
| Linux arm64 | 1.9 ms | 0.066 / 0.204 ms | 789 Mbit/s | 0.14 ms | 0.004 / 0.030 ms |

UDP goodput counts 1280-byte packets echoed back through the tunnel, so the
tunnel carries twice that.

### Kernel (Linux arm64, 10-second runs)

| Path | Setup p50 | TCP connect p50 | RTT 64 B p50 / p99 | TCP throughput |
| --- | --- | --- | --- | --- |
| warren over QUIC | 25.4 ms | 0.21 ms | 0.123 / 0.572 ms | 1553 Mbit/s |
| warren over the HTTP/2 fallback | 31.3 ms | 0.17 ms | 0.106 / 0.184 ms | 1463 Mbit/s |
| TLS 1.3 over TCP | n/a | 0.18 ms | 0.008 / 0.021 ms | 30259 Mbit/s |
| plain TCP | n/a | 0.008 ms | 0.006 / 0.050 ms | 133388 Mbit/s |
| WireGuard | not available in this virtual machine | | | |

## Reading the numbers

- **One TCP stream through warren moves about 1.5 Gbit/s** between
  namespaces, above the v1 target of 1 Gbit/s per connector, through a
  relay, with the client on a 1280-byte path. Every packet is encrypted
  twice by the client (inner and outer session), decrypted and re-encrypted
  by the relay, and decrypted twice by the connector, all in userspace at the
  tunnel MTU.
- **The TLS-over-TCP baseline is not the same job.** It encrypts once per
  record and hands the kernel 64 KB segments that veth carries without
  splitting, so it sets a ceiling for the links rather than a target for a
  packet tunnel. The comparison warren is held to is other private-access
  tunnels on the same links, which CI cannot run; WireGuard, where the
  kernel offers it, is the nearest packet-tunnel reference.
- **Each round trip costs about 0.1 ms more than a direct connection**: two
  userspace hops (relay and connector) and the client's own processing. A
  TCP connect through the tunnel (0.21 ms) is one tunnel round trip plus
  about 0.1 ms of first-packet work at the connector: the policy decision,
  the audit record and the flow and NAT state.
- **Setup takes about 2 ms in-process and 25 ms in namespaces.** Both cover
  two QUIC handshakes and two CONNECT exchanges; the namespace figure also
  includes neighbor discovery on fresh links and the client's 1280-byte
  path, on which full-size inner handshake packets travel in capsules on
  the outer stream (docs/protocol.md section 9). Profiling the namespace
  setup path is follow-up work.
- **The HTTP/2 fallback costs little on a clean link** (about 6% of
  throughput here); on lossy links TCP's head-of-line blocking will show
  more, which is why QUIC is preferred and re-probed.

## What comes next

The M4 performance work starts from these suites: CPU per Gbit/s, multiple
streams and clients, lossy and high-latency links (netem), and batching on
the TUN devices, which today move one packet per system call.
