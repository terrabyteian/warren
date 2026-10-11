# warren documentation

| Document | What it covers |
| --- | --- |
| [design.md](design.md) | What warren promises and why: goals, non-goals and the leave-out list, the guarantees (G1 to G19), architecture and trust boundaries, client experience, identity, devices and policy, Kubernetes, revocation and failure behavior, deployment, configuration as code, and the roadmap. |
| [protocol.md](protocol.md) | The wire profile for M1: outer and inner QUIC, CONNECT-UDP and CONNECT-IP with their capsules, the HTTP/2 fallback, the MTU budget, the certificate profile, control channels, the revocation push channel, and named parameters. |
| [threat-model.md](threat-model.md) | Assets, actors, trust boundaries, and threats with mitigations, each tied to a guarantee. |
| [policy.md](policy.md) | The policy schema (connector groups, apps, posture profiles, access rules, just-in-time access) and how it compiles to Cedar, with examples. |
| [dependencies.md](dependencies.md) | The dependency policy, how CI enforces it, and the measured dependency closure. |
| [benchmarks.md](benchmarks.md) | How the data path is benchmarked (setup time, latency, throughput through a relay against TLS over TCP), how to run it, and recorded results. |

Read [design.md](design.md) first; the others refine it. When documents
disagree, the design's guarantees win and the other document is the one to
fix.
