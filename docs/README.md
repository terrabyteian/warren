# warren documentation

| Document | What it covers |
| --- | --- |
| [design.md](design.md) | What warren promises and why: goals, non-goals and the leave-out list, the guarantees (G1 to G19), architecture and trust boundaries, client experience, identity, devices and policy, Kubernetes, revocation and failure behavior, deployment, configuration as code, and the roadmap. |
| [protocol.md](protocol.md) | The wire profile for M1: outer and inner QUIC, CONNECT-UDP and CONNECT-IP with their capsules, the HTTP/2 fallback, the MTU budget, the certificate profile, control channels, the revocation push channel, and named parameters. |
| [threat-model.md](threat-model.md) | Assets, actors, trust boundaries, and threats with mitigations, each tied to a guarantee. |
| [policy.md](policy.md) | The policy schema (connector groups, apps, posture profiles, access rules, just-in-time access) and how it compiles to Cedar, with examples. |
| [macos.md](macos.md) | The macOS client: installing it, signing in, `sudo warren up`, the device key in the Secure Enclave and its software fallback, what M1 leaves out, the menu-bar app and system extension, and how it is tested. |
| [console.md](console.md) | The web console: setting it up, who sees what, the changes it makes, how sign-in, sessions and forms are protected, and its routes. |
| [operating.md](operating.md) | Running the control plane: TLS certificates for the organization URL and for relays and connectors, and the HTTPS listener's connection limits. |
| [dependencies.md](dependencies.md) | The dependency policy, how CI enforces it, and the measured dependency closure. |
| [benchmarks.md](benchmarks.md) | How the data path is benchmarked (setup time, latency, throughput through a relay against TLS over TCP), how to run it, and recorded results. |
| [api/openapi.yaml](api/openapi.yaml) | The control-plane API: client sign-in, enrollment, certificates and entitlements; node joining, bundles, events and audit; the admin API. |
| [examples/](examples) | An example control-plane configuration and the policy examples from policy.md, both kept valid by tests. |

Read [design.md](design.md) first; the others refine it. When documents
disagree, the design's guarantees win and the other document is the one to
fix.
