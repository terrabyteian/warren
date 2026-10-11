# Security policy

warren is security software, and we take reports seriously, including reports
about the design itself.

## Supported versions

warren is in early development and has no releases yet. Until v1.0, fixes land
on `main`. Once releases exist, this section will list the versions that
receive security fixes.

## Reporting a vulnerability

Please do not open a public issue, discussion or pull request for a
vulnerability.

Report it privately through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**. Include:

- what is affected (component, version or commit, configuration);
- how to reproduce it, or the design reasoning for a design flaw;
- the impact you expect, and any guarantee in
  [docs/design.md](docs/design.md#4-guarantees) it breaks.

We aim to acknowledge reports within a week, keep you informed while we
investigate, and agree on a disclosure date with you. We credit reporters who
want to be credited.

## Scope

In scope: everything in this repository, including the design documents,
protocol profile, threat model, build and dependency pipeline, and CI
configuration. [docs/threat-model.md](docs/threat-model.md) describes what
warren defends against and the risks it accepts.

Out of scope: vulnerabilities in third-party dependencies that do not affect
warren (please report those upstream), and denial of service by sheer volume.
