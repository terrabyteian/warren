#!/usr/bin/env bash
# Writes an SPDX 2.3 JSON SBOM of a binary's third-party crates to stdout,
# from its closure baseline in deps/closure/, which scripts/check-closure.sh
# keeps equal to what cargo compiles into that binary across the release
# targets. The release attests it to each image the binary ships in.
#
# Usage: scripts/closure-sbom.sh CLOSURE_FILE NAME VERSION
set -euo pipefail

if [ $# -ne 3 ]; then
  echo "usage: $0 CLOSURE_FILE NAME VERSION" >&2
  exit 2
fi
closure=$1
name=$2
version=$3

crates=$(awk '
  /^#/ || !NF { next }
  NF != 2 || $2 !~ /^v[0-9]/ { print "error: " FILENAME ":" NR ": not \"crate vVERSION\": " $0 > "/dev/stderr"; bad = 1; next }
  { print $1 " " substr($2, 2) }
  END { exit bad }' "$closure")

printf '%s\n' "$crates" | jq -R -s \
  --arg name "$name" --arg version "$version" \
  --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
  [split("\n")[] | select(length > 0) | split(" ") | {name: .[0], version: .[1]}
   | . + {id: ("SPDXRef-crate-\(.name)-\(.version)" | gsub("[^A-Za-z0-9.-]"; "-"))}] as $crates
  | {
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: "\($name)-\($version)-crates",
      documentNamespace: "https://github.com/terrabyteian/warren/sbom/\($name)-\($version)",
      creationInfo: {created: $created, creators: ["Tool: warren scripts/closure-sbom.sh"]},
      packages: [$crates[] | {
        name, SPDXID: .id, versionInfo: .version,
        downloadLocation: "https://crates.io/api/v1/crates/\(.name)/\(.version)/download",
        filesAnalyzed: false,
        externalRefs: [{referenceCategory: "PACKAGE-MANAGER", referenceType: "purl",
                        referenceLocator: "pkg:cargo/\(.name)@\(.version)"}]
      }],
      relationships: [$crates[] | {spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: .id}]
    }'
