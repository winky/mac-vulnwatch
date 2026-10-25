#!/bin/bash
#
# collectors/mas.sh
# Mac App Store apps with an update waiting, from `mas outdated`.
#
# As with casks, the App Store says nothing about what an update fixes, so these are reported
# as updates rather than vulnerabilities.
#
#   collectors/mas.sh            scan this machine
#   collectors/mas.sh --parse    read `mas outdated` output on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

# One line per app:
#
#   408981434  iMovie  (10.4.4 -> 10.4.5)
#
# The name can contain spaces and parentheses of its own, so the version pair is matched from
# the end of the line.
parse() {
  jq -R -s -L "${ROOT}/lib" '
    include "findings";
    [split("\n")[]
     | capture("^\\s*(?<app_id>[0-9]+)\\s+(?<name>.+?)\\s+\\((?<installed>[^()]+?)\\s+->\\s+(?<available>[^()]+?)\\)\\s*$")?
     | {
         id: "mas/\(.app_id)",
         source: "mas",
         kind: "update",
         package: .name,
         installed,
         available,
         severity: "unknown",
         title: "\(.name) \(.installed): \(.available) is available",
         remediation: "Update the app from the App Store. The App Store does not say whether this update contains security fixes.",
         command: "mas upgrade \(.app_id)",
         url: "https://apps.apple.com/app/id\(.app_id)",
         advisories: []
       }]'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    command -v mas > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    mas outdated | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
