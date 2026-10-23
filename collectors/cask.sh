#!/bin/bash
#
# collectors/cask.sh
# Homebrew casks with a newer version available.
#
# Unlike formulae, casks have no vulnerability database to match against, so an available
# update is all there is to go on. That is still worth reporting: casks are browsers, chat
# clients and other apps that read untrusted input all day, and their updates are where their
# security fixes ship.
#
# Casks that update themselves (auto_updates, or version :latest) are left out by default,
# as `brew outdated` does. Set CASK_GREEDY=true to include them.
#
#   collectors/cask.sh            scan this machine
#   collectors/cask.sh --parse    read `brew outdated --cask --json=v2` on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

parse() {
  jq -L "${ROOT}/lib" '
    include "findings";
    [(.casks // [])[]
     | {
         id: "cask/\(.name)",
         source: "cask",
         kind: "update",
         package: .name,
         installed: (.installed_versions | join(", ")),
         available: .current_version,
         severity: "unknown",
         title: "\(.name) \(.installed_versions | join(", ")): \(.current_version) is available",
         remediation: "Update the app. Homebrew does not say whether this update contains security fixes.",
         command: "brew upgrade --cask \(.name)",
         url: "https://formulae.brew.sh/cask/\(.name)",
         advisories: []
       }]'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    command -v brew > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    greedy=()
    if config_true CASK_GREEDY false; then
      greedy=(--greedy)
    fi
    # ${greedy[@]+...} because bash 3.2 treats expanding an empty array as unbound under set -u.
    brew outdated --cask --json=v2 ${greedy[@]+"${greedy[@]}"} | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
