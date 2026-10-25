#!/bin/bash
#
# collectors/brew.sh
# Homebrew formulae with known vulnerabilities, from `brew vulns` (OSV.dev).
#
# `brew outdated` is read alongside it only to say whether an upgrade exists. A formula that is
# merely outdated is not reported: most upgrades are not security fixes, and reporting all of
# them would bury the ones that are.
#
#   collectors/brew.sh            scan this machine
#   collectors/brew.sh --parse    read {"vulns": ..., "outdated": ...} on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

parse() {
  jq -L "${ROOT}/lib" '
    include "findings";
    ((.outdated.formulae // []) | map({key: .name, value: .current_version}) | from_entries) as $available
    | [.vulns.findings[]
       | (.vulnerabilities | length) as $count
       | $available[.formula] as $newer
       | {
           id: "brew/\(.formula)",
           source: "brew",
           kind: "vulnerability",
           package: .formula,
           installed: .version,
           available: $newer,
           severity: ([.vulnerabilities[].severity] | max_severity),
           title: "\(.formula) \(.version): \(plural($count; "known vulnerability"; "known vulnerabilities"))",
           remediation: (if $newer
             then "Upgrade to \($newer). A newer release does not always carry the fix, so check the advisories."
             else "No newer version in Homebrew yet. Follow the advisories, or uninstall the formula if nothing needs it."
             end),
           command: (if $newer then "brew upgrade \(.formula)" else null end),
           url: .repo_url,
           advisories: [.vulnerabilities[] | {
             id,
             severity: ((.severity // "unknown") | ascii_downcase),
             summary,
             fixed: (.fixed_versions // []),
             url: "https://osv.dev/vulnerability/\(.id)"
           }]
         }]'
}

fetch() {
  local work
  work="$(mktemp -d "${TMPDIR:-/tmp}/mac-vulnwatch.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: work is local and gone by the time EXIT fires
  trap "rm -rf '${work}'" EXIT

  # brew vulns exits 1 when it finds something, so the exit status cannot tell a finding from a
  # failure. Valid JSON with a findings array is what says it worked.
  brew vulns --json > "${work}/vulns.json" 2> "${work}/vulns.err" || true
  if ! jq -e '.findings | type == "array"' "${work}/vulns.json" > /dev/null 2>&1; then
    log "brew vulns did not produce a report: $(tail -n 3 "${work}/vulns.err")"
    exit 1
  fi

  if ! brew outdated --formula --json=v2 > "${work}/outdated.json" 2> "${work}/outdated.err"; then
    log "brew outdated failed: $(tail -n 3 "${work}/outdated.err")"
    exit 1
  fi

  jq -n --slurpfile vulns "${work}/vulns.json" --slurpfile outdated "${work}/outdated.json" \
    '{vulns: $vulns[0], outdated: $outdated[0]}'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    command -v brew > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    # Older Homebrew has no vulns command. Skipping says "upgrade Homebrew" more quietly than
    # failing every day would.
    if ! brew vulns --help > /dev/null 2>&1; then
      log "This Homebrew has no \`brew vulns\`; run \`brew update\` to get it."
      exit "${EXIT_NOT_APPLICABLE}"
    fi
    fetch | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
