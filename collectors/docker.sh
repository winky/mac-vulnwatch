#!/bin/bash
#
# collectors/docker.sh
# Local Docker images with HIGH or CRITICAL vulnerabilities, from trivy.
#
# Off by default (add docker to COLLECTORS): the first run downloads trivy's database, and
# scanning every image takes minutes. Needs trivy installed and the Docker daemon running;
# without either it is skipped rather than failed, since a stopped Docker Desktop is normal.
#
# Set DOCKER_SEVERITY to change what is reported, e.g. MEDIUM,HIGH,CRITICAL.
#
#   collectors/docker.sh            scan this machine
#   collectors/docker.sh --parse    read [{"image": ..., "report": <trivy JSON>}] on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

parse() {
  jq -L "${ROOT}/lib" '
    include "findings";
    [.[]
     | .image as $image
     | [(.report.Results // [])[] | (.Vulnerabilities // [])[]]
     | unique_by(.VulnerabilityID)
     | select(length > 0)
     | . as $vulns
     | ([$vulns[] | select((.FixedVersion // "") != "")] | length) as $fixable
     | {
         id: "docker/\($image)",
         source: "docker",
         kind: "vulnerability",
         package: $image,
         installed: $image,
         available: null,
         severity: ([$vulns[].Severity] | max_severity),
         title: "\($image): \(plural($vulns | length; "vulnerability"; "vulnerabilities"))",
         remediation: (if $fixable > 0
           then "Pull or rebuild the image on a newer base. \($fixable) of these have a fixed version upstream."
           else "None of these has a fixed version upstream yet. Remove the image if nothing uses it."
           end),
         command: "docker pull \($image)",
         url: null,
         advisories: [$vulns
           | sort_by(-(.Severity | severity_rank))[]
           | {
               id: .VulnerabilityID,
               severity: (.Severity | ascii_downcase),
               summary: "\(.PkgName) \(.InstalledVersion): \(.Title // "")",
               fixed: (if (.FixedVersion // "") == "" then [] else [.FixedVersion] end),
               url: (.PrimaryURL // "https://avd.aquasec.com/nvd/\(.VulnerabilityID | ascii_downcase)")
             }]
       }]'
}

fetch() {
  local severity image report results
  severity="$(config_get DOCKER_SEVERITY HIGH,CRITICAL)"
  results="[]"
  while IFS= read -r image; do
    case "${image}" in
      '' | *'<none>'*) continue ;;
    esac
    if ! report="$(trivy image --quiet --format json --scanners vuln --severity "${severity}" "${image}" 2>&1)"; then
      log "trivy could not scan ${image}: ${report##*$'\n'}"
      exit 1
    fi
    results="$(jq -c --arg image "${image}" --argjson report "${report}" \
      '. + [{image: $image, report: $report}]' <<< "${results}")"
  done < <(docker image ls --format '{{.Repository}}:{{.Tag}}' | sort -u)
  printf '%s\n' "${results}"
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    command -v docker > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    if ! command -v trivy > /dev/null 2>&1; then
      log "trivy is not installed (brew install trivy)."
      exit "${EXIT_NOT_APPLICABLE}"
    fi
    docker info > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    fetch | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
