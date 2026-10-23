#!/bin/bash
#
# collectors/packages.sh
# Globally installed packages with known vulnerabilities, matched against OSV.dev.
#
# Reads whichever of these the machine has, and skips the rest:
#
#   npm      npm ls -g --all       every package in the global tree
#   pipx     pipx's venvs          every package in each app's venv
#   uv       uv tool dir           every package in each tool's venv
#   pip-user user site-packages    pip install --user
#   go       go version -m         every module compiled into each binary in GOBIN, and the
#                                  Go standard library it was built with
#   cargo    ~/.cargo/.crates2.json  installed crates (cargo keeps no record of their deps)
#
# One finding per installed tool, listing everything vulnerable inside it, because the tool is
# what can be upgraded. Project dependencies are out of scope: GitHub's Dependabot covers those.
#
# npm only sees the Node.js on PATH. With asdf or mise that is the version selected globally;
# packages installed under other versions are not read.
#
#   collectors/packages.sh            scan this machine
#   collectors/packages.sh --parse    read {"inventory", "results", "vulns"} on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

OSV_API="${OSV_API:-https://api.osv.dev/v1}"

parse() {
  jq -L "${ROOT}/lib" -f "${ROOT}/lib/package_findings.jq"
}

# python_site_inventory MANAGER SITE_PACKAGES VIA COMMAND
#
# Reads the METADATA of every distribution in SITE_PACKAGES rather than asking pip: uv's venvs
# have no pip, and running /usr/bin/python3 on a Mac without the Command Line Tools opens an
# installer dialog. An empty VIA makes each package its own tool (pip install --user).
python_site_inventory() {
  local manager="$1" site="$2" via="$3" command="$4" metadata name version
  for metadata in "${site}"/*.dist-info/METADATA; do
    [ -f "${metadata}" ] || continue
    name="$(sed -n 's/^Name: *//p' "${metadata}" | head -n 1 | tr -d '\r')"
    version="$(sed -n 's/^Version: *//p' "${metadata}" | head -n 1 | tr -d '\r')"
    [ -n "${name}" ] && [ -n "${version}" ] || continue
    jq -nc --arg manager "${manager}" --arg via "${via}" --arg command "${command}" \
      --arg name "${name}" --arg version "${version}" '
      # PEP 503: names compare case-insensitively, with runs of - _ . equivalent.
      def normalise: ascii_downcase | gsub("[-_.]+"; "-");
      {manager: $manager,
       via: (if $via == "" then $name else $via end),
       via_version: (if $via == "" or ($via | normalise) == ($name | normalise) then $version else null end),
       command: (if $via == "" then "python3 -m pip install --user --upgrade \($name)" else $command end),
       ecosystem: "PyPI", name: $name, version: $version}'
  done
}

# The venv's own package carries the tool's version; give it to every entry from that venv.
fill_via_version() {
  jq -sc 'group_by([.manager, .via])
          | map((map(select(.via_version != null))[0].via_version // "") as $v
                | map(.via_version = $v))
          | flatten[]'
}

# venvs_inventory MANAGER VENVS_DIR COMMAND_PREFIX
venvs_inventory() {
  local manager="$1" venvs="$2" prefix="$3" venv site
  for venv in "${venvs}"/*/; do
    venv="${venv%/}"
    [ -d "${venv}" ] || continue
    for site in "${venv}"/lib/python*/site-packages; do
      [ -d "${site}" ] || continue
      python_site_inventory "${manager}" "${site}" "$(basename "${venv}")" "${prefix} $(basename "${venv}")"
    done
  done
}

inventory() {
  local found=false listing venvs bin site
  if command -v npm > /dev/null 2>&1; then
    found=true
    # npm ls exits non-zero for problems in the tree (extraneous, missing peer) while still
    # printing it, so the JSON is what decides.
    listing="$(npm ls -g --all --json 2> /dev/null || true)"
    if ! jq -e '.dependencies' <<< "${listing}" > /dev/null 2>&1; then
      log "npm ls -g did not produce a tree."
      return 1
    fi
    jq -c -L "${ROOT}/lib" 'include "packages"; npm_inventory' <<< "${listing}"
  fi

  if command -v pipx > /dev/null 2>&1; then
    found=true
    venvs="$(pipx environment --value PIPX_LOCAL_VENVS 2> /dev/null)" || {
      log "pipx environment failed."
      return 1
    }
    venvs_inventory pipx "${venvs}" "pipx upgrade" | fill_via_version
  fi

  if command -v uv > /dev/null 2>&1; then
    found=true
    venvs="$(uv tool dir 2> /dev/null)" || {
      log "uv tool dir failed."
      return 1
    }
    venvs_inventory uv "${venvs}" "uv tool upgrade" | fill_via_version
  fi

  # pip install --user: the framework layout macOS Pythons use, and the XDG layout others do.
  for site in "${HOME}"/Library/Python/*/lib/python/site-packages "${HOME}"/.local/lib/python*/site-packages; do
    [ -d "${site}" ] || continue
    found=true
    python_site_inventory pip-user "${site}" "" ""
  done

  if command -v go > /dev/null 2>&1; then
    bin="$(go env GOBIN 2> /dev/null)"
    [ -n "${bin}" ] || bin="$(go env GOPATH 2> /dev/null)/bin"
    if [ -d "${bin}" ]; then
      found=true
      # go version -m reports binaries it cannot read on stderr and carries on.
      go version -m "${bin}" 2> /dev/null | jq -Rsc -L "${ROOT}/lib" 'include "packages"; go_inventory'
    fi
  fi

  if [ -f "${CARGO_HOME:-${HOME}/.cargo}/.crates2.json" ]; then
    found=true
    jq -c -L "${ROOT}/lib" 'include "packages"; cargo_inventory' "${CARGO_HOME:-${HOME}/.cargo}/.crates2.json"
  fi

  if [ "${found}" = false ]; then
    log "No npm, pipx, uv, pip --user packages, Go binaries or cargo installs found."
    return "${EXIT_NOT_APPLICABLE}"
  fi
}

fetch() {
  local work status batch id
  work="$(mktemp -d "${TMPDIR:-/tmp}/mac-vulnwatch.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: work is local and gone by the time EXIT fires
  trap "rm -rf '${work}'" EXIT

  set +e
  inventory > "${work}/inventory.jsonl"
  status=$?
  set -e
  [ "${status}" -eq 0 ] || exit "${status}"
  jq -s . "${work}/inventory.jsonl" > "${work}/inventory.json"

  # Each distinct package once, in batches of OSV's limit of 1000 queries per request.
  jq -c '[.[] | {ecosystem, name, version}] | unique | . as $all
         | range(0; length; 1000) as $i | $all[$i:$i + 1000]' "${work}/inventory.json" > "${work}/batches.jsonl"
  echo '[]' > "${work}/results.json"
  while IFS= read -r batch; do
    if ! jq -c '{queries: map({package: {name, ecosystem}, version})}' <<< "${batch}" \
      | curl -fsS --max-time 60 -X POST -H 'Content-Type: application/json' --data-binary @- \
        "${OSV_API}/querybatch" > "${work}/response.json"; then
      log "OSV.dev querybatch failed."
      exit 1
    fi
    # Results come back in query order, each with the ids of the advisories that apply.
    jq --argjson batch "${batch}" --slurpfile response "${work}/response.json" \
      '. + [range(0; $batch | length) as $i
            | $batch[$i] + {ids: [($response[0].results[$i].vulns // [])[].id]}]' \
      "${work}/results.json" > "${work}/results.next"
    mv "${work}/results.next" "${work}/results.json"
  done < "${work}/batches.jsonl"

  # The batch endpoint returns ids only; the records hold the summary, severity and fixes.
  mkdir -p "${work}/vulns"
  jq -r '[.[].ids[]] | unique | .[]' "${work}/results.json" > "${work}/ids.txt"
  while IFS= read -r id; do
    if ! curl -fsS --max-time 30 "${OSV_API}/vulns/${id}" > "${work}/vulns/${id}.json"; then
      log "Could not fetch ${id} from OSV.dev."
      exit 1
    fi
  done < "${work}/ids.txt"

  if [ -s "${work}/ids.txt" ]; then
    jq -s 'map({key: .id, value: .}) | from_entries' "${work}"/vulns/*.json > "${work}/vulns.json"
  else
    echo '{}' > "${work}/vulns.json"
  fi

  jq -n --slurpfile inventory "${work}/inventory.json" --slurpfile results "${work}/results.json" \
    --slurpfile vulns "${work}/vulns.json" \
    '{inventory: $inventory[0], results: $results[0], vulns: $vulns[0]}'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    fetch | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
