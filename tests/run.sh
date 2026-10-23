#!/bin/bash
#
# tests/run.sh
# Runs every parser and the sync planner against the fixtures, and compares the output with
# the expected snapshots. Needs nothing but bash and jq: no Homebrew, no network, no GitHub.
#
#   tests/run.sh            check
#   UPDATE=1 tests/run.sh   rewrite the snapshots from the current output (then review the diff)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="${ROOT}/tests/fixtures"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/mac-vulnwatch.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

passed=0
failed=0

# check NAME ACTUAL_FILE
check() {
  local name="$1" actual="$2" expected="${FIXTURES}/$1.expected.json"
  jq -S . "${actual}" > "${WORK}/actual.json"
  if [ "${UPDATE:-}" = 1 ]; then
    cp "${WORK}/actual.json" "${expected}"
    echo "updated ${name}"
    return
  fi
  if [ ! -f "${expected}" ]; then
    echo "FAIL ${name}: no snapshot (run with UPDATE=1)"
    failed=$((failed + 1))
  elif diff -u "${expected}" "${WORK}/actual.json" > "${WORK}/diff"; then
    echo "ok   ${name}"
    passed=$((passed + 1))
  else
    echo "FAIL ${name}"
    cat "${WORK}/diff"
    failed=$((failed + 1))
  fi
}

# Every collector parser, against every fixture named after it.
for input in "${FIXTURES}"/*.input.*; do
  name="$(basename "${input}")"
  name="${name%%.input.*}"
  collector="${name%%-*}"
  [ -f "${ROOT}/collectors/${collector}.sh" ] || continue
  bash "${ROOT}/collectors/${collector}.sh" --parse < "${input}" > "${WORK}/${name}.json"
  check "${name}" "${WORK}/${name}.json"
done

# The inventory functions in lib/packages.jq, against inventory-<kind>.input.*: a .txt fixture
# is raw text (go version -m), anything else JSON.
for input in "${FIXTURES}"/inventory-*.input.*; do
  name="$(basename "${input}")"
  name="${name%%.input.*}"
  kind="${name#inventory-}"
  case "${input}" in
    *.txt) raw=(-R -s) ;;
    *) raw=() ;;
  esac
  jq ${raw[@]+"${raw[@]}"} -L "${ROOT}/lib" "include \"packages\"; [${kind}_inventory]" "${input}" > "${WORK}/${name}.json"
  check "${name}" "${WORK}/${name}.json"
done

# The sync planner.
jq -L "${ROOT}/lib" -f "${ROOT}/lib/sync.jq" "${FIXTURES}/sync.input.json" > "${WORK}/sync.json"
check sync "${WORK}/sync.json"

# Applying a plan and planning again must produce nothing: otherwise every daily run would edit
# every issue. Build the issues a create would have made, and plan against them.
jq -L "${ROOT}/lib" '
  include "findings";
  .host as $host
  | .issues = [.report.findings[] | {number: 0, title: issue_title($host), body: issue_body($host),
                                    labels: (issue_labels($host) | map({name: .}))}]' \
  "${FIXTURES}/sync.input.json" > "${WORK}/settled.json"
if [ "$(jq -L "${ROOT}/lib" -f "${ROOT}/lib/sync.jq" "${WORK}/settled.json" | jq length)" = 0 ]; then
  echo "ok   sync is idempotent"
  passed=$((passed + 1))
else
  echo "FAIL sync is idempotent: a settled state still produced actions"
  failed=$((failed + 1))
fi

# The Markdown report renders, and escapes a | inside a summary.
jq -n --slurpfile findings <(bash "${ROOT}/collectors/brew.sh" --parse < "${FIXTURES}/brew.input.json") '
  {host: "test-mac", scanned_at: "2099-01-01T00:00:00Z", version: "0.0.0",
   sources: {brew: {status: "ok"}, mas: {status: "skipped", error: "mas is not installed"}},
   findings: $findings[0]}' > "${WORK}/report.json"
jq -r -L "${ROOT}/lib" 'include "findings"; report_markdown' "${WORK}/report.json" > "${WORK}/report.md"
jq -Rs '{markdown: .}' "${WORK}/report.md" > "${WORK}/report-md.json"
check report "${WORK}/report-md.json"

[ "${UPDATE:-}" = 1 ] && exit 0
echo
echo "${passed} passed, ${failed} failed"
[ "${failed}" -eq 0 ]
