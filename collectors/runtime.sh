#!/bin/bash
#
# collectors/runtime.sh
# Tools installed through asdf, checked against endoflife.date.
#
# Any asdf plugin that names an endoflife.date product (or one of its aliases) is checked:
# nodejs, python, ruby, golang, terraform, kubectl, java and so on. The mapping lives in
# lib/runtime.jq. Two things are reported, per product and release line (nodejs 24, python 3.12):
#
#   - the line has reached end of life, so it no longer gets security fixes   -> kind "eol"
#   - the newest installed version in the line is behind the line's latest    -> kind "update"
#
# Only the newest installed version in each line counts. Old patch versions left behind after
# an upgrade are not what runs, and reporting each of them would make every upgrade look
# unfinished.
#
# Skipped when asdf is not installed. Tools installed by Homebrew are covered by the brew
# collector instead.
#
#   collectors/runtime.sh            scan this machine
#   collectors/runtime.sh --parse    read {"index", "installs", "products"} on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

ENDOFLIFE_API="${ENDOFLIFE_API:-https://endoflife.date/api/v1/products}"

parse() {
  jq -L "${ROOT}/lib" '
    include "findings";
    include "runtime";
    .index as $index
    | .products as $products
    | [.installs[]
       | resolve($index)
       | . as $install
       | ($products[.product] // []) as $releases
       # The release line a version belongs to is the longest release name it starts with:
       # 3.12.4 belongs to "3.12", not "3".
       | ([$releases[] | .name as $name | select($install.version == $name or ($install.version | startswith($name + ".")))]
          | max_by(.name | length)) as $line
       | select($line != null)
       | . + {line: $line}]
    | group_by([.product, .line.name])
    | map(max_by(.version | version_key))
    | [.[]
       | .line as $line
       # What the user typed (kubectl, golang), with the product it was matched to when that
       # differs, so a title says both what is installed and what the dates are about.
       | (if .tool == .product then .tool else "\(.tool) (\(.product))" end) as $name
       | if $line.isEol then {
           id: "runtime/\(.product)@\($line.name)",
           source: "runtime",
           kind: "eol",
           package: "\(.product)@\($line.name)",
           installed: .version,
           available: null,
           severity: "high",
           title: "\($name) \(.version): release line \($line.name) reached end of life\(if $line.eolFrom then " on \($line.eolFrom)" else "" end)",
           remediation: "Move to a supported release line. This one no longer receives security fixes.",
           command: null,
           url: "https://endoflife.date/\(.product)",
           advisories: []
         }
         elif (.eol_only | not) and ($line.latest.name // null) != null
              and (.version | version_key) < ($line.latest.name | version_key) then {
           id: "runtime/\(.product)@\($line.name)",
           source: "runtime",
           kind: "update",
           package: "\(.product)@\($line.name)",
           installed: .version,
           available: $line.latest.name,
           severity: "unknown",
           title: "\($name) \(.version): \($line.latest.name) is available in the \($line.name) line",
           remediation: "Install the latest patch release and switch to it. Patch releases are where security fixes land; see the changelog for what this one contains.",
           command: "asdf install \(.tool) \($line.latest.name)",
           url: ($line.latest.link // "https://endoflife.date/\(.product)"),
           advisories: []
         }
         else empty end]'
}

# Prints [{manager, tool, version}] for everything asdf has installed.
asdf_installs() {
  local plugin version
  while IFS= read -r plugin; do
    [ -n "${plugin}" ] || continue
    # `asdf list nodejs` prints one version per line, the current one marked with *.
    while IFS= read -r version; do
      version="$(printf '%s' "${version}" | tr -d ' *')"
      [ -n "${version}" ] || continue
      jq -nc --arg tool "${plugin}" --arg version "${version}" '{manager: "asdf", tool: $tool, version: $version}'
    done < <(asdf list "${plugin}" 2> /dev/null || true)
  done < <(asdf plugin list 2> /dev/null || true)
}

fetch() {
  local work product
  work="$(mktemp -d "${TMPDIR:-/tmp}/mac-vulnwatch.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: work is local and gone by the time EXIT fires
  trap "rm -rf '${work}'" EXIT

  asdf_installs | jq -s . > "${work}/installs.json"

  if ! curl -fsS --max-time 30 "${ENDOFLIFE_API}" > "${work}/index-response.json"; then
    log "Could not reach endoflife.date."
    exit 1
  fi
  jq '.result' "${work}/index-response.json" > "${work}/index.json"

  # Only the products something is installed for: one request each.
  echo '{}' > "${work}/products.json"
  while IFS= read -r product; do
    if ! curl -fsS --max-time 30 "${ENDOFLIFE_API}/${product}" > "${work}/product.json"; then
      log "Could not reach endoflife.date for ${product}."
      exit 1
    fi
    jq --arg product "${product}" --slurpfile body "${work}/product.json" \
      '. + {($product): $body[0].result.releases}' "${work}/products.json" > "${work}/products.next"
    mv "${work}/products.next" "${work}/products.json"
  done < <(jq -r -L "${ROOT}/lib" --slurpfile index "${work}/index.json" \
    'include "runtime"; [.[] | resolve($index[0]) | .product] | unique | .[]' "${work}/installs.json")

  jq -n --slurpfile index "${work}/index.json" --slurpfile installs "${work}/installs.json" \
    --slurpfile products "${work}/products.json" \
    '{index: $index[0], installs: $installs[0], products: $products[0]}'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    if ! command -v asdf > /dev/null 2>&1; then
      log "asdf is not installed."
      exit "${EXIT_NOT_APPLICABLE}"
    fi
    fetch | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
