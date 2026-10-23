#!/bin/bash
#
# collectors/runtime.sh
# Language runtimes installed through asdf, checked against endoflife.date.
#
# Two things are reported, per runtime and release line (nodejs 24, python 3.12):
#
#   - the line has reached end of life, so it no longer gets security fixes   -> kind "eol"
#   - the newest installed version in the line is behind the line's latest    -> kind "update"
#
# Only the newest installed version in each line counts. Old patch versions left behind after
# an upgrade are not what runs, and reporting each of them would make every upgrade look
# unfinished.
#
# Runtimes installed by Homebrew are covered by the brew collector instead.
#
#   collectors/runtime.sh            scan this machine
#   collectors/runtime.sh --parse    read {"installs": [...], "products": {...}} on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

ENDOFLIFE_API="${ENDOFLIFE_API:-https://endoflife.date/api/v1/products}"

# asdf plugin name -> endoflife.date product. A plugin not listed here is not checked.
product_for() {
  case "$1" in
    nodejs) echo nodejs ;;
    python) echo python ;;
    ruby) echo ruby ;;
    golang | go) echo go ;;
    php) echo php ;;
    java) echo "" ;; # Several vendors share the plugin, and their release lines differ.
    *) echo "" ;;
  esac
}

parse() {
  jq -L "${ROOT}/lib" '
    include "findings";
    .products as $products
    | [.installs[]
       | . as $install
       | ($products[.product] // []) as $releases
       # The release line a version belongs to is the longest release name it starts with:
       # 3.12.4 belongs to "3.12", not "3".
       | ([$releases[] | .name as $name | select($install.version == $name or ($install.version | startswith($name + ".")))]
          | max_by(.name | length)) as $line
       | select($line != null)
       | . + {line: $line}]
    | group_by([.tool, .line.name])
    | map(max_by(.version | version_key))
    | [.[]
       | .line as $line
       | if $line.isEol then {
           id: "runtime/\(.tool)@\($line.name)",
           source: "runtime",
           kind: "eol",
           package: "\(.tool)@\($line.name)",
           installed: .version,
           available: null,
           severity: "high",
           title: "\(.tool) \(.version): release line \($line.name) reached end of life\(if $line.eolFrom then " on \($line.eolFrom)" else "" end)",
           remediation: "Move to a supported release line. This one no longer receives security fixes.",
           command: null,
           url: "https://endoflife.date/\(.product)",
           advisories: []
         }
         elif ($line.latest.name // null) != null and (.version | version_key) < ($line.latest.name | version_key) then {
           id: "runtime/\(.tool)@\($line.name)",
           source: "runtime",
           kind: "update",
           package: "\(.tool)@\($line.name)",
           installed: .version,
           available: $line.latest.name,
           severity: "unknown",
           title: "\(.tool) \(.version): \($line.latest.name) is available in the \($line.name) line",
           remediation: "Install the latest patch release and switch to it. Patch releases are where security fixes land; see the changelog for what this one contains.",
           command: "asdf install \(.tool) \($line.latest.name)",
           url: ($line.latest.link // "https://endoflife.date/\(.product)"),
           advisories: []
         }
         else empty end]'
}

fetch() {
  local plugin product version installs products releases
  installs="[]"
  products="{}"
  while IFS= read -r plugin; do
    [ -n "${plugin}" ] || continue
    product="$(product_for "${plugin}")"
    [ -n "${product}" ] || continue

    # `asdf list nodejs` prints one version per line, the current one marked with *.
    while IFS= read -r version; do
      version="$(printf '%s' "${version}" | tr -d ' *')"
      [ -n "${version}" ] || continue
      installs="$(jq -c --arg tool "${plugin}" --arg product "${product}" --arg version "${version}" \
        '. + [{tool: $tool, product: $product, version: $version}]' <<< "${installs}")"
    done < <(asdf list "${plugin}" 2> /dev/null || true)

    if [ "$(jq --arg product "${product}" 'has($product)' <<< "${products}")" = false ]; then
      if ! releases="$(curl -fsS --max-time 30 "${ENDOFLIFE_API}/${product}")"; then
        log "Could not reach endoflife.date for ${product}."
        exit 1
      fi
      products="$(jq -c --arg product "${product}" --argjson body "${releases}" \
        '. + {($product): $body.result.releases}' <<< "${products}")"
    fi
  done < <(asdf plugin list 2> /dev/null || true)

  jq -n --argjson installs "${installs}" --argjson products "${products}" \
    '{installs: $installs, products: $products}'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    command -v asdf > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    fetch | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
