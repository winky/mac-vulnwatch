#!/bin/bash
#
# collectors/runtime.sh
# Languages and tools, however they were installed, checked against endoflife.date.
#
# Read from, whichever the machine has:
#
#   asdf, mise        everything they have installed
#   Homebrew          formulae installed on request, end of life only (see below)
#   python.org        /Library/Frameworks/Python.framework
#   go.dev            /usr/local/go
#   nodejs.org        /usr/local/bin/node, when it is not Homebrew's
#   JDK installers    /Library/Java/JavaVirtualMachines and ~/Library/Java/JavaVirtualMachines,
#                     end of life only
#   rustup            the stable toolchain
#
# Any tool that names an endoflife.date product (or one of its aliases) is checked:
# nodejs, python, ruby, go, terraform, kubectl, postgresql, java and so on. The mapping lives in
# lib/runtime.jq. Two things are reported, per product and release line (nodejs 24, python 3.12):
#
#   - the line has reached end of life, so it no longer gets security fixes   -> kind "eol"
#   - the newest installed version in the line is behind the line's latest    -> kind "update"
#
# Only the newest installed version in each line counts. Old patch versions left behind after
# an upgrade are not what runs, and reporting each of them would make every upgrade look
# unfinished.
#
# A tool installed more than one way is one finding: findings are keyed by product, and the
# newest install in each line decides. Skipped only when none of the above is present.
#
# Homebrew formulae are judged on end of life only. Their vulnerabilities are the brew
# collector's, and a patch release endoflife.date knows about is often not packaged yet, so
# "behind" would suggest a brew upgrade that does nothing.
#
# The interpreters Apple ships (/usr/bin/ruby, perl, python3) are left out on purpose: only
# Apple can update them, and its updates are reported by the macos collector.
#
#   collectors/runtime.sh            scan this machine
#   collectors/runtime.sh --parse    read {"index", "installs", "products"} on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

ENDOFLIFE_API="${ENDOFLIFE_API:-https://endoflife.date/api/v1/products}"

# Prefixed to the system paths the vendor installers use, so that tests can stand up a fake
# /Library and /usr/local. Empty in normal use.
SYSROOT="${MAC_VULNWATCH_SYSROOT:-}"

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
    # End of life is a property of the line, so the newest install shows it. Being behind is
    # judged only among installs whose versions compare: a Homebrew python@3.13 must not hide
    # a python.org 3.13 that is behind.
    | map((max_by(.version | version_key)) as $newest
          | (map(select(.eol_only | not)) | max_by(.version | version_key)) as $comparable
          | if $newest.line.isEol then $newest + {verdict: "eol"}
            elif $comparable != null and ($comparable.line.latest.name // null) != null
                 and ($comparable.version | version_key) < ($comparable.line.latest.name | version_key)
            then $comparable + {verdict: "update"}
            else empty end)
    | [.[]
       | .line as $line
       # What the user typed (kubectl, golang), with the product it was matched to when that
       # differs, so a title says both what is installed and what the dates are about.
       | (if .tool == .product then .tool else "\(.tool) (\(.product))" end) as $name
       | if .verdict == "eol" then {
           id: "runtime/\(.product)@\($line.name)",
           source: "runtime",
           kind: "eol",
           package: "\(.product)@\($line.name)",
           installed: .shown_version,
           available: null,
           severity: "high",
           title: "\($name) \(.shown_version): release line \($line.name) reached end of life\(if $line.eolFrom then " on \($line.eolFrom)" else "" end)",
           remediation: ("Move to a supported release line. This one no longer receives security fixes."
             + (if .hint then " \(.hint)" else "" end)),
           # Moving to another line is usually a decision (it can break things), so there is no
           # command -- except where staying current is the only supported way, as with rustup.
           command: (.eol_command // null),
           url: "https://endoflife.date/\(.product)",
           advisories: []
         }
         else {
           id: "runtime/\(.product)@\($line.name)",
           source: "runtime",
           kind: "update",
           package: "\(.product)@\($line.name)",
           installed: .shown_version,
           available: $line.latest.name,
           severity: "unknown",
           title: "\($name) \(.shown_version): \($line.latest.name) is available in the \($line.name) line",
           remediation: ("Install the latest patch release and switch to it. Patch releases are where security fixes land; see the changelog for what this one contains."
             + (if .hint then " \(.hint)" else "" end)),
           # mise upgrade moves within the requested range and switches to it; asdf only
           # installs, and switching stays with the user (asdf set) since it may be per project.
           command: (if .manager == "mise" then "mise upgrade \(.tool)"
                     elif .manager == "asdf" then "asdf install \(.tool) \($line.latest.name)"
                     else .command end),
           url: ($line.latest.link // "https://endoflife.date/\(.product)"),
           advisories: []
         }
         end]'
}

# Prints [{manager, tool, version}] for everything asdf has installed.
asdf_installs() {
  local plugin version plugins
  # Failing here is a failure, not "nothing installed": an empty list would close every issue.
  plugins="$(asdf plugin list 2> /dev/null)" || {
    log "asdf plugin list failed."
    return 1
  }
  while IFS= read -r plugin; do
    [ -n "${plugin}" ] || continue
    # `asdf list nodejs` prints one version per line, the current one marked with *.
    while IFS= read -r version; do
      version="$(printf '%s' "${version}" | tr -d ' *')"
      [ -n "${version}" ] || continue
      jq -nc --arg tool "${plugin}" --arg version "${version}" '{manager: "asdf", tool: $tool, version: $version}'
    done < <(asdf list "${plugin}" 2> /dev/null || true)
  done <<< "${plugins}"
}

# Prints [{manager, tool, version}] for everything mise has installed, whether or not any
# configuration asks for it -- the scan runs from launchd, outside every project.
mise_installs() {
  local listing
  listing="$(mise ls --installed --json 2> /dev/null)" || {
    log "mise ls failed."
    return 1
  }
  jq -c 'to_entries[] | .key as $tool | .value[] | select(.installed != false)
         | {manager: "mise", tool: $tool, version}' <<< "${listing}"
}

# Prints {manager, tool, version} for every formula installed on request -- what someone chose
# to install, not what came in as a dependency. A dependency on an end-of-life line is
# Homebrew's to move, and the only thing a user could do about it is uninstall whatever needs
# it; its vulnerabilities are still reported by the brew collector.
brew_installs() {
  local listing
  listing="$(brew info --json=v2 --installed 2> /dev/null)" || {
    log "brew info --installed failed."
    return 1
  }
  jq -c '.formulae[] | .name as $formula
         | .installed[] | select(.installed_on_request)
         | {manager: "brew", tool: $formula, version, eol_only: true, command: null,
            hint: "Install a newer versioned formula (brew search \($formula | sub("@.*$"; ""))) and move to it."}' \
    <<< "${listing}"
}

# Prints {manager, tool, version} for languages installed from their vendors' own installers.
# Versions are read from files or from the binaries themselves; nothing here can open a dialog.
direct_installs() {
  local dir version release implementor vendor rustup_home

  for dir in "${SYSROOT}"/Library/Frameworks/Python.framework/Versions/*/; do
    dir="${dir%/}"
    case "$(basename "${dir}")" in Current) continue ;; esac
    [ -x "${dir}/bin/python3" ] || continue
    version="$("${dir}/bin/python3" --version 2>&1 | awk '{print $2}')"
    [ -n "${version}" ] || continue
    jq -nc --arg version "${version}" '{manager: "python.org", tool: "python", version: $version, command: null,
      hint: "Download the installer from https://www.python.org/downloads/macos/."}'
  done

  if [ -f "${SYSROOT}/usr/local/go/VERSION" ]; then
    version="$(head -n 1 "${SYSROOT}/usr/local/go/VERSION" | sed 's/^go//')"
    jq -nc --arg version "${version}" '{manager: "go.dev", tool: "go", version: $version, command: null,
      hint: "Download the installer from https://go.dev/dl/."}'
  fi

  # The nodejs.org installer puts a real binary here. On an Intel Mac, Homebrew lives under
  # /usr/local too, but its node is a symlink into the Cellar, and the brew reader has it.
  if [ -f "${SYSROOT}/usr/local/bin/node" ] && [ ! -L "${SYSROOT}/usr/local/bin/node" ]; then
    version="$("${SYSROOT}/usr/local/bin/node" --version 2> /dev/null || true)"
    [ -n "${version}" ] && jq -nc --arg version "${version}" '{manager: "nodejs.org", tool: "node", version: $version,
      command: null, hint: "Download the installer from https://nodejs.org/."}'
  fi

  # Every JDK writes a release file naming its vendor and version. The vendor becomes the
  # product through the same <vendor>-<version> form asdf-java uses. A symlinked JDK is
  # Homebrew's openjdk linked in by hand, which is the brew collector's.
  for dir in "${SYSROOT}"/Library/Java/JavaVirtualMachines/*.jdk "${HOME}"/Library/Java/JavaVirtualMachines/*.jdk; do
    [ -d "${dir}" ] && [ ! -L "${dir}" ] || continue
    release="${dir}/Contents/Home/release"
    [ -f "${release}" ] || continue
    implementor="$(sed -n 's/^IMPLEMENTOR="\(.*\)"$/\1/p' "${release}")"
    version="$(sed -n 's/^JAVA_VERSION="\(.*\)"$/\1/p' "${release}")"
    # Oracle's JDK and Oracle's OpenJDK builds both say "Oracle Corporation"; they are judged as
    # the JDK, whose support is the longer of the two.
    case "${implementor}" in
      "Eclipse Adoptium") vendor=temurin ;;
      "Amazon.com Inc.") vendor=corretto ;;
      "Azul Systems, Inc.") vendor=zulu ;;
      "Oracle Corporation") vendor=oracle-java ;;
      "Microsoft") vendor=microsoft-build-of-openjdk ;;
      "BellSoft") vendor=liberica ;;
      "SAP SE") vendor=sapmachine ;;
      "IBM Corporation" | "International Business Machines Corporation") vendor=semeru ;;
      "GraalVM Community") vendor=graalvm ;;
      *) continue ;;
    esac
    [ -n "${version}" ] || continue
    jq -nc --arg version "${vendor}-${version}" --arg implementor "${implementor}" \
      '{manager: "jdk", tool: "java", version: $version, command: null,
        hint: "Download a current release from \($implementor)."}'
  done

  # Only the stable channel: a pinned toolchain is pinned on purpose, and Rust's six-week
  # releases would have it reported as end of life within weeks.
  rustup_home="${RUSTUP_HOME:-${HOME}/.rustup}"
  for dir in "${rustup_home}"/toolchains/stable-*; do
    [ -x "${dir}/bin/rustc" ] || continue
    version="$("${dir}/bin/rustc" --version 2> /dev/null | awk '{print $2}')"
    [ -n "${version}" ] && jq -nc --arg version "${version}" '{manager: "rustup", tool: "rust", version: $version,
      command: "rustup update stable", eol_command: "rustup update stable", hint: null}'
  done
  return 0
}

fetch() {
  local work product
  work="$(mktemp -d "${TMPDIR:-/tmp}/mac-vulnwatch.XXXXXX")"
  # shellcheck disable=SC2064 # expand now: work is local and gone by the time EXIT fires
  trap "rm -rf '${work}'" EXIT

  : > "${work}/installs.jsonl"
  if command -v asdf > /dev/null 2>&1; then
    asdf_installs >> "${work}/installs.jsonl" || exit 1
  fi
  if command -v mise > /dev/null 2>&1; then
    mise_installs >> "${work}/installs.jsonl" || exit 1
  fi
  if command -v brew > /dev/null 2>&1; then
    brew_installs >> "${work}/installs.jsonl" || exit 1
  fi
  direct_installs >> "${work}/installs.jsonl"
  jq -s . "${work}/installs.jsonl" > "${work}/installs.json"

  if [ "$(jq length "${work}/installs.json")" -eq 0 ]; then
    log "Nothing installed through asdf, mise, Homebrew or the vendors' installers."
    exit "${EXIT_NOT_APPLICABLE}"
  fi

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
    fetch | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
