#!/bin/bash
#
# collectors/macos.sh
# Apple software updates the machine has not installed: macOS itself, Safari, Command Line
# Tools, and the security responses Apple ships between releases.
#
# Each update is keyed by its name with the version taken off, so "macOS Tahoe 26.1" and
# "macOS Tahoe 26.2" are the same finding. When 26.2 supersedes an uninstalled 26.1 the issue
# is updated rather than closed -- closing it would read as "fixed".
#
#   collectors/macos.sh            scan this machine
#   collectors/macos.sh --parse    read `softwareupdate --list` output on stdin instead
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/common.sh
. "${ROOT}/lib/common.sh"

# softwareupdate prints two lines per update:
#
#   * Label: macOS Tahoe 26.1-25B78
#   	Title: macOS Tahoe 26.1, Version: 26.1, Size: 7381234KiB, Recommended: YES, Action: restart,
parse() {
  jq -R -s -L "${ROOT}/lib" '
    include "findings";
    split("\n") as $lines
    | [range(0; $lines | length) as $i
       | ($lines[$i] | capture("^\\* Label: (?<label>.+?)\\s*$")?) as $head
       | ($lines[$i + 1] // "") as $detail
       | ($detail | capture("Title: (?<title>.+?), Version: (?<version>[^,]*)")? // {title: $head.label, version: ""}) as $info
       | ($info.title | sub("\\s+[0-9][0-9.]*(\\s*\\([a-z]\\))?$"; "")) as $name
       | ($detail | test("Recommended: YES")) as $recommended
       | ($detail | test("Action: restart")) as $restart
       | {
           id: "macos/\($name | slug)",
           source: "macos",
           kind: "update",
           package: $name,
           installed: "-",
           available: (if $info.version == "" then $head.label else $info.version end),
           severity: "unknown",
           title: "\($info.title) is not installed",
           remediation: ("Install it from System Settings > General > Software Update"
             + (if $restart then " (restarts the Mac)" else "" end)
             + (if $recommended then ". Apple marks it as recommended." else "." end)),
           command: "softwareupdate --install \($head.label | @sh)",
           url: "https://support.apple.com/en-us/100100",
           advisories: []
         }]'
}

case "${1:-}" in
  --parse)
    parse
    ;;
  "")
    command -v softwareupdate > /dev/null 2>&1 || exit "${EXIT_NOT_APPLICABLE}"
    # "No new software available." goes to stderr; the list goes to stdout.
    softwareupdate --list 2> /dev/null | parse
    ;;
  *)
    echo "usage: $(basename "$0") [--parse]" >&2
    exit 2
    ;;
esac
