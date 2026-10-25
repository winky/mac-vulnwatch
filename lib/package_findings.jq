# lib/package_findings.jq
# {inventory, results: [{ecosystem, name, version, ids}], vulns: {id: <OSV record>}}
#   -> {findings, inventory}, the inventory being every installed tool and its version
#
# A program rather than a module function, so that it can include both lib/findings.jq and
# lib/packages.jq without nesting one inside the other (see the note in lib/findings.jq).
#
# A finding is one tool with everything vulnerable inside it: what the user can act on is
# `npm install -g corepack@latest`, not the transitive semver it happens to carry.

include "findings";
include "packages";

. as $in
| {
  findings: ($in
    .vulns as $vulns
    | (.results | map({key: "\(.ecosystem)\u0000\(.name)\u0000\(.version)", value: .ids}) | from_entries) as $ids
    | [.inventory[]
       | . as $pkg
       | ($ids["\(.ecosystem)\u0000\(.name)\u0000\(.version)"] // []) as $found
       | select($found | length > 0)
       | $found[]
       | $vulns[.] as $v
       | select($v != null)
       | {pkg: $pkg, advisory: {
           id: $v.id,
           severity: ($v | osv_severity),
           summary: "\($pkg.name) \($pkg.version): \($v.summary // ($v.details // "" | .[:120]))",
           fixed: ($v | osv_fixed($pkg.ecosystem; $pkg.name)),
           url: "https://osv.dev/vulnerability/\($v.id)"
         }}]
    | group_by([.pkg.manager, .pkg.via])
    | map(
        .[0].pkg as $tool
        | (map(.advisory) | unique_by([.id, .summary]) | sort_by(-(.severity | severity_rank), .id)) as $advisories
        | ([.[].pkg | "\(.name) \(.version)"] | unique) as $packages
        | {
            id: "packages/\($tool.manager)/\($tool.via)",
            source: "packages",
            kind: "vulnerability",
            package: $tool.via,
            installed: $tool.via_version,
            available: null,
            severity: ([$advisories[].severity] | max_severity),
            title: "\($tool.via) (\($tool.manager)): \(plural($advisories | length; "known vulnerability"; "known vulnerabilities")) in \($packages | if length == 1 then .[0] else "\(length) packages" end)",
            remediation: (if $tool.command
              then "Upgrade \($tool.via). If the newest release still carries the vulnerable \(if ($packages | length) == 1 then "package" else "packages" end), the fix has to come from its maintainers."
              else "Rebuild \($tool.via) with current dependencies and toolchain." end),
            command: $tool.command,
            url: null,
            advisories: $advisories
          })
  ),
  # Every tool read, vulnerable or not: finding id -> installed versions.
  inventory: ($in.inventory
    | map({key: "packages/\(.manager)/\(.via)", value: .via_version})
    | group_by(.key)
    | map({key: .[0].key, value: (map(.value) | unique)})
    | from_entries)
}
