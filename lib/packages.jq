# lib/packages.jq
# Inventories of globally installed packages, and the findings made from them.
#
# An inventory entry is one installed package, with the tool it belongs to:
#
#   {
#     "manager":     "npm",              # npm | pipx | uv | pip-user | go | cargo
#     "via":         "corepack",         # the tool the user installed; the unit of a finding
#     "via_version": "0.34.0",
#     "command":     "npm install -g corepack@latest" | null,
#     "ecosystem":   "npm",              # as OSV names it: npm, PyPI, Go, crates.io
#     "name":        "semver",
#     "version":     "7.5.1"
#   }
#
# Findings are made from these by lib/package_findings.jq. This module includes nothing, so
# that a program can include it alongside lib/findings.jq (see the note there on nesting).

# `npm ls -g --all --json` -> inventory. Every package in the tree, each attributed to the
# top-level package it was installed under.
def npm_inventory:
  def walk_deps:
    (.dependencies // {}) | to_entries[]
    | select(.value.version != null)
    | {name: .key, version: .value.version}, (.value | walk_deps);
  (.dependencies // {}) | to_entries[]
  | select(.value.version != null)
  | .key as $top
  | .value.version as $top_version
  | ({name: .key, version: .value.version}, (.value | walk_deps))
  | {manager: "npm", via: $top, via_version: $top_version,
     command: "npm install -g \($top)@latest", ecosystem: "npm"} + .;

# `go version -m <binaries>` -> inventory. The output, per binary:
#
#   /Users/me/go/bin/gopls: go1.22.1
#   	path	golang.org/x/tools/gopls
#   	mod	golang.org/x/tools/gopls	v0.15.2	h1:...
#   	dep	golang.org/x/mod	v0.16.0	h1:...
#   	=>	example.com/fork	v0.1.0	h1:...      (replacement of the line above)
#   	build	-compiler=gc
#
# The Go standard library the binary was built with is a package too ("stdlib" in OSV), and
# often the one with the advisories.
def go_inventory:
  split("\n")
  | reduce .[] as $line ({binaries: [], current: null};
      if ($line | test("^\\S.*: go[0-9]")) then
        ($line | capture("^(?<file>.*): go(?<go>[0-9][^ ]*)")) as $head
        | .binaries += (if .current then [.current] else [] end)
        | .current = {binary: ($head.file | split("/") | last), go: $head.go, path: null, mod_version: null, deps: []}
      elif .current == null then .
      else
        ($line | ltrimstr("\t") | split("\t")) as $f
        | if $f[0] == "path" then .current.path = $f[1]
          elif $f[0] == "mod" then .current.mod_version = $f[2] | .current.deps += [{name: $f[1], version: $f[2]}]
          elif $f[0] == "dep" then .current.deps += [{name: $f[1], version: $f[2]}]
          elif $f[0] == "=>" then .current.deps[-1] = {name: $f[1], version: $f[2]}
          else . end
      end)
  | (.binaries + (if .current then [.current] else [] end))[]
  | . as $bin
  | ([{name: "stdlib", version: $bin.go}] + [$bin.deps[] | select(.version != "(devel)" and .version != null)])[]
  | {manager: "go", via: $bin.binary, via_version: ($bin.mod_version // "go\($bin.go)"),
     # A binary built locally (go build, or a module at "(devel)") cannot be reinstalled from
     # anywhere; only its owner can rebuild it.
     command: (if $bin.path and $bin.path != "command-line-arguments" and ($bin.mod_version // "(devel)") != "(devel)"
               then "go install \($bin.path)@latest" else null end),
     ecosystem: "Go", name, version: (.version | ltrimstr("v"))};

# ~/.cargo/.crates2.json -> inventory. Only what was installed: cargo keeps no record of the
# dependencies compiled into each binary.
def cargo_inventory:
  (.installs // {}) | keys[]
  | capture("^(?<name>\\S+) (?<version>\\S+) ")
  | {manager: "cargo", via: .name, via_version: .version, command: "cargo install \(.name)",
     ecosystem: "crates.io", name, version};

# OSV's database_specific.severity where it has one (GitHub advisories do: LOW, MODERATE, HIGH,
# CRITICAL). The Go database carries none, so those stay unknown rather than guessed.
def osv_severity:
  (.database_specific.severity // "unknown") | ascii_downcase
  | if . == "moderate" then "medium" else . end;

def osv_fixed($ecosystem; $name):
  [(.affected // [])[]
   | select(.package.ecosystem == $ecosystem and .package.name == $name)
   | (.ranges // [])[] | .events[] | .fixed // empty]
  | unique;
