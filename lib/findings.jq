# lib/findings.jq
# The shape every collector produces, and everything that renders it.
#
# A finding:
#
#   {
#     "id":          "brew/openssl@3",   # <source>/<package>; stable across versions
#     "source":      "brew",
#     "kind":        "vulnerability" | "update" | "eol",
#     "package":     "openssl@3",
#     "installed":   "3.6.4",
#     "available":   "3.6.5" | null,
#     "severity":    "critical" | "high" | "medium" | "low" | "unknown",
#     "title":       "openssl@3 3.6.4: 13 known vulnerabilities",
#     "remediation": "Upgrade the formula.",       # prose, always present
#     "command":     "brew upgrade openssl@3" | null,  # what to run, when there is one
#     "url":         "https://..." | null,
#     "advisories":  [{"id", "severity", "summary", "fixed": [..], "url"}]
#   }
#
# The id leaves out the version on purpose. An upgrade that still leaves something behind
# updates the same issue instead of closing one and opening another.
#
# Include this from a program (jq -f, or a filter on the command line), never from another
# module. jq 1.8.2 aborts with "Unknown function type" when a module included by a module calls
# one of its own functions, and most functions here do. Only 1.8.2 is affected: it registers
# libraries in the reverse of their dependency order (jqlang/jq#3597, #3636), fixed by
# jqlang/jq#3620 after 1.8.2 was released. Nesting becomes safe once 1.8.2 is no longer in use.

def severity_rank:
  (ascii_downcase) as $s
  | {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1}[$s] // 0;

def severity_name:
  ["unknown", "low", "medium", "high", "critical"][.];

# The highest severity in a list of severity strings.
def max_severity:
  (map(severity_rank) | max // 0) | severity_name;

def plural($n; $one; $many):
  if $n == 1 then "\($n) \($one)" else "\($n) \($many)" end;

# Lowercase, and anything that is not a letter, a digit, @, . or - becomes a single -.
def slug:
  ascii_downcase | gsub("[^a-z0-9@.-]+"; "-") | gsub("^-+|-+$"; "");

# Splits a version into numbers for comparison. Non-numeric parts (rc1, beta) count as 0,
# which errs towards "not behind" -- a pre-release is never reported as outdated by mistake.
def version_key:
  split(".") | map(tonumber? // 0);

# GitHub refuses an issue body over 65536 characters, and a Docker image can carry hundreds
# of advisories. The table stops well before that and says how many it left out.
def advisory_limit: 50;

def advisories_markdown:
  if (.advisories | length) == 0 then ""
  else
    "\n### Advisories\n\n| ID | Severity | Summary | Fixed in |\n|---|---|---|---|\n"
    + ([.advisories[:advisory_limit][]
        | "| [\(.id)](\(.url // "")) | \(.severity // "unknown") | \((.summary // "") | gsub("\\|"; "\\|") | gsub("\n"; " ")) | \((.fixed // []) | map(if test("^[0-9a-f]{40}$") then .[:12] else . end) | join(", ")) |"]
       | join("\n"))
    + (if (.advisories | length) > advisory_limit
       then "\n\n\((.advisories | length) - advisory_limit) more not shown."
       else "" end)
    + "\n"
  end;

def fingerprint($host): "\($host)/\(.id)";

def fingerprint_marker($host): "<!-- mac-vulnwatch:fingerprint=\(fingerprint($host)) -->";

def issue_title($host): "[\($host)] \(.title)";

# The body holds nothing that changes from one scan to the next unless the finding does, so
# comparing bodies is enough to tell whether an issue needs editing.
def issue_body($host):
  fingerprint_marker($host) + "\n"
  + "| | |\n|---|---|\n"
  + "| Host | `\($host)` |\n"
  + "| Source | `\(.source)` |\n"
  + "| Package | `\(.package)` |\n"
  + "| Installed | `\(.installed)` |\n"
  + "| Available | \(if .available then "`\(.available)`" else "-" end) |\n"
  + "| Severity | \(.severity) |\n"
  + "| Kind | \(.kind) |\n"
  + (if .url then "| Reference | \(.url) |\n" else "" end)
  + "\n### Remediation\n\n"
  + "\(.remediation)\n"
  + (if .command then "\n```sh\n\(.command)\n```\n" else "" end)
  + advisories_markdown
  + "\n---\nReported by [mac-vulnwatch](https://github.com/winky/mac-vulnwatch). Closed automatically once a scan no longer finds it.\n";

def issue_labels($host):
  ["mac-vulnwatch", "host:\($host)", "source:\(.source)", "severity:\(.severity)", "kind:\(.kind)"];

# The local report: one Markdown document for the whole scan.
def report_markdown:
  . as $r
  | "# mac-vulnwatch report: \($r.host)\n\n"
    + "Scanned at \($r.scanned_at) by mac-vulnwatch \($r.version).\n\n"
    + "| Source | Status | Findings |\n|---|---|---|\n"
    + ([$r.sources | to_entries[]
        | .key as $source
        | "| \($source) | \(.value.status)\(if .value.error then " (\(.value.error | gsub("\n"; " ") | .[:120]))" else "" end) | \([$r.findings[] | select(.source == $source)] | length) |"]
       | join("\n"))
    + "\n\n"
    + (if ($r.findings | length) == 0 then "Nothing to report.\n"
       else
         "## Findings\n\n| Severity | Source | Finding | Fix |\n|---|---|---|---|\n"
         + ([$r.findings
             | sort_by(-(.severity | severity_rank), .source, .package)[]
             | "| \(.severity) | \(.source) | \(.title) | \(if .command then "`\(.command)`" else .remediation end | gsub("\\|"; "\\|")) |"]
            | join("\n"))
         + "\n"
       end);
