# lib/sync.jq
# Decides what to do to GitHub issues, given a scan and the issues already open.
#
# Input:
#   {
#     "host":   "mac-mini",
#     "report": {"scanned_at": ..., "sources": {"brew": {"status": "ok"}, ...}, "findings": [...]},
#     "issues": [{"number": 1, "title": ..., "body": ..., "labels": [{"name": ...}]}]
#   }
#
# Output: a list of actions, each one of
#   {"op": "create", "title", "body", "labels"}
#   {"op": "update", "number", "title", "body", "add_labels", "remove_labels"}
#   {"op": "close",  "number", "comment"}
#
# Pure, so that it can be tested without GitHub. lib/sync.sh carries the actions out.

include "findings";

def issue_fingerprint:
  (.body // "") | capture("<!-- mac-vulnwatch:fingerprint=(?<fp>[^ ]+) -->")?.fp;

# host/source/package -> source. The package part may itself contain slashes (a tapped formula
# is user/tap/name), so only the first two separators matter.
def fingerprint_source:
  split("/")[1];

# A body as GitHub hands it back is not byte-for-byte what was sent: trailing newlines and line
# endings drift. Compare what a reader would see.
def comparable_body:
  gsub("\r\n"; "\n") | sub("\\s+$"; "");

. as $in
| $in.host as $host
| ($in.issues | map(select(issue_fingerprint != null) | {key: issue_fingerprint, value: .}) | from_entries) as $open
| ($in.report.findings | map({key: fingerprint($host), value: .}) | from_entries) as $current
| (
    # New findings, and findings whose issue has drifted from what the scan says now.
    [$in.report.findings[]
     | fingerprint($host) as $fp
     | issue_title($host) as $title
     | issue_body($host) as $body
     | issue_labels($host) as $labels
     | if $open[$fp] == null then
         {op: "create", title: $title, body: $body, labels: $labels}
       else
         $open[$fp] as $issue
         | ($issue.labels | map(.name)) as $have
         # Only labels this tool owns are compared: anything a person added stays.
         | ([$have[] | select(test("^(severity|kind|source):"))] - $labels) as $remove
         | ($labels - $have) as $add
         | if $issue.title != $title or (($issue.body // "") | comparable_body) != ($body | comparable_body)
              or ($add | length) > 0 or ($remove | length) > 0
           then {op: "update", number: $issue.number, title: $title, body: $body,
                 add_labels: $add, remove_labels: $remove}
           else empty end
       end]
  )
  + (
    # Open issues the scan no longer finds. Closed only when their source scanned cleanly this
    # time: a source that failed or was skipped says nothing about whether the problem is gone.
    [$open | to_entries[]
     | select(.key | startswith($host + "/"))
     | select($current[.key] == null)
     | select(($in.report.sources[.key | fingerprint_source].status // "") == "ok")
     | {op: "close", number: .value.number,
        comment: ("No longer found on `\($host)` by the scan at \($in.report.scanned_at), so closing.\n\n"
          + "Either the software was updated or removed, or the advisory data changed (an advisory "
          + "withdrawn or its affected versions revised). If it is found again, a new issue is opened.")}]
  )
