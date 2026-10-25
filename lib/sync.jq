# lib/sync.jq
# Decides what to do to GitHub issues, given a scan and the issues already open.
#
# Input:
#   {
#     "host":   "mac-mini",
#     "report": {"scanned_at": ..., "sources": {"brew": {"status": "ok"}, ...}, "findings": [...],
#                "inventory": {"brew/ffmpeg": ["9.0.2"], ...}},
#     "issues": [{"number": 1, "title": ..., "body": ..., "labels": [{"name": ...}]}]
#   }
#
# Output: a list of actions, each one of
#   {"op": "create", "title", "body", "labels"}
#   {"op": "update", "number", "title", "body", "add_labels", "remove_labels"}
#   {"op": "close",  "number", "comment"}
#   {"op": "hold",   "number", "comment", "add_labels"}
#
# Pure, so that it can be tested without GitHub. lib/sync.sh carries the actions out.

include "findings";

# Put on an issue the scan stopped reporting while the software stayed as it was. Owned by this
# tool: removed again if the finding comes back.
def review_label: "needs-review";

# The installed version an issue was filed for, from its body.
def issue_installed:
  [(.body // "") | capture("\\| Installed \\| `(?<version>[^`]*)` \\|")?][0].version;

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
         | ([$have[] | select(test("^(severity|kind|source):") or . == review_label)] - $labels) as $remove
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
     | .value as $issue
     | (.key | ltrimstr($host + "/")) as $id
     | ($id | split("/")[0]) as $source
     # Only a source that reports an inventory can say whether the software is still there.
     | ([($in.report.inventory // {}) | keys[] | select(startswith($source + "/"))] | length > 0) as $inventoried
     | (($in.report.inventory // {})[$id] // null) as $now
     | ($issue | issue_installed) as $was
     # Still installed at the version the issue was filed for: nothing on this machine changed,
     # so what changed is the data. brew vulns stopped reporting ffmpeg 9.0.2 this way when
     # OSV.dev rewrote its records, while 9.0.2 was still affected. Keep it open, and say so once.
     | if $now != null and $was != null and ($now | index($was)) != null then
         if ($issue.labels | map(.name) | index(review_label)) != null then empty
         else {op: "hold", number: $issue.number, add_labels: [review_label],
               comment: ("No longer reported by the scan at \($in.report.scanned_at), but `\($was)` is still "
                 + "installed on `\($host)`, so this stays open.\n\n"
                 + "Nothing changed on the machine; the advisory data did. That can mean an advisory was "
                 + "withdrawn or corrected, or that the source stopped matching it. Check the advisories "
                 + "above, and close this by hand if the version is not affected. It closes by itself "
                 + "once the software is updated or removed.")}
         end
       else
         {op: "close", number: $issue.number,
          comment: ("No longer found on `\($host)` by the scan at \($in.report.scanned_at), so closing: "
            + (if $inventoried and $now == null
               then "it is no longer installed."
               elif $was != null and $now != null then "the installed version changed from `\($was)`."
               else "either the software was updated or removed, or the advisory data changed." end)
            + " If it is found again, a new issue is opened.")}
       end]
  )
