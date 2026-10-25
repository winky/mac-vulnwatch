# shellcheck shell=bash
#
# lib/sync.sh
# Carries out the actions lib/sync.jq decides on, through the gh CLI.
#
# Needs lib/common.sh sourced first, and ROOT set.

# Colours for the labels this tool creates. Anything not listed gets a neutral grey.
label_color() {
  case "$1" in
    severity:critical) echo b60205 ;;
    severity:high) echo d93f0b ;;
    severity:medium) echo fbca04 ;;
    severity:low) echo 0e8a16 ;;
    kind:vulnerability) echo 5319e7 ;;
    kind:eol) echo 000000 ;;
    mac-vulnwatch) echo 1d76db ;;
    needs-review) echo fbca04 ;;
    *) echo ededed ;;
  esac
}

# sync_plan REPO HOST REPORT_FILE
# Prints the actions as a JSON array, without changing anything.
sync_plan() {
  local repo="$1" host="$2" report="$3"
  # Every open issue for this host, whatever its source: one listing call instead of one per
  # source, and the plan needs all of them to know what to close.
  #
  # Through a pipe rather than --argjson: with hundreds of issue bodies the listing can outgrow
  # what an argument may hold.
  gh issue list --repo "${repo}" --state open \
    --label mac-vulnwatch --label "host:${host}" \
    --limit 1000 --json number,title,body,labels \
    | jq -L "${ROOT}/lib" --arg host "${host}" --slurpfile report "${report}" \
      '{host: $host, report: $report[0], issues: .}' \
    | jq -L "${ROOT}/lib" -f "${ROOT}/lib/sync.jq"
}

# ensure_labels REPO PLAN
# gh refuses to apply a label that does not exist, so create the missing ones first.
ensure_labels() {
  local repo="$1" plan="$2" existing label
  existing="$(gh label list --repo "${repo}" --limit 1000 --json name --jq '.[].name')" || return 1
  while IFS= read -r label; do
    [ -n "${label}" ] || continue
    if ! grep -Fxq -- "${label}" <<< "${existing}"; then
      gh label create "${label}" --repo "${repo}" --color "$(label_color "${label}")" > /dev/null || return 1
    fi
  done < <(jq -r '[.[] | (.labels // []), (.add_labels // [])] | flatten | unique | .[]' <<< "${plan}")
}

# sync_apply REPO PLAN
#
# Bodies are piped with jq -j rather than -r: -r appends a newline, and GitHub keeps it.
# Prints one line per action taken. Returns non-zero if any action failed, after trying all.
sync_apply() {
  local repo="$1" plan="$2" action op number label failed=0 args
  ensure_labels "${repo}" "${plan}" || {
    log "Could not create the labels in ${repo}."
    return 1
  }

  while IFS= read -r action; do
    op="$(jq -r .op <<< "${action}")"
    number="$(jq -r '.number // empty' <<< "${action}")"
    case "${op}" in
      create)
        args=()
        while IFS= read -r label; do
          args+=(--label "${label}")
        done < <(jq -r '.labels[]' <<< "${action}")
        if jq -j .body <<< "${action}" | gh issue create --repo "${repo}" \
          --title "$(jq -r .title <<< "${action}")" --body-file - "${args[@]}" > /dev/null; then
          echo "opened   $(jq -r .title <<< "${action}")"
        else
          failed=1
        fi
        ;;
      update)
        args=()
        while IFS= read -r label; do
          [ -n "${label}" ] && args+=(--add-label "${label}")
        done < <(jq -r '.add_labels[]' <<< "${action}")
        while IFS= read -r label; do
          [ -n "${label}" ] && args+=(--remove-label "${label}")
        done < <(jq -r '.remove_labels[]' <<< "${action}")
        if jq -j .body <<< "${action}" | gh issue edit "${number}" --repo "${repo}" \
          --title "$(jq -r .title <<< "${action}")" --body-file - ${args[@]+"${args[@]}"} > /dev/null; then
          echo "updated  #${number} $(jq -r .title <<< "${action}")"
        else
          failed=1
        fi
        ;;
      hold)
        if gh issue edit "${number}" --repo "${repo}" --add-label "$(jq -r '.add_labels[0]' <<< "${action}")" > /dev/null \
          && gh issue comment "${number}" --repo "${repo}" --body "$(jq -r .comment <<< "${action}")" > /dev/null; then
          echo "held     #${number}"
        else
          failed=1
        fi
        ;;
      close)
        if gh issue close "${number}" --repo "${repo}" --reason completed \
          --comment "$(jq -r .comment <<< "${action}")" > /dev/null; then
          echo "closed   #${number}"
        else
          failed=1
        fi
        ;;
    esac
  done < <(jq -c '.[]' <<< "${plan}")

  return "${failed}"
}
