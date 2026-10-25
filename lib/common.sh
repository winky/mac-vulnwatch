# shellcheck shell=bash
#
# lib/common.sh
# Helpers shared by the entry point and the collectors.
#
# Everything here has to run on the bash that ships with macOS, which is 3.2: no associative
# arrays, no mapfile, no ${var,,}, and an empty array cannot be expanded under `set -u`.

# shellcheck disable=SC2034 # read by bin/mac-vulnwatch, which sources this file
MAC_VULNWATCH_VERSION="0.1.0"

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "mac-vulnwatch: $*"
  exit 1
}

# A collector exits with this when it does not apply to the machine (the tool it needs is not
# installed). That is not a failure: it is reported as "skipped", and nothing it owns is closed.
# shellcheck disable=SC2034 # read by the collectors and bin/mac-vulnwatch
EXIT_NOT_APPLICABLE=3

# config_get KEY DEFAULT
#
# Reads KEY from the environment (MAC_VULNWATCH_KEY) first, then from the config file. The
# config file is parsed rather than sourced, so that it can hold nothing but values.
config_get() {
  local key="$1" default="$2" env_name value
  env_name="MAC_VULNWATCH_${key}"
  if [ -n "${!env_name+set}" ]; then
    printf '%s' "${!env_name}"
    return
  fi
  value=""
  if [ -n "${MAC_VULNWATCH_CONFIG:-}" ] && [ -f "${MAC_VULNWATCH_CONFIG}" ]; then
    value="$(sed -n "s/^[[:space:]]*${key}[[:space:]]*=[[:space:]]*//p" "${MAC_VULNWATCH_CONFIG}" | tail -n 1)"
    # Strip one pair of surrounding quotes, so KEY="a b" and KEY=a b mean the same thing.
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
  fi
  printf '%s' "${value:-${default}}"
}

config_true() {
  case "$(config_get "$1" "$2")" in
    1 | true | yes | on) return 0 ;;
    *) return 1 ;;
  esac
}

# Homebrew updates its own metadata and sends analytics when it feels like it. A scan should
# do neither: it reads, and it should take the same time every day.
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_ENV_HINTS=1
