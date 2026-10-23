# mac-vulnwatch

[日本語](README.ja.md)

Dependabot for your Mac. A daily scan finds software on the machine that has known
vulnerabilities or a pending update, writes a local report, and (optionally) mirrors each
finding as a GitHub issue that closes itself once the scan stops finding it.

```
| Severity | Source  | Finding                                         | Fix                            |
|----------|---------|-------------------------------------------------|--------------------------------|
| high     | brew    | openssl@3 3.6.4: 13 known vulnerabilities       | `brew upgrade openssl@3`       |
| high     | runtime | nodejs 25.2.0: release line 25 reached end of life | Move to a supported release line |
| unknown  | macos   | macOS Tahoe 26.1 is not installed               | `softwareupdate --install ...` |
| unknown  | cask    | example-browser 120.0.1: 121.0.0 is available   | `brew upgrade --cask ...`      |
```

No AI, no service, no account: it is bash and jq on top of tools you already have, and the
vulnerability data comes from public databases ([OSV.dev](https://osv.dev),
[endoflife.date](https://endoflife.date), trivy's DB).

## What it checks

| Collector | Looks at | Reports | Needs |
|---|---|---|---|
| `macos` | `softwareupdate --list` | macOS, Safari, CLT and security updates not yet installed | - |
| `brew` | `brew vulns` (OSV.dev) | Formulae with known vulnerabilities, and whether an upgrade exists | Homebrew with `brew vulns` |
| `cask` | `brew outdated --cask` | Apps with a newer version | Homebrew |
| `mas` | `mas outdated` | App Store apps with an update | [mas](https://github.com/mas-cli/mas) |
| `runtime` | asdf + endoflife.date | Tools on an end-of-life line, or behind their line's latest patch: any asdf plugin endoflife.date knows (nodejs, python, golang, terraform, kubectl, java, ...) | asdf |
| `docker` | `trivy image` | Local images with HIGH/CRITICAL vulnerabilities (off by default) | trivy, a running Docker |

A collector whose tool is not installed is skipped, not failed.

Findings come in three kinds. **vulnerability** has a known advisory. **eol** means the
software no longer receives security fixes. **update** means a newer version exists but the
source does not say whether it fixes anything security-related; casks, App Store apps and
macOS updates can only ever be this.

## Install

Requirements: macOS, `jq`. For GitHub issues, `gh`.

```sh
git clone https://github.com/winky/mac-vulnwatch.git
cd mac-vulnwatch
make link              # optional: puts mac-vulnwatch in ~/.local/bin
mac-vulnwatch --dry-run
```

`--dry-run` scans and prints the report but saves nothing and touches nothing on GitHub.

To run daily:

```sh
make install                   # 09:00 every day
make install HOUR=7 MINUTE=30  # or another time
make status
```

The scan runs as a LaunchAgent, i.e. as you, while you are logged in. If the Mac is asleep at
the scheduled time, it runs when it wakes. Output goes to
`~/Library/Logs/mac-vulnwatch/mac-vulnwatch.log`.

## Configure

Copy [config.example](config.example) to `~/.config/mac-vulnwatch/config`. Every key is
optional.

### GitHub issues

```sh
gh repo create your-name/machine-vulns --private
echo 'GITHUB_REPO=your-name/machine-vulns' >> ~/.config/mac-vulnwatch/config
mac-vulnwatch --dry-run   # shows "would open ..." for each issue
```

**Use a private repository.** The issues list what is installed on your machine and what is
vulnerable in it.

Each finding becomes one issue, labelled `host:<name>`, `source:<collector>`,
`severity:<level>` and `kind:<kind>`, so several Macs can share one repository. On each scan:

- a new finding opens an issue
- a finding that changed (new version, new advisory) updates its issue
- a finding that is gone closes its issue with a comment

An issue is closed only when its collector **ran successfully**. A failed or skipped
collector never closes anything, so a network error is not mistaken for a fix. Labels you add
yourself are left alone.

## Output

| | |
|---|---|
| stdout | The report, as Markdown, or JSON with `--format json` |
| `~/.local/state/mac-vulnwatch/latest.{md,json}` | The last report |
| Notification | When a scan finds something the previous scan did not |
| Exit code | `1` if a collector or the issue sync failed, otherwise `0` |

```sh
mac-vulnwatch --only brew,macos --no-sync --format json | jq '.findings[] | select(.severity == "high")'
```

## Development

```sh
make test   # bash + jq only; no Homebrew, network or GitHub needed
make lint   # shellcheck
```

Each collector separates fetching from parsing: `collectors/<name>.sh --parse` reads the raw
tool output on stdin, which is what the tests feed from `tests/fixtures/`. The decision of what
to do to GitHub issues is a pure jq program (`lib/sync.jq`), tested the same way, including that
a settled state produces no changes.

Everything targets the `/bin/bash` 3.2 that ships with macOS.

To add a collector, write `collectors/<name>.sh` that prints a JSON array of findings (the
shape is documented at the top of `lib/findings.jq`) and exits `3` when it does not apply.

## License

MIT
