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
| `runtime` | asdf, mise, Homebrew, vendor installers + endoflife.date | Languages and tools on an end-of-life line, or behind their line's latest patch: anything endoflife.date knows (nodejs, python, go, terraform, kubectl, postgresql, java, rust, ...) | any of those |
| `packages` | npm -g, pipx, uv tools, pip --user, Go binaries, cargo + OSV.dev | Globally installed tools carrying known vulnerabilities, including their dependencies | any of those |
| `docker` | `trivy image` | Local images with HIGH/CRITICAL vulnerabilities (off by default) | trivy, a running Docker |

A collector whose tool is not installed is skipped, not failed. Project dependencies (lockfiles in
your repositories) are out of scope: GitHub's Dependabot already covers them.

`packages` reports one finding per installed tool, listing every vulnerable package inside it,
because the tool is what you can upgrade. npm is read for the Node.js on PATH; with asdf or mise
that is the globally selected version.

`runtime` reads every way a language is commonly installed: asdf, mise, Homebrew (formulae you
installed yourself, end of life only), python.org, go.dev, nodejs.org, JDK installers and
rustup's stable toolchain. The interpreters Apple ships (`/usr/bin/ruby`, `perl`, `python3`) are
left out on purpose: only Apple can update them, and the `macos` collector reports when it does.

Findings come in three kinds. **vulnerability** has a known advisory. **eol** means the
software no longer receives security fixes. **update** means a newer version exists but the
source does not say whether it fixes anything security-related; casks, App Store apps and
macOS updates can only ever be this.

## Install

Requirements: macOS. For GitHub issues, `gh`.

### With Homebrew

```sh
brew install winky/tap/mac-vulnwatch
mac-vulnwatch --dry-run
brew services start mac-vulnwatch   # scan every day at 09:00
```

`--dry-run` scans and prints the report but saves nothing and touches nothing on GitHub.

`brew upgrade` keeps it current. The daily scan runs as a LaunchAgent, i.e. as you, while you
are logged in; if the Mac is asleep at 09:00 it runs when it wakes. Output goes to
`$(brew --prefix)/var/log/mac-vulnwatch.log`.

### From a clone

For another time of day, or to work on it:

```sh
git clone https://github.com/winky/mac-vulnwatch.git
cd mac-vulnwatch
make link                      # optional: puts mac-vulnwatch in ~/.local/bin
make install HOUR=7 MINUTE=30  # scan daily at 07:30 (default 09:00)
make status
```

Needs `jq`. Output goes to `~/Library/Logs/mac-vulnwatch/mac-vulnwatch.log`. Use one or the
other: both installed means two scans a day.

## Configure

Copy [config.example](config.example) to `~/.config/mac-vulnwatch/config`. Every key is
optional.

### GitHub issues

```sh
gh repo create your-name/vuln-findings --private
echo 'GITHUB_REPO=your-name/vuln-findings' >> ~/.config/mac-vulnwatch/config
mac-vulnwatch --dry-run   # shows "would open ..." for each issue
```

**Use a private repository.** The issues list what is installed on your machine and what is
vulnerable in it.

Each finding becomes one issue, labelled `host:<name>`, `source:<collector>`,
`severity:<level>` and `kind:<kind>`, so several Macs can share one repository. On each scan:

- a new finding opens an issue
- a finding that changed (new version, new advisory) updates its issue
- a finding that is gone closes its issue with a comment saying why

An issue is closed only when its collector **ran successfully**. A failed or skipped
collector never closes anything, so a network error is not mistaken for a fix.

Nor is a change in the advisory data. Where a collector knows what is installed (`brew`,
`packages`), an issue is closed only once the version it was filed for is gone. If a finding
disappears while that version is still installed, the issue stays open with a `needs-review`
label and one comment: something changed in the data, not on the machine. Labels you add
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

## Limitations

mac-vulnwatch is only as complete as its sources, and none of them is complete.

- **Homebrew formulae** are checked by `brew vulns`, which matches OSV.dev records by
  repository and tag. Advisories it cannot match are missed. Two cases seen in practice:
  - A formula built from a GitHub mirror, when OSV.dev indexes the advisory under the
    project's own repository. In October 2026 FFmpeg's advisories stopped matching
    `github.com/ffmpeg/ffmpeg` and were found only under `git.ffmpeg.org`.
  - Advisories recorded only in NVD with CPEs, and never in OSV.dev's git ranges.

  `brew vulns` does account for patches Homebrew applies to a formula, which CPE-based scanners
  do not.
- **Casks, App Store apps and macOS** have no vulnerability data: only "an update exists".
- **runtime** reports end of life and patch lag from endoflife.date, not CVEs.
- **packages** sees npm for the Node.js on PATH only, and cargo installs without their
  dependencies.

For a second opinion on Homebrew, an SBOM scanner covers some of what `brew vulns` misses, at
the cost of false positives from CPE matching and from patches it cannot see. It is not built
in; to run it by hand:

```sh
brew install syft grype
syft scan dir:"$(brew --prefix)/Cellar" --select-catalogers homebrew -o syft-json=sbom.json
grype sbom:sbom.json
```

syft currently names versioned formulae and revisions in a way NVD does not
(`openssl\@3`, `3.6.4_1`), so those are missed unless corrected. The vulnerability database
grype downloads is about 3 GB on disk.

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
