# mac-vulnwatch

[English](README.md)

Mac 版の Dependabot。毎日のスキャンで、既知の脆弱性があるソフトウェアや未適用の更新を見つけ、
ローカルにレポートを書き出す。設定すれば各検出を GitHub Issue として起票し、検出されなくなったら
自動で close する。

AI もサービスもアカウントも不要。手元にあるツールの上で bash と jq が動くだけで、脆弱性データは
公開データベース（[OSV.dev](https://osv.dev)、[endoflife.date](https://endoflife.date)、trivy の DB）
から来る。

## 検査対象

| コレクタ | 見るもの | 報告するもの | 必要なもの |
|---|---|---|---|
| `macos` | `softwareupdate --list` | 未適用の macOS・Safari・CLT・セキュリティ更新 | - |
| `brew` | `brew vulns`（OSV.dev） | 既知の脆弱性がある formula と、アップグレード先の有無 | `brew vulns` がある Homebrew |
| `cask` | `brew outdated --cask` | 新しい版があるアプリ | Homebrew |
| `mas` | `mas outdated` | 更新がある App Store アプリ | [mas](https://github.com/mas-cli/mas) |
| `runtime` | asdf、mise、Homebrew、公式インストーラ ＋ endoflife.date | EOL の系列にある言語やツール、系列の最新パッチより古いもの。endoflife.date が知っているものすべて（nodejs, python, go, terraform, kubectl, postgresql, java, rust など） | いずれか |
| `packages` | npm -g、pipx、uv tool、pip --user、Go バイナリ、cargo ＋ OSV.dev | 既知の脆弱性を含むグローバルに入れたツール（依存も含む） | いずれか |
| `docker` | `trivy image` | HIGH/CRITICAL の脆弱性があるローカルイメージ（既定で無効） | trivy、起動中の Docker |

ツールが入っていないコレクタは「失敗」ではなく「スキップ」になる。プロジェクトの依存（リポジトリの
lockfile）は対象外で、GitHub の Dependabot が既に見ている。

`packages` はインストールしたツールごとに1件で、その中の脆弱なパッケージをすべて並べる。アップグレード
できる単位がツールだからである。npm は PATH 上の Node.js のものを読む。asdf や mise ならグローバルに
選ばれているバージョン。

`runtime` は言語の一般的な入れ方をすべて読む。asdf、mise、Homebrew（自分で入れた formula のみ、EOL 判定
のみ）、python.org、go.dev、nodejs.org、JDK のインストーラ、rustup の stable。Apple が同梱するもの
（`/usr/bin/ruby`、`perl`、`python3`）は意図的に対象外にしている。更新できるのは Apple だけで、更新が
出れば `macos` コレクタが報告する。

検出は3種類。**vulnerability** は既知のアドバイザリがある。**eol** はもうセキュリティ修正が
出ない。**update** は新しい版があるが、セキュリティ修正を含むかは情報源が言っていない。cask・
App Store・macOS の更新はこれにしかなりえない。

## インストール

必要なもの: macOS。GitHub Issue を使うなら `gh`。

### Homebrew で入れる

```sh
brew install winky/tap/mac-vulnwatch
mac-vulnwatch --dry-run
brew services start mac-vulnwatch   # 毎日 09:00 にスキャン
```

`--dry-run` はスキャンしてレポートを出すが、何も保存せず GitHub にも触れない。

更新は `brew upgrade` で。毎日のスキャンは LaunchAgent として、ログイン中のあなたの権限で動く。
09:00 にスリープしていれば復帰時に動く。出力は `$(brew --prefix)/var/log/mac-vulnwatch.log`。

### clone して使う

別の時刻に動かしたい場合や、手を入れる場合:

```sh
git clone https://github.com/winky/mac-vulnwatch.git
cd mac-vulnwatch
make link                      # 任意: ~/.local/bin に mac-vulnwatch を置く
make install HOUR=7 MINUTE=30  # 毎日 07:30 にスキャン（既定は 09:00）
make status
```

`jq` が必要。出力は `~/Library/Logs/mac-vulnwatch/mac-vulnwatch.log`。どちらか一方だけを使うこと。
両方入れると1日に2回スキャンする。

## 設定

[config.example](config.example) を `~/.config/mac-vulnwatch/config` にコピーする。すべて任意。

### GitHub Issue

```sh
gh repo create your-name/vuln-findings --private
echo 'GITHUB_REPO=your-name/vuln-findings' >> ~/.config/mac-vulnwatch/config
mac-vulnwatch --dry-run   # 起票される Issue が "would open ..." として出る
```

**private リポジトリを使うこと。** Issue には機体に何が入っていて何が脆弱かが並ぶ。

検出1件が Issue 1件になり、`host:<名前>`・`source:<コレクタ>`・`severity:<重要度>`・
`kind:<種類>` のラベルが付く。複数の Mac で1つのリポジトリを共有できる。スキャンのたびに:

- 新しい検出は Issue を起票する
- 変化した検出（版が変わった、アドバイザリが増えた）は Issue を更新する
- 消えた検出は、理由をコメントに書いて Issue を close する

close するのはそのコレクタが**成功したときだけ**。失敗やスキップでは何も close しないので、
ネットワークエラーを修正済みと取り違えない。

アドバイザリのデータの変化も修正済みと取り違えない。インストール済みのものを把握している
コレクタ（`brew`、`packages`）では、起票したときの版が無くなって初めて close する。その版が
入ったまま検出だけが消えたら、Issue は `needs-review` ラベルとコメント1件を付けて開いたままにする。
変わったのは機体ではなくデータの方だからである。自分で付けたラベルには触らない。

## 出力

| | |
|---|---|
| 標準出力 | レポート。Markdown、`--format json` なら JSON |
| `~/.local/state/mac-vulnwatch/latest.{md,json}` | 最後のレポート |
| 通知 | 前回のスキャンに無かった検出があったとき |
| 終了コード | コレクタか Issue 同期が失敗したら `1`、それ以外は `0` |

## 制約

mac-vulnwatch の網羅性は情報源の網羅性で決まり、完全な情報源は無い。

- **Homebrew の formula** は `brew vulns` で見る。OSV.dev のレコードをリポジトリとタグで照合する
  ので、照合できないアドバイザリは見逃す。実際に見た例は2つ。
  - GitHub ミラーからビルドされる formula で、OSV.dev がプロジェクト自身のリポジトリの下にだけ
    アドバイザリを登録している場合。2026年10月、FFmpeg のアドバイザリは `github.com/ffmpeg/ffmpeg`
    では引けなくなり、`git.ffmpeg.org` でしか見つからなくなった。
  - NVD に CPE でだけ記録され、OSV.dev の git の範囲には無いアドバイザリ。

  一方で `brew vulns` は、Homebrew が formula に当てたパッチを考慮する。CPE で照合するスキャナは
  これを考慮しない。
- **cask・App Store アプリ・macOS** には脆弱性のデータが無い。分かるのは「更新がある」ことだけ。
- **runtime** は endoflife.date から EOL とパッチの遅れを見る。CVE は見ない。
- **packages** は、npm は PATH 上の Node.js のものだけ、cargo は依存を含まない。

Homebrew について別の観点からも見たいなら、SBOM スキャナで `brew vulns` の抜けの一部を補える。
ただし CPE による照合と、見えないパッチによる誤検知が増える。組み込んではいないので、手で動かす:

```sh
brew install syft grype
syft scan dir:"$(brew --prefix)/Cellar" --select-catalogers homebrew -o syft-json=sbom.json
grype sbom:sbom.json
```

今の syft は versioned formula と revision を NVD と違う形で書く（`openssl\@3`、`3.6.4_1`）ので、
補正しない限りそれらは見逃す。grype がダウンロードする脆弱性 DB はディスク上で約 3GB ある。

## 開発

```sh
make test   # bash と jq だけ。Homebrew もネットワークも GitHub も要らない
make lint   # shellcheck
```

各コレクタは取得と解析を分けている。`collectors/<名前>.sh --parse` は標準入力からツールの生の
出力を読み、テストは `tests/fixtures/` からそれを与える。GitHub Issue に何をするかの判断は純粋な
jq プログラム（`lib/sync.jq`）で、同じようにテストしている。反映済みの状態から再計画すると何も
起きないことも確かめている。

すべて macOS 標準の `/bin/bash` 3.2 で動くように書いている。

## ライセンス

MIT
