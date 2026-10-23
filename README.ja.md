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
| `runtime` | asdf ＋ endoflife.date | EOL の系列にあるランタイム、系列の最新パッチより古いランタイム | asdf |
| `docker` | `trivy image` | HIGH/CRITICAL の脆弱性があるローカルイメージ（既定で無効） | trivy、起動中の Docker |

ツールが入っていないコレクタは「失敗」ではなく「スキップ」になる。

検出は3種類。**vulnerability** は既知のアドバイザリがある。**eol** はもうセキュリティ修正が
出ない。**update** は新しい版があるが、セキュリティ修正を含むかは情報源が言っていない。cask・
App Store・macOS の更新はこれにしかなりえない。

## インストール

必要なもの: macOS、`jq`。GitHub Issue を使うなら `gh`。

```sh
git clone https://github.com/winky/mac-vulnwatch.git
cd mac-vulnwatch
make link              # 任意: ~/.local/bin に mac-vulnwatch を置く
mac-vulnwatch --dry-run
```

`--dry-run` はスキャンしてレポートを出すが、何も保存せず GitHub にも触れない。

毎日動かすには:

```sh
make install                   # 毎日 09:00
make install HOUR=7 MINUTE=30  # 時刻を変える
make status
```

LaunchAgent として、ログイン中のあなたの権限で動く。予定時刻にスリープしていれば復帰時に動く。
出力は `~/Library/Logs/mac-vulnwatch/mac-vulnwatch.log`。

## 設定

[config.example](config.example) を `~/.config/mac-vulnwatch/config` にコピーする。すべて任意。

### GitHub Issue

```sh
gh repo create your-name/machine-vulns --private
echo 'GITHUB_REPO=your-name/machine-vulns' >> ~/.config/mac-vulnwatch/config
mac-vulnwatch --dry-run   # 起票される Issue が "would open ..." として出る
```

**private リポジトリを使うこと。** Issue には機体に何が入っていて何が脆弱かが並ぶ。

検出1件が Issue 1件になり、`host:<名前>`・`source:<コレクタ>`・`severity:<重要度>`・
`kind:<種類>` のラベルが付く。複数の Mac で1つのリポジトリを共有できる。スキャンのたびに:

- 新しい検出は Issue を起票する
- 変化した検出（版が変わった、アドバイザリが増えた）は Issue を更新する
- 消えた検出は Issue にコメントを付けて close する

close するのはそのコレクタが**成功したときだけ**。失敗やスキップでは何も close しないので、
ネットワークエラーを修正済みと取り違えない。自分で付けたラベルには触らない。

## 出力

| | |
|---|---|
| 標準出力 | レポート。Markdown、`--format json` なら JSON |
| `~/.local/state/mac-vulnwatch/latest.{md,json}` | 最後のレポート |
| 通知 | 前回のスキャンに無かった検出があったとき |
| 終了コード | コレクタか Issue 同期が失敗したら `1`、それ以外は `0` |

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
