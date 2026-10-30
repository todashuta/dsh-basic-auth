# dsh-basic-auth

DSH（DeepSeek Harness）の Web GUI に HTTP Basic 認証を追加する DSH bundle です。

起動時に表示される `?token=...` 付き URL の代わりに、ブラウザ標準のパスワードダイアログでログインできます。認証に成功すると DSH 本来の署名 Cookie が発行されるので、`/api` や WebSocket は既存の Cookie 認証のまま動きます。

## 仕組み

DSH は起動ごとにランダムなトークンを URL で渡し、それを署名 Cookie に交換してブラウザを認証します。この bundle は `/` のルートを横取りし、Cookie がない場合に Basic 認証を要求します。

```
ブラウザ
  │  GET /
  ▼
dsh-basic-auth（exact route "/"）
  │
  ├─ 署名 Cookie あり ─────────────► index を返す
  │
  ├─ Authorization: Basic ────────► 資格情報を検証
  │                                   │
  │                                   ├─ OK ──► authorizeIndex() を合成リクエストで呼ぶ
  │                                   │          └─ 200 + Set-Cookie（index をそのまま返す）
  │                                   │
  │                                   └─ NG ──► 401 + WWW-Authenticate
  │
  └─ ?token=... ──────────────────► 既存のトークン交換（303 + Set-Cookie）
```

- Cookie がない状態で Basic 認証に成功すると、DSH の署名 Cookie を発行し、同じレスポンスで index を返します。303 リダイレクトを挟まないため、Cookie の保存が遅い環境でもリダイレクトループになりません。
- 以後の `/api` と WebSocket は、これまでどおり Connection の Cookie 認証で保護されます。
- 既存の `?token=...` URL も引き続き使えます（ブックマークや起動スクリプトの互換性のため）。
- パスワードが未設定または空の場合は Basic 認証を有効にせず、DSH 本来のトークン方式のまま動きます。

## インストール

DSH のプロファイルに bundle として追加します。

```sh
# npm から（公開後）
dsh plugin --profile web add dsh-basic-auth

# GitHub から
dsh plugin --profile web add github:todashuta/dsh-basic-auth

# ローカルのチェックアウトから
dsh plugin --profile web add link:/path/to/dsh-basic-auth
```

インストールすると `dsh.profile.bundles` に追加され、bundle が有効になります。HMR が有効なプロファイルならその場で反映され、そうでなければ次回起動時に反映されます。

`dsh plugin add` はプロファイルの `node_modules` にパッケージを置き、bundle の `dsh.bundle.patch` を読みます。`cordis.patch.yml` の中で `web-runtime` の表示設定を止めているので、URL の表示はこのプラグインが担当します。

## 起動

```sh
DSH_WEB_PASSWORD='change-me' dsh --profile web
```

起動すると、トークンなしの URL と Basic 認証のユーザー名が表示されます。

```
dsh web: http://127.0.0.1:3080
dsh web: HTTP Basic authentication is enabled for user "dsh"
```

ブラウザで URL を開くと Basic 認証のダイアログが出るので、ユーザー名 `dsh`、パスワード `change-me` を入力します。

### パスワードを変える

`DSH_WEB_PASSWORD` を変えて再起動してください。ブラウザが古いパスワードをキャッシュしている場合は、一度 401 になってから再入力ダイアログが出ます。

### ユーザー名や realm を変える

bundle の patch はパッケージ内にあるので、プロファイル側の `cordis.patch.yml` で上書きします。

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: dsh-basic-auth
  config:
    username: alice
    password: !!js process.env.DSH_WEB_PASSWORD
    realm: DeepSeek Harness
```

プロファイルの patch は bundle の patch より後に適用されるため、ここで指定した値が優先されます。ユーザー名に `:` は使えません。

## 設定

| キー | 既定値 | 説明 |
| --- | --- | --- |
| `username` | `dsh` | Basic 認証のユーザー名。空文字と `:` は不可 |
| `password` | `DSH_WEB_PASSWORD` | パスワード。未設定または空なら Basic 認証は無効 |
| `realm` | `DeepSeek Harness` | `WWW-Authenticate` の realm。`"`、`\`、制御文字は不可 |

## セキュリティ

- **通信路が保護されている前提**です。VPN、Tailscale、TLS 終端のリバースプロキシなど、経路が暗号化されている環境で使ってください。Basic 認証はパスワードを Base64 で送るだけなので、保護されていない HTTP でインターネットに晒すとパスワードが読まれます。
- 総当たり対策、ログアウト、パスワード変更 UI はありません。1 ユーザーの資格情報を固定で使う想定です。
- 静的アセット（`/assets/...` など）は公開のままです。データと `/api` は Cookie で保護されます。
- `?token=...` URL は引き続き有効です。トークンを知っている人は Basic 認証を迂回できます（DSH の既存動作）。トークン付き URL を共有・ログ出力しないでください。
- Basic 認証の資格情報はブラウザがキャッシュします。共用端末では注意してください。

## 既知の制約

- 署名 Cookie の発行に `ctx.connection.authorizeIndex()` を合成リクエストで呼んでいます。これは DSH が index 用に公開している API で、公式の認証拡張点ではありません。DSH のアップデートで動かなくなる可能性があります。
- Cookie が保存されない環境では、index は表示されても `/api` が 401 になります。DSH を TLS で動かしているのに HTTP でアクセスしている場合、`Secure` Cookie が保存されないため HTTPS でアクセスしてください。リバースプロキシ配下で `Host` が書き換わる環境では、Cookie の audience が一致せず再ログインが必要になることがあります。
- `/index.html` を直接開いた場合、Basic チャレンジは出ません（Cookie があれば通ります）。通常は `/` から入るため実用上は問題ありません。
- bundle の patch で `openBrowser: false` にしているため、起動時の自動ブラウザオープンは無効です。表示された URL を手動で開いてください。
- 複数ユーザーには対応していません。
- DSH 本体（`packages/client/connection`）に Basic 認証を組み込む方式ではありません。本体を変更せず、bundle の範囲で動かすための実装です。

## 開発

```sh
npm test
# または
node --test test/
```

テストは `node:test` だけで動きます。DSH のチェックアウトは不要です。

ローカルの変更を DSH で試すときは、`link:` でインストールします。

```sh
dsh plugin --profile web add link:$PWD
```

### bundle の構成

- `package.json` の `dsh.bundle.patch` が `./cordis.patch.yml` を指します。
- `cordis.patch.yml` が `web-runtime` の表示を止め、`dsh-basic-auth` を insert します。
- `locale/en.json` と `locale/ja.json` が Plugins ページの表示名と説明を提供します。
- プラグイン本体は `src/index.mjs` で、実行時依存は `node:crypto` だけです。

## ライセンス

MIT
