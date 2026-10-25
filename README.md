# dsh-basic-auth

DSH（DeepSeek Harness）の Web GUI に HTTP Basic 認証を追加する単体プラグインです。

起動時に表示される `?token=...` 付き URL の代わりに、ブラウザ標準のパスワードダイアログでログインできます。認証に成功すると DSH 本来の署名 Cookie が発行されるので、`/api` や WebSocket は既存の Cookie 認証のまま動きます。

## 仕組み

DSH は起動ごとにランダムなトークンを URL で渡し、それを署名 Cookie に交換してブラウザを認証します。このプラグインは `/` のルートを横取りし、Cookie がない場合に Basic 認証を要求します。

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
  │                                   │          └─ 303 + Set-Cookie を返す
  │                                   │
  │                                   └─ NG ──► 401 + WWW-Authenticate
  │
  └─ ?token=... ──────────────────► 既存のトークン交換（303 + Set-Cookie）
```

- Cookie がない状態で Basic 認証に成功すると、DSH の署名 Cookie を発行して `./` に 303 でリダイレクトします。
- 以後の `/api` と WebSocket は、これまでどおり Connection の Cookie 認証で保護されます。
- 既存の `?token=...` URL も引き続き使えます（ブックマークや起動スクリプトの互換性のため）。
- パスワードが未設定または空の場合は Basic 認証を有効にせず、DSH 本来のトークン方式のまま動きます。

## 必要なもの

- DSH のチェックアウト（`pnpm dsh` で起動できる状態）
- Node.js 22 以上
- DSH の Web プロファイル（`dsh --profile web`）

## 使い方

### 1. 取得

```sh
git clone https://github.com/todashuta/dsh-basic-auth.git
cd dsh-basic-auth
```

### 2. overlay のパスを書き換える

`cordis.patch.yml.example` をコピーしてローカル用の `cordis.patch.yml` を作り、`file:///REPLACE/WITH/ABS/PATH/...` をこのディレクトリの絶対パスに置き換えます。`cordis.patch.yml` は `.gitignore` 対象なので、環境ごとのパスがリポジトリに入りません。

```sh
cp cordis.patch.yml.example cordis.patch.yml
sed -i "s|file:///REPLACE/WITH/ABS/PATH/dsh-basic-auth/src/index.mjs|file://$PWD/src/index.mjs|" cordis.patch.yml
grep 'file://' cordis.patch.yml
```

### 3. 起動

DSH のチェックアウトで、overlay を `--patch` に渡します。

```sh
cd /path/to/deepseek-harness
DSH_WEB_PASSWORD='change-me' pnpm dsh \
  --patch /path/to/dsh-basic-auth/cordis.patch.yml \
  --profile web
```

`--patch` は `dsh` のグローバルオプションです。`--profile web` の後ろに置くと `unknown option '--patch'` になるので、必ず前に置いてください。

起動すると、トークンなしの URL と Basic 認証のユーザー名が表示されます。

```
dsh web: http://127.0.0.1:3080
dsh web: HTTP Basic authentication is enabled for user "dsh"
```

ブラウザで URL を開くと Basic 認証のダイアログが出るので、ユーザー名 `dsh`、パスワード `change-me` を入力します。

### パスワードを変える

`DSH_WEB_PASSWORD` を変えて再起動してください。ブラウザが古いパスワードをキャッシュしている場合は、一度 401 になってから再入力ダイアログが出ます。

### ユーザー名を変える

`cordis.patch.yml` の `config.username` を変更します。ユーザー名に `:` は使えません。

## 設定

| キー | 既定値 | 説明 |
| --- | --- | --- |
| `username` | `dsh` | Basic 認証のユーザー名。空文字と `:` は不可 |
| `password` | `DSH_WEB_PASSWORD` | パスワード。未設定または空なら Basic 認証は無効 |
| `realm` | `DeepSeek Harness` | `WWW-Authenticate` の realm。`"`、`\`、制御文字は不可 |

`password` を overlay に直接書くこともできますが、環境変数から渡すほうが履歴やファイルに残りにくくなります。

## セキュリティ

- **通信路が保護されている前提**です。VPN、Tailscale、TLS 終端のリバースプロキシなど、経路が暗号化されている環境で使ってください。Basic 認証はパスワードを Base64 で送るだけなので、保護されていない HTTP でインターネットに晒すとパスワードが読まれます。
- 総当たり対策、ログアウト、パスワード変更 UI はありません。1 ユーザーの資格情報を固定で使う想定です。
- 静的アセット（`/assets/...` など）は公開のままです。データと `/api` は Cookie で保護されます。
- `?token=...` URL は引き続き有効です。トークンを知っている人は Basic 認証を迂回できます（DSH の既存動作）。トークン付き URL を共有・ログ出力しないでください。
- Basic 認証の資格情報はブラウザがキャッシュします。共用端末では注意してください。

## 既知の制約

- 署名 Cookie の発行に `ctx.connection.authorizeIndex()` を合成リクエストで呼んでいます。これは DSH が index 用に公開している API で、公式の認証拡張点ではありません。DSH のアップデートで動かなくなる可能性があります。
- `/index.html` を直接開いた場合、Basic チャレンジは出ません（Cookie があれば通ります）。通常は `/` から入るため実用上は問題ありません。
- overlay で `openBrowser: false` にしているため、起動時の自動ブラウザオープンは無効です。表示された URL を手動で開いてください。
- 複数ユーザーには対応していません。
- DSH 本体（`packages/client/connection`）に Basic 認証を組み込む方式ではありません。本体を変更せず、`--patch` の範囲で動かすための実装です。

## 開発

```sh
npm test
# または
node --test test/
```

テストは `node:test` だけで動きます。DSH のチェックアウトは不要です。

## ライセンス

MIT
