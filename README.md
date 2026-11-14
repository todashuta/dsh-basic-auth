# dsh-basic-auth

DSH（DeepSeek Harness）のWeb GUIにHTTP Basic認証を追加するDSH bundleです。DSH 0.2.2-rc.3以降で動きます。

起動時に表示される`?token=...`付きURLの代わりに、ブラウザ標準のパスワードダイアログでログインできます。認証に成功するとDSH本来の署名Cookieが発行されるので、`/api`やWebSocketは既存のCookie認証のまま動きます。

## 仕組み

DSHは起動ごとにランダムなトークンをURLで渡し、それを署名Cookieに交換してブラウザを認証します。このbundleは`/`のルートを横取りし、Cookieがない場合にBasic認証を要求します。

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

- Cookieがない状態でBasic認証に成功すると、DSHの署名Cookieを発行し、同じレスポンスでindexを返します。303リダイレクトを挟まないため、Cookieの保存が遅い環境でもリダイレクトループになりません。
- 以後の`/api`とWebSocketは、これまでどおりConnectionのCookie認証で保護されます。
- ブックマークや起動スクリプトの互換性のため、既存の`?token=...` URLも引き続き使えます。
- パスワードが未設定または空の場合はBasic認証を有効にせず、DSH本来のトークン方式のまま動きます。

## インストール

DSHのプロファイルにbundleとして追加します。

```sh
# npmから。パッケージ公開後に使えます
dsh plugin --profile web add dsh-basic-auth

# GitHubから
dsh plugin --profile web add github:todashuta/dsh-basic-auth

# ローカルのチェックアウトから
dsh plugin --profile web add link:/path/to/dsh-basic-auth
```

インストールすると`dsh.profile.bundles`に追加され、bundleが有効になります。HMRが有効なプロファイルならその場で反映され、そうでなければ次回起動時に反映されます。

`dsh plugin add`はプロファイルの`node_modules`にパッケージを置き、bundleの`dsh.bundle.patch`を読みます。`cordis.patch.yml`の中で`web-runtime`の表示設定を止めているので、起動時のURL表示はこのプラグインが担当します。

## 起動

```sh
DSH_WEB_PASSWORD='change-me' dsh --profile web
```

起動すると、トークンなしのURLとBasic認証のユーザー名が表示されます。

```
dsh web: http://127.0.0.1:3080
dsh web: HTTP Basic authentication is enabled for user "dsh"
```

ブラウザでURLを開くとBasic認証のダイアログが出るので、ユーザー名`dsh`、パスワード`change-me`を入力します。

### パスワードを変える

`DSH_WEB_PASSWORD`を変えて再起動してください。ブラウザが古いパスワードをキャッシュしている場合は、一度401になってから再入力ダイアログが出ます。

### ユーザー名やrealmを変える

bundleのpatchはパッケージ内にあるので、プロファイル側の`cordis.patch.yml`で上書きします。

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: dsh-basic-auth
  config:
    username: alice
    password: !!js process.env.DSH_WEB_PASSWORD
    realm: DeepSeek Harness
```

プロファイルのpatchはbundleのpatchより後に適用されるため、ここで指定した値が優先されます。ユーザー名に`:`は使えません。

## 設定

| キー | 既定値 | 説明 |
| --- | --- | --- |
| `username` | `dsh` | Basic認証のユーザー名。空文字と`:`は使えません |
| `password` | `DSH_WEB_PASSWORD` | パスワード。未設定か空ならBasic認証を無効にします |
| `realm` | `DeepSeek Harness` | `WWW-Authenticate`のrealm。`"`、`\`、制御文字は使えません |

## セキュリティ

- 通信路が保護されている前提です。VPN、Tailscale、TLS終端のリバースプロキシなど、経路が暗号化されている環境で使ってください。Basic認証はパスワードをBase64で送るだけなので、保護されていないHTTPでインターネットに晒すとパスワードが読まれます。
- 総当たり対策、ログアウト、パスワード変更UIはありません。1ユーザーの資格情報を固定で使う想定です。
- 静的アセット（`/assets/...`など）は公開のままです。データと`/api`はCookieで保護されます。
- `?token=...` URLは引き続き有効です。トークンを知っている人はBasic認証を迂回できます。この迂回路はDSH本来のトークン方式で、Basic認証は閉じません。トークン付きURLを共有・ログ出力しないでください。
- Basic認証の資格情報はブラウザがキャッシュします。共用端末では注意してください。

## 既知の制約

- DSH 0.2.2-rc.3で`ctx.connection.authorizeIndex()`と`authenticatedUrl()`がToken Providerへ移りました。このプラグインは`@deepseek-ai/dsh-host-authentication-token`の`src/browser-auth.ts`を直接インポートして、Token Providerと同じ署名鍵とCookie形式を共有しています。このモジュールはパッケージの公開APIではないため、DSHの更新で動かなくなる可能性があります。
- Cookieが保存されない環境では、indexは表示されても`/api`が401になります。DSHをTLSで動かしているのにHTTPでアクセスしている場合、`Secure` Cookieが保存されないためHTTPSでアクセスしてください。リバースプロキシ配下で`Host`が書き換わる環境では、Cookieのaudienceが一致せず再ログインが必要になることがあります。
- `/index.html`を直接開いた場合、Basicチャレンジは出ません。Cookieがあればそのまま通ります。通常は`/`から入るため実用上は問題ありません。
- bundleのpatchで`openBrowser: false`にしているため、起動時の自動ブラウザオープンは無効です。表示されたURLを手動で開いてください。
- 複数ユーザーには対応していません。
- DSH本体の`packages/client/connection`にBasic認証を組み込む方式ではありません。DSHを変更せず、bundleの範囲で動かすための実装です。

## 開発

```sh
npm test
# または
node --test test/
```

テストは`node:test`だけで動きます。DSHのチェックアウトは不要です。

ローカルの変更をDSHで試すときは、`link:`でインストールします。

```sh
dsh plugin --profile web add link:$PWD
```

### bundleの構成

- `package.json`の`dsh.bundle.patch`が`./cordis.patch.yml`を指します。
- `cordis.patch.yml`が`web-runtime`の表示を止め、`dsh-basic-auth`をinsertします。
- `locale/en.json`と`locale/ja.json`がPluginsページの表示名と説明を提供します。
- プラグイン本体は`src/index.mjs`で、実行時依存は`node:crypto`だけです。

## ライセンス

MIT
