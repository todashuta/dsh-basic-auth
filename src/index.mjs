/**
 * dsh-basic-auth — DSHのWeb GUIのindexルートの前に立つHTTP Basic認証ゲート。
 *
 * DSHは、起動プロセスごとのトークンをURLで渡し、それを署名Cookieに交換して
 * ブラウザを認証する。このプラグインはindexの前にもう1つの固定資格情報を加え、
 * 正しい`Authorization: Basic`ヘッダを同じ署名Cookieに交換する。だからHostに
 * ある他の通信、つまり`/api`ブリッジとすべてのWebSocketは、既存のCookie認証の
 * ままで動き続ける。
 *
 * DSH 0.2.2-rc.3で`ctx.connection.authorizeIndex`と`authenticatedUrl`が
 * Token Providerへ移った。このプラグインは
 * `@deepseek-ai/dsh-host-authentication-token`の`src/browser-auth.ts`から
 * BrowserAuthを直接使い、Token Providerと同じ署名鍵とCookie形式を共有する。
 * このモジュールはパッケージの公開APIではないため、DSHの更新で壊れる可能性がある。
 *
 * DSH本体のclient-connectionを書き換えない理由：配布パッケージへのpatchは、
 * DSHの内部をアップグレードのたびに追いかけなければならず、そもそもチェックアウトが
 * 読み取り専用だと適用できない。
 */

import { createHash, timingSafeEqual } from 'node:crypto'

/** Cordisがプラグインを識別する名前。 */
export const name = 'dsh-basic-auth'

/** indexルートを登録する前に必要なサービス。 */
export const inject = ['webServer', 'connection', 'connection.authentication', 'webApp', 'credentials']

/**
 * Token Providerと同じCookie寿命。
 * Cookieの形式と署名鍵を共有するので、値も揃える。
 */
const COOKIE_MAX_AGE_DAYS = 30

const DEFAULT_USERNAME = 'dsh'
const DEFAULT_REALM = 'DeepSeek Harness'
const BASIC_CREDENTIAL = /^Basic[ \t]+([A-Za-z0-9+/=]+)$/iu
const INDEX_URL = 'http://dsh.invalid/index.html'
const TOKEN_PROBE_URL = 'http://dsh.invalid/'
const TEXT_HEADERS = { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' }

/** URL表示済みのroot context。プラグインは同じroot contextでもう一度適用され得る。 */
const ANNOUNCED = new WeakSet()

/**
 * `/`にBasic認証ゲートを組み込む。
 * @param ctx - このゲートが必要とするWebサービスを載せたCordis context。
 * @param config - 生のプラグイン設定。{@link resolveSettings}を参照。
 */
export async function apply(ctx, config) {
  const settings = resolveSettings(config ?? {})
  const { BrowserAuth } = await import('@deepseek-ai/dsh-host-authentication-token/src/browser-auth.ts')
  const { Context } = await import('@deepseek-ai/cordis')
  const rootContext = ctx[Context.root]
  const auth = await BrowserAuth.create(rootContext, ctx.credentials, COOKIE_MAX_AGE_DAYS)
  const handle = createIndexHandler(ctx, settings, auth)
  // WebServerの既定はrequiredなので、Basic認証を自前で処理する
  // このルートはanonymousを明示する
  ctx.effect(
    () => ctx.webServer.register({ kind: 'exact', path: '/', resource: handle, auth: 'anonymous' }),
    'dsh-basic-auth: index gate',
  )
  announce(ctx, settings, auth, rootContext)
}

/**
 * プラグイン設定を正規化して検証する。
 *
 * パスワードが未設定か空のときはBasic認証を無効にし、DSH本来のトークン方式の
 * ままにする。環境変数のタイポが、パスワードを想定した構成を静かに弱めない
 * ためである。
 * @param config - 生のオーバーレイ・設定オブジェクト。
 * @returns 検証済み設定と、Basic認証が有効かどうか。
 */
export function resolveSettings(config) {
  const username = config.username ?? DEFAULT_USERNAME
  const password = config.password ?? process.env.DSH_WEB_PASSWORD ?? ''
  const realm = config.realm ?? DEFAULT_REALM
  if (typeof username !== 'string' || username.length === 0 || username.includes(':')) {
    throw new Error('dsh-basic-auth: username must be a non-empty string without ":"')
  }
  if (typeof password !== 'string') {
    throw new Error('dsh-basic-auth: password must be a string when set')
  }
  if (typeof realm !== 'string' || realm.length === 0 || /["\\\u0000-\u001f\u007f]/u.test(realm)) {
    throw new Error('dsh-basic-auth: realm must be a non-empty string without quotes, backslashes, or control characters')
  }
  return { username, password, realm, enabled: password.length > 0 }
}

/**
 * `/`のresourceを作る。トークン交換、Cookieによる通過、その後にBasicの順に判定する。
 * @param ctx - Webサービスを載せたCordis context。
 * @param settings - {@link resolveSettings}が返した検証済み設定。
 * @param auth - Token Providerと同じCookieを発行するBrowserAuth。
 * @returns `/`のGETとHEADに応じるwebserver resource。
 */
export function createIndexHandler(ctx, settings, auth) {
  const readIndex = (request) => {
    // `/index.html`は静的fallbackルートの処理対象で、このexactルートには来ない。
    // そのためindexの読み出しが自分自身に再帰しない
    const method = request.method === 'HEAD' ? 'HEAD' : 'GET'
    return ctx.webServer.readResource(
      new Request(INDEX_URL, { method }),
      ctx.connection.browserPeer,
    )
  }

  const tokenExchange = (request) => captureAuthorizeIndex(
    ctx,
    auth,
    { method: request.method, url: request.url, headers: request.headers },
    () => readIndex(request),
  )

  const mintCookie = (headers) => {
    const tokenUrl = new URL(auth.authenticatedUrl(TOKEN_PROBE_URL))
    const token = tokenUrl.searchParams.get('token')
    if (token === null) return undefined
    const exchange = captureAuthorizeIndex(
      ctx,
      auth,
      { method: 'GET', url: `/?${new URLSearchParams({ token }).toString()}`, headers },
      () => undefined,
    )
    if (exchange === undefined || exchange.status !== 303) return undefined
    const cookie = exchange.headers.get('set-cookie')
    return cookie === null ? undefined : cookie
  }

  return async function handleIndex(request) {
    // 印刷されたものやブックマークされた`?token=` URLは、従来どおりに通す
    if (new URL(request.url).searchParams.has('token')) return tokenExchange(request)

    const admission = ctx.connection.admit({ headers: request.headers })
    if ('peer' in admission) return readIndex(request)
    // 403はHost/Originのフェンス。Basic認証では直せない
    if (admission.rejection === 403) return forbidden()

    // パスワードが設定されていないとき、このプラグインは素通しにする。
    // indexの401をBasicで置き換えず、DSH本来のトークン方式のままで出す
    if (!settings.enabled) return tokenExchange(request)

    if (!matchesBasicCredential(request.headers.get('authorization'), settings)) {
      return unauthorized(settings, request.method === 'HEAD')
    }
    const cookie = mintCookie(request.headers)
    if (cookie === undefined) return unauthorized(settings, request.method === 'HEAD')
    // indexはCookieと同じレスポンスで返す。ここで303を返すと、ブラウザは
    // Set-Cookieを保存した後にもう一度`/`へ取りに来る。Set-Cookieの保存が
    // 遅い・拒否される環境では、Basicチャレンジとリダイレクトの間でループする
    // （ERR_TOO_MANY_REDIRECTS）
    return withCookie(await readIndex(request), cookie)
  }
}

/**
 * Token Providerのindex認証を実行し、そのwriteHead/end応答を
 * FetchのResponseとして受け取る。
 * @param ctx - `webServer`を載せたCordis context。
 * @param auth - Token Providerと同じCookieを発行するBrowserAuth。
 * @param request - indexリクエストのmethod、url、headers。
 * @param onAdmitted - リクエストが通ったときの戻り値。
 * @returns 受け取った応答。通ったときは`onAdmitted()`の結果。
 */
function captureAuthorizeIndex(ctx, auth, request, onAdmitted) {
  let status = 401
  let headers = new Headers()
  let body
  const admitted = auth.authorizeIndex(request, {
    writeHead(nextStatus, nextHeaders) {
      status = nextStatus
      headers = new Headers(nextHeaders)
    },
    end(text) {
      body = text
    },
  }, ctx.webServer.protocol === 'https:')
  if (admitted) return onAdmitted()
  return new Response(body, { status, headers })
}

/**
 * index応答に、発行したばかりのセッションCookieを付けて返し直す。
 * @param response - fallbackルートから届いたindex応答。
 * @param cookie - Token Providerが発行した`Set-Cookie`の値。
 * @returns 同じbodyに`set-cookie`と`cache-control: no-store`を載せた応答。
 */
function withCookie(response, cookie) {
  const headers = new Headers(response.headers)
  headers.append('set-cookie', cookie)
  headers.set('cache-control', 'no-store')
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  })
}

/**
 * リクエストのBasic資格情報を設定値と比較する。
 * @param headerValue - 生の`Authorization`ヘッダ。存在しないこともある。
 * @param settings - {@link resolveSettings}が返した検証済み設定。
 * @returns ユーザー名とパスワードの両方が一致したときだけtrue。
 */
export function matchesBasicCredential(headerValue, settings) {
  const credential = parseBasicCredential(headerValue)
  if (credential === undefined) return false
  const username = constantTimeMatches(credential.username, settings.username)
  const password = constantTimeMatches(credential.password, settings.password)
  // ビット演算の`&`で両方の比較を必ず評価する。`&&`だとユーザー名が違うときに
  // パスワード比較が短絡し、タイミングオラクルになる
  return (username & password) === 1
}

/**
 * RFC 7617のBasic資格情報を1つデコードする。
 * @param headerValue - 生の`Authorization`ヘッダ。存在しないこともある。
 * @returns ユーザー名とパスワード。Basicでないヘッダにはundefined。
 */
export function parseBasicCredential(headerValue) {
  if (typeof headerValue !== 'string') return undefined
  const match = BASIC_CREDENTIAL.exec(headerValue)
  if (match === null) return undefined
  const decoded = Buffer.from(match[1], 'base64').toString('utf8')
  const separator = decoded.indexOf(':')
  if (separator === -1) return undefined
  return { username: decoded.slice(0, separator), password: decoded.slice(separator + 1) }
}

/**
 * 実行時間で長さや中身を漏らさずに、2つの秘密を比較する。
 * @param actual - クライアントが送った値。
 * @param expected - 設定値。
 * @returns 値が一致したときtrue。
 */
export function constantTimeMatches(actual, expected) {
  const left = createHash('sha256').update(actual, 'utf8').digest()
  const right = createHash('sha256').update(expected, 'utf8').digest()
  return timingSafeEqual(left, right)
}

/**
 * 認証がないリクエストにBasicチャレンジで応じる。
 * @param settings - realmを持つ検証済み設定。
 * @param head - HEADリクエストのときtrueで、応答からbodyを省く。
 * @returns 401応答。
 */
function unauthorized(settings, head) {
  return new Response(head ? null : 'dsh web authentication required\n', {
    status: 401,
    headers: {
      ...TEXT_HEADERS,
      'www-authenticate': `Basic realm="${settings.realm}", charset="UTF-8"`,
    },
  })
}

/** Host/Originのフェンスに拒否されたリクエストへの応答。 */
function forbidden() {
  return new Response('forbidden\n', { status: 403, headers: TEXT_HEADERS })
}

/**
 * Loaderツリーの準備ができたら、トークンなしのURLとBasic認証のユーザー名を
 * 表示する。
 *
 * `web-runtime`は`printUrl`を止めない限りトークン付きURLを表示する。
 * このプラグインが同梱するpatchはそれを止め、オペレーターへ届く表示を1行にする。
 * Loaderを待つのは、`/api`ルートの持ち主と表示の順序で競合しないためで、
 * `web-app`がLoaderを待つのと同じ理由である。
 * @param ctx - `webApp`とLoaderを載せたCordis context。
 * @param settings - どちらのURL形を表示するかを決める検証済み設定。
 * @param auth - トークン付きURLを作るBrowserAuth。
 * @param rootContext - URL表示済みかどうかを覚えるroot context。
 */
function announce(ctx, settings, auth, rootContext) {
  const ready = () => {
    if (ANNOUNCED.has(rootContext)) return
    ANNOUNCED.add(rootContext)
    const url = ctx.webApp.getAdvertisedUrl()
    console.log(`dsh web: ${settings.enabled ? url : auth.authenticatedUrl(url)}`)
    if (settings.enabled) {
      console.log(`dsh web: HTTP Basic authentication is enabled for user ${JSON.stringify(settings.username)}`)
    }
  }
  const loader = ctx.get('loader')
  if (loader === undefined) {
    ready()
    return
  }
  void loader.await().then(() => {
    if (ctx.get('webServer') !== undefined && ctx.get('connection') !== undefined) ready()
  }).catch(() => {
    // 起動は失敗を自前で報告する。死んだサーバーがURLを表示してはいけない
  })
}
