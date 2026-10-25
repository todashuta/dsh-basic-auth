/**
 * dsh-basic-auth — an HTTP Basic authentication gate in front of the DSH Web
 * GUI's index route.
 *
 * DSH already authenticates browsers with a per-process launch token that it
 * exchanges for a signed cookie. This plugin adds a second, stable credential
 * in front of the index: a correct `Authorization: Basic` header is exchanged
 * for that same signed cookie, so the rest of the Host (the `/api` bridge and
 * every WebSocket) keeps its existing cookie authentication unchanged.
 *
 * The plugin is a single ES module whose only runtime import is `node:crypto`,
 * so it can live outside the DSH checkout and be loaded from an absolute
 * `file://` URL in a `--patch` overlay.
 *
 * Why not modify `@deepseek-ai/dsh-client-connection` instead: a patch to the
 * shipped package has to track DSH internals across upgrades and cannot be
 * applied when the checkout is read-only. The price is that the cookie is
 * minted by calling `ctx.connection.authorizeIndex()` with a synthetic token
 * request — an API DSH exposes for the index route, not a public
 * authentication-extension point. A future DSH change could break it.
 */

import { createHash, timingSafeEqual } from 'node:crypto'

/** Stable Cordis plugin name. */
export const name = 'dsh-basic-auth'

/** Services required before the index route can be claimed. */
export const inject = ['webServer', 'connection', 'webApp']

const DEFAULT_USERNAME = 'dsh'
const DEFAULT_REALM = 'DeepSeek Harness'
const BASIC_CREDENTIAL = /^Basic[ \t]+([A-Za-z0-9+/=]+)$/iu
const INDEX_URL = 'http://dsh.invalid/index.html'
const TOKEN_PROBE_URL = 'http://dsh.invalid/'
const TEXT_HEADERS = { 'cache-control': 'no-store', 'content-type': 'text/plain; charset=utf-8' }

/** One browser session per Host context has already printed its URL. */
const ANNOUNCED = new WeakSet()

/**
 * Mount the Basic authentication gate on `/`.
 * @param ctx - Cordis context carrying the Web services this gate needs.
 * @param config - raw plugin config; see {@link resolveSettings}.
 */
export function apply(ctx, config) {
  const settings = resolveSettings(config ?? {})
  const handle = createIndexHandler(ctx, settings)
  ctx.effect(
    () => ctx.webServer.register({ kind: 'exact', path: '/', resource: handle }),
    'dsh-basic-auth: index gate',
  )
  announce(ctx, settings)
}

/**
 * Normalize and validate the plugin config.
 *
 * An absent or empty password disables Basic authentication and leaves the
 * launch-token flow exactly as DSH ships it; that is the safe default because
 * a typo in an environment variable must not silently weaken a deployment
 * that expected a password.
 * @param config - raw overlay/config object.
 * @returns validated settings plus whether Basic authentication is enabled.
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
 * Build the `/` resource: token exchange, cookie admission, then Basic.
 * @param ctx - Cordis context carrying the Web services.
 * @param settings - validated settings from {@link resolveSettings}.
 * @returns a webserver resource answering GET and HEAD on `/`.
 */
export function createIndexHandler(ctx, settings) {
  const readIndex = (request) => {
    // `/index.html` reaches the fallback seat (frontend-static), never this
    // exact route, so the read cannot recurse into itself.
    const method = request.method === 'HEAD' ? 'HEAD' : 'GET'
    return ctx.webServer.readResource(
      new Request(INDEX_URL, { method }),
      ctx.connection.browserPeer,
    )
  }

  const tokenExchange = (request) => captureAuthorizeIndex(
    ctx,
    { method: request.method, url: request.url, headers: request.headers },
    () => readIndex(request),
  )

  const mintCookie = (headers) => {
    const tokenUrl = new URL(ctx.connection.authenticatedUrl(TOKEN_PROBE_URL))
    const token = tokenUrl.searchParams.get('token')
    if (token === null) return undefined
    const exchange = captureAuthorizeIndex(
      ctx,
      { method: 'GET', url: `/?${new URLSearchParams({ token }).toString()}`, headers },
      () => undefined,
    )
    if (exchange === undefined || exchange.status !== 303 || !exchange.headers.has('set-cookie')) {
      return undefined
    }
    return exchange
  }

  return async function handleIndex(request) {
    // A printed or bookmarked `?token=` URL must keep working unchanged.
    if (new URL(request.url).searchParams.has('token')) return tokenExchange(request)

    const admission = ctx.connection.admit({ headers: request.headers })
    if ('peer' in admission) return readIndex(request)
    // 403 is the Host/Origin fence; Basic authentication cannot fix it.
    if (admission.rejection === 403) return forbidden()

    // Without a configured password this plugin is a pass-through: the index
    // keeps DSH's token-only 401 instead of advertising a second scheme.
    if (!settings.enabled) return tokenExchange(request)

    if (!matchesBasicCredential(request.headers.get('authorization'), settings)) {
      return unauthorized(settings, request.method === 'HEAD')
    }
    return mintCookie(request.headers) ?? unauthorized(settings, request.method === 'HEAD')
  }
}

/**
 * Run Connection's index authentication and capture its writeHead/end
 * response as a Fetch response.
 * @param ctx - Cordis context carrying `connection`.
 * @param request - index request facts (method, url, headers).
 * @param onAdmitted - result when Connection admits the request.
 * @returns the captured response, or `onAdmitted()` when admitted.
 */
function captureAuthorizeIndex(ctx, request, onAdmitted) {
  let status = 401
  let headers = new Headers()
  let body
  const admitted = ctx.connection.authorizeIndex(request, {
    writeHead(nextStatus, nextHeaders) {
      status = nextStatus
      headers = new Headers(nextHeaders)
    },
    end(text) {
      body = text
    },
  })
  if (admitted) return onAdmitted()
  return new Response(body, { status, headers })
}

/**
 * Compare the request's Basic credential with the configured one.
 * @param headerValue - raw `Authorization` header, when present.
 * @param settings - validated settings from {@link resolveSettings}.
 * @returns true only when both the user name and password match.
 */
export function matchesBasicCredential(headerValue, settings) {
  const credential = parseBasicCredential(headerValue)
  if (credential === undefined) return false
  const username = constantTimeMatches(credential.username, settings.username)
  const password = constantTimeMatches(credential.password, settings.password)
  // Bitwise `&` evaluates both comparisons; `&&` would short-circuit the
  // password check on a wrong user name and turn it into a timing oracle.
  return (username & password) === 1
}

/**
 * Decode one RFC 7617 Basic credential.
 * @param headerValue - raw `Authorization` header, when present.
 * @returns the user name and password, or undefined for a non-Basic header.
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
 * Compare two secrets without leaking their length or contents through timing.
 * @param actual - value supplied by the client.
 * @param expected - configured value.
 * @returns true when the values are equal.
 */
export function constantTimeMatches(actual, expected) {
  const left = createHash('sha256').update(actual, 'utf8').digest()
  const right = createHash('sha256').update(expected, 'utf8').digest()
  return timingSafeEqual(left, right)
}

/**
 * Answer an unauthenticated request with a Basic challenge.
 * @param settings - validated settings carrying the realm.
 * @param head - whether the request method was HEAD (omit the body).
 * @returns the 401 response.
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

/** Answer a request the Host/Origin fence refused. */
function forbidden() {
  return new Response('forbidden\n', { status: 403, headers: TEXT_HEADERS })
}

/**
 * Print the clean URL (and the user name) once the Loader tree is ready.
 *
 * `web-runtime` prints the tokenized URL unless its `printUrl` is disabled;
 * the overlay this plugin ships turns that off so exactly one line reaches the
 * operator. Announcing before Loader settlement would race the /api route
 * owner, which is the same readiness reason `web-app` waits.
 * @param ctx - Cordis context carrying `webApp` and the Loader.
 * @param settings - validated settings deciding which URL form to print.
 */
function announce(ctx, settings) {
  const ready = () => {
    const root = ctx.root ?? ctx
    if (ANNOUNCED.has(root)) return
    ANNOUNCED.add(root)
    const url = ctx.webApp.getAdvertisedUrl()
    console.log(`dsh web: ${settings.enabled ? url : ctx.connection.authenticatedUrl(url)}`)
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
    // Boot reports its own failure; a dead server must not print a URL.
  })
}
