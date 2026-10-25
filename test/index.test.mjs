import assert from 'node:assert/strict'
import test from 'node:test'
import {
  constantTimeMatches,
  createIndexHandler,
  matchesBasicCredential,
  parseBasicCredential,
  resolveSettings,
} from '../src/index.mjs'

const SETTINGS = { username: 'dsh', password: 's3cret', realm: 'DSH', enabled: true }

function basic(username, password) {
  return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
}

function fixture(overrides = {}) {
  const state = { ...overrides }
  const ctx = {
    root: {},
    get: () => undefined,
    effect(fn) { return fn() },
    webServer: {
      register(route) {
        state.registered = route
        return () => {}
      },
      readResource(request, peer) {
        state.read = { request, peer }
        return Promise.resolve(new Response('<html>index</html>', {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        }))
      },
    },
    connection: {
      admit(request) {
        return state.admit === undefined ? { rejection: 401 } : state.admit(request)
      },
      authorizeIndex(request, response) {
        if (state.authorizeIndex !== undefined) return state.authorizeIndex(request, response)
        response.writeHead(401, { 'content-type': 'text/plain; charset=utf-8' })
        response.end('unauthorized\n')
        return false
      },
      authenticatedUrl(base) { return `${base}?token=test-token` },
      browserPeer: { id: 'browser' },
    },
    webApp: { getAdvertisedUrl: () => 'http://localhost:3080/' },
  }
  return { ctx, state }
}

test('resolveSettings defaults to the token-only flow', () => {
  const saved = process.env.DSH_WEB_PASSWORD
  delete process.env.DSH_WEB_PASSWORD
  try {
    assert.deepEqual(resolveSettings({}), {
      username: 'dsh',
      password: '',
      realm: 'DeepSeek Harness',
      enabled: false,
    })
  } finally {
    if (saved === undefined) delete process.env.DSH_WEB_PASSWORD
    else process.env.DSH_WEB_PASSWORD = saved
  }
})

test('resolveSettings reads DSH_WEB_PASSWORD', () => {
  const saved = process.env.DSH_WEB_PASSWORD
  process.env.DSH_WEB_PASSWORD = 'env-secret'
  try {
    const settings = resolveSettings({})
    assert.equal(settings.password, 'env-secret')
    assert.equal(settings.enabled, true)
  } finally {
    if (saved === undefined) delete process.env.DSH_WEB_PASSWORD
    else process.env.DSH_WEB_PASSWORD = saved
  }
})

test('resolveSettings rejects a colon in the user name', () => {
  assert.throws(() => resolveSettings({ username: 'a:b', password: 'x' }), /without ":"/u)
})

test('resolveSettings rejects a quote in the realm', () => {
  assert.throws(() => resolveSettings({ realm: 'a"b', password: 'x' }), /realm/u)
})

test('parseBasicCredential decodes an RFC 7617 credential', () => {
  assert.deepEqual(parseBasicCredential(basic('alice', 's3cret')), { username: 'alice', password: 's3cret' })
  assert.equal(parseBasicCredential('Bearer abc'), undefined)
  assert.equal(parseBasicCredential(undefined), undefined)
  assert.equal(parseBasicCredential(`Basic ${Buffer.from('nocolon').toString('base64')}`), undefined)
})

test('matchesBasicCredential requires both halves', () => {
  assert.equal(matchesBasicCredential(basic('dsh', 's3cret'), SETTINGS), true)
  assert.equal(matchesBasicCredential(basic('dsh', 'wrong'), SETTINGS), false)
  assert.equal(matchesBasicCredential(basic('bob', 's3cret'), SETTINGS), false)
})

test('constantTimeMatches compares two secrets', () => {
  assert.equal(constantTimeMatches('a', 'a'), true)
  assert.equal(constantTimeMatches('a', 'b'), false)
  assert.equal(constantTimeMatches('a', 'a'.repeat(1000)), false)
})

test('an admitted cookie reads the index', async () => {
  const { ctx, state } = fixture({ admit: () => ({ peer: { id: 'browser' } }) })
  const handle = createIndexHandler(ctx, SETTINGS)
  const response = await handle(new Request('http://x/'))
  assert.equal(response.status, 200)
  assert.equal(await response.text(), '<html>index</html>')
  assert.equal(state.read.peer.id, 'browser')
  assert.equal(state.read.request.url, 'http://dsh.invalid/index.html')
})

test('a valid Basic credential mints the signed cookie', async () => {
  const { ctx, state } = fixture({
    authorizeIndex(request, response) {
      assert.match(request.url, /^\/\?token=test-token$/u)
      response.writeHead(303, {
        location: './',
        'set-cookie': 'dsh-auth-test=session',
      })
      response.end()
      return false
    },
  })
  const handle = createIndexHandler(ctx, SETTINGS)
  const response = await handle(new Request('http://x/', {
    headers: { authorization: basic('dsh', 's3cret') },
  }))
  assert.equal(response.status, 303)
  assert.equal(response.headers.get('set-cookie'), 'dsh-auth-test=session')
  assert.equal(response.headers.get('location'), './')
  assert.equal(state.read, undefined)
})

test('a wrong Basic credential answers 401 with a challenge', async () => {
  const { ctx } = fixture()
  const handle = createIndexHandler(ctx, SETTINGS)
  const response = await handle(new Request('http://x/', {
    headers: { authorization: basic('dsh', 'wrong') },
  }))
  assert.equal(response.status, 401)
  assert.match(response.headers.get('www-authenticate'), /^Basic realm="DSH", charset="UTF-8"$/u)
  assert.match(await response.text(), /authentication required/u)
})

test('a launch-token URL keeps its 303 flow', async () => {
  const { ctx } = fixture({
    authorizeIndex(request, response) {
      assert.equal(request.url, 'http://x/?token=legacy')
      response.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-test=session' })
      response.end()
      return false
    },
  })
  const handle = createIndexHandler(ctx, SETTINGS)
  const response = await handle(new Request('http://x/?token=legacy'))
  assert.equal(response.status, 303)
})

test('without a password the handler delegates to the token flow', async () => {
  const { ctx, state } = fixture()
  const handle = createIndexHandler(ctx, { ...SETTINGS, password: '', enabled: false })
  const response = await handle(new Request('http://x/'))
  assert.equal(response.status, 401)
  assert.equal(response.headers.get('www-authenticate'), null)
  assert.equal(state.read, undefined)
})

test('the Host/Origin fence stays a 403', async () => {
  const { ctx } = fixture({ admit: () => ({ rejection: 403 }) })
  const handle = createIndexHandler(ctx, SETTINGS)
  const response = await handle(new Request('http://x/'))
  assert.equal(response.status, 403)
  assert.equal(await response.text(), 'forbidden\n')
})

test('HEAD omits the challenge body', async () => {
  const { ctx } = fixture()
  const handle = createIndexHandler(ctx, SETTINGS)
  const response = await handle(new Request('http://x/', { method: 'HEAD' }))
  assert.equal(response.status, 401)
  assert.equal(await response.text(), '')
})
