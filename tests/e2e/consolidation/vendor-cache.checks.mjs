import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('../utils/vendor-cache.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
const { cacheVendorAssets, isVendorAsset } = await import('data:text/javascript;base64,' + Buffer.from(compiled).toString('base64'))

test('only public vendor assets are cached; application and remote-target traffic stay native', async () => {
  for (const url of ['https://cdn.tailwindcss.com/3.4.17', 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js', 'https://unpkg.com/htmx.org@2.0.3', 'https://fonts.googleapis.com/css2?family=Inter', 'https://fonts.gstatic.com/inter.woff2']) assert.equal(isVendorAsset(new URL(url)), true)
  for (const url of ['http://localhost:8787/admin', 'http://localhost:8787/api/media', 'https://cdn.jsdelivr.net.evil/npm/x', 'https://example.com/index.js', 'https://unpkg.com/private-api', 'http://cdn.tailwindcss.com/']) assert.equal(isVendorAsset(new URL(url)), false)
  let registrations = 0
  const context = { route: async () => { registrations++ } }
  await cacheVendorAssets(context, 'https://preview.example')
  assert.equal(registrations, 0)
})

test('cache keeps real bytes, redirects and CORS headers; concurrent reads fetch once with zero retries', async () => {
  let handler, registrations = 0, fetches = 0
  const context = { once() {}, route: async (_match, callback) => { registrations++; handler = callback } }
  await cacheVendorAssets(context, 'http://localhost:8787')
  await cacheVendorAssets(context, 'http://localhost:8787')
  assert.equal(registrations, 1)
  const body = Buffer.from('export const realVendor = true;')
  const fulfilled = []
  const route = {
    request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/fixture@1/index.js', allHeaders: async () => ({ 'user-agent': 'test' }) }),
    fetch: async options => { fetches++; assert.equal(options.maxRedirects, 0); assert.equal(options.maxRetries, 0); return { status: () => 302, headers: () => ({ location: '/npm/fixture@1.0.0/index.js', 'access-control-allow-origin': '*', 'content-encoding': 'gzip', 'content-length': '100' }), body: async () => body } },
    fulfill: async options => { fulfilled.push(options) },
  }
  await Promise.all([handler(route), handler(route)])
  assert.equal(fetches, 1)
  assert.equal(fulfilled.length, 2)
  assert.equal(fulfilled[0].status, 302)
  assert.deepEqual(fulfilled[0].body, body)
  assert.equal(fulfilled[0].headers.location, '/npm/fixture@1.0.0/index.js')
  assert.equal(fulfilled[0].headers['access-control-allow-origin'], '*')
  assert.equal(fulfilled[0].headers['content-encoding'], undefined)
  assert.equal(fulfilled[0].headers['content-length'], undefined)
  let continued = 0
  await handler({ ...route, request: () => ({ method: () => 'POST' }), continue: async () => { continued++ } })
  assert.equal(continued, 1)
  assert.equal(fetches, 1)
})

test('upstream errors remain errors and are never cached as successful assets', async () => {
  let handler, fetches = 0
  const context = { once() {}, route: async (_match, callback) => { handler = callback } }
  await cacheVendorAssets(context, 'http://localhost:8787')
  const statuses = []
  const route = {
    request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/error-fixture@1/index.js', allHeaders: async () => ({}) }),
    fetch: async () => { fetches++; return { status: () => 503, headers: () => ({ 'content-type': 'text/plain' }), body: async () => Buffer.from('upstream unavailable') } },
    fulfill: async response => { statuses.push(response.status); assert.equal(response.body.toString(), 'upstream unavailable') },
  }
  await handler(route)
  assert.equal(fetches, 1)
  await handler(route)
  assert.equal(fetches, 2)
  assert.deepEqual(statuses, [503, 503])
})

test('closing a context cancels its pending fetch without poisoning the next context', async () => {
  let handler, onClose, rejectBody
  const context = { once: (_event, callback) => { onClose = callback }, route: async (_match, callback) => { handler = callback } }
  await cacheVendorAssets(context, 'http://localhost:8787')
  const url = 'https://fonts.gstatic.com/closing-context.woff2'
  const route = {
    request: () => ({ method: () => 'GET', url: () => url, allHeaders: async () => ({}) }),
    fetch: async () => ({ status: () => 200, headers: () => ({}), body: () => new Promise((_resolve, reject) => { rejectBody = reject }) }),
    fulfill: async () => { assert.fail('closed context must not be fulfilled') },
  }
  const result = handler(route)
  await new Promise(resolve => setImmediate(resolve))
  onClose()
  rejectBody(new Error('Response has been disposed'))
  await result
  let nextHandler, fetches = 0, fulfilled = 0
  await cacheVendorAssets({ once() {}, route: async (_match, callback) => { nextHandler = callback } }, 'http://localhost:8787')
  await nextHandler({ ...route,
    fetch: async () => { fetches++; return { status: () => 200, headers: () => ({}), body: async () => Buffer.from('real asset') } },
    fulfill: async response => { fulfilled++; assert.equal(response.body.toString(), 'real asset') },
  })
  assert.equal(fetches, 1)
  assert.equal(fulfilled, 1)
})

test('vendor downloads use the worker client so page teardown cannot dispose response bodies', async () => {
  let handler, fetched = 0, fulfilled = 0
  const url = 'https://cdn.jsdelivr.net/npm/worker-fixture@1/index.js'
  const client = { get: async (actual, options) => {
    fetched++; assert.equal(actual, url); assert.equal(options.maxRetries, 0); assert.equal(options.maxRedirects, 0)
    assert.equal(options.headers['accept-encoding'], 'gzip, deflate, br')
    return { status: () => 200, headers: () => ({ 'content-type': 'text/javascript' }), body: async () => Buffer.from('real worker bytes') }
  } }
  await cacheVendorAssets({ once() {}, route: async (_match, callback) => { handler = callback } }, 'http://localhost:8787', client)
  await handler({
    request: () => ({ method: () => 'GET', url: () => url, allHeaders: async () => ({}) }),
    fetch: async () => { assert.fail('page-owned client must not own vendor downloads') },
    fulfill: async response => { fulfilled++; assert.equal(response.body.toString(), 'real worker bytes') },
  })
  assert.equal(fetched, 1)
  assert.equal(fulfilled, 1)
})

function deferred() {
  let resolve, reject
  const promise = new Promise((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}

test('stale handler finally cannot delete a newer pending non-cacheable download', async () => {
  let handler, fetches = 0
  await cacheVendorAssets({ once() {}, route: async (_match, callback) => { handler = callback } }, 'http://localhost:8787')
  const firstBody = deferred(), newerBody = deferred(), slowFulfill = deferred(), slowStarted = deferred(), newerStarted = deferred()
  const route = {
    request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/pending-ownership/index.js', allHeaders: async () => ({}) }),
    fetch: async () => {
      fetches++
      const body = fetches === 1 ? firstBody.promise : newerBody.promise
      if (fetches > 1) newerStarted.resolve()
      return { status: () => 503, headers: () => ({}), body: () => body }
    },
    fulfill: async response => { assert.equal(response.status, 503) },
  }
  const fast = handler(route)
  const slow = handler({ ...route, fulfill: async response => {
    assert.equal(response.status, 503)
    slowStarted.resolve()
    await slowFulfill.promise
  } })
  firstBody.resolve(Buffer.from('first upstream failure'))
  await Promise.all([fast, slowStarted.promise])
  const newer = handler(route)
  await newerStarted.promise
  slowFulfill.resolve()
  await slow
  const follower = handler(route)
  newerBody.resolve(Buffer.from('next upstream failure'))
  await Promise.all([newer, follower])
  assert.equal(fetches, 2, 'follower must share newer download after stale handler finishes')
})

test('cache identity uses complete canonical effective forwarded headers across contexts', async () => {
  const downloads = []
  const url = 'https://cdn.jsdelivr.net/npm/representation-fixture/index.js'
  const client = { get: async (actual, options) => {
    assert.equal(actual, url)
    downloads.push(options.headers)
    return { status: () => 200, headers: () => ({ 'access-control-allow-origin': '*' }), body: async () => Buffer.from(JSON.stringify(options.headers)) }
  } }
  async function read(headers) {
    let handler, result
    await cacheVendorAssets({ once() {}, route: async (_match, callback) => { handler = callback } }, 'http://localhost:8787', client)
    await handler({
      request: () => ({ method: () => 'GET', url: () => url, headers: () => ({ 'user-agent': 'browser', accept: '*/*' }), allHeaders: async () => headers }),
      fulfill: async response => { result = response; assert.equal(response.headers['access-control-allow-origin'], '*') },
    })
    return result.body.toString()
  }
  const headers = { 'user-agent': 'browser', accept: '*/*', 'accept-language': 'en', cookie: 'vendor=one', 'x-vendor-variant': 'one', 'accept-encoding': 'browser encoding' }
  const first = await read(headers)
  assert.equal(await read(Object.fromEntries(Object.entries(headers).reverse())), first)
  assert.equal(downloads.length, 1, 'property order must not change representation identity')
  for (const [name, value] of [['accept-language', 'fr'], ['cookie', 'vendor=two'], ['x-vendor-variant', 'two']]) {
    assert.notEqual(await read({ ...headers, [name]: value }), first, name)
  }
  assert.equal(downloads.length, 4)
  assert.equal(await read({ ...headers, 'accept-encoding': 'different browser encoding' }), first, 'key reflects forced decoded-byte download encoding')
  const { cookie, ...noCookie } = headers
  await read(noCookie)
  assert.equal(downloads.at(-1).cookie, '', 'explicit empty cookie prevents worker-client cookie jar injection')
  assert.equal(downloads.at(-1)['accept-encoding'], 'gzip, deflate, br')
})

for (const [name, headers] of [
  ['wildcard Vary', { vary: 'Accept-Language, *' }],
  ['private', { 'cache-control': 'max-age=100, PRIVATE' }],
  ['no-store', { 'cache-control': 'no-store' }],
  ['Set-Cookie', { 'set-cookie': 'vendor=session; Path=/' }],
]) test(`${name} responses are delivered intact without cross-context storage`, async () => {
  let fetches = 0
  for (let index = 0; index < 2; index++) {
    let handler
    await cacheVendorAssets({ once() {}, route: async (_match, callback) => { handler = callback } }, 'http://localhost:8787')
    await handler({
      request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/nonpublic/' + name, allHeaders: async () => ({}), headers: () => ({}) }),
      fetch: async () => { fetches++; return { status: () => 200, headers: () => headers, body: async () => Buffer.from('original bytes') } },
      fulfill: async response => { assert.equal(response.status, 200); assert.deepEqual(response.headers, headers); assert.equal(response.body.toString(), 'original bytes') },
    })
  }
  assert.equal(fetches, 2)
})

test('live transport failures propagate and never populate successful-byte cache', async () => {
  let handler, fetches = 0
  const fault = new Error('real upstream transport failure')
  await cacheVendorAssets({ once() {}, route: async (_match, callback) => { handler = callback } }, 'http://localhost:8787')
  const route = {
    request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/transport-error/index.js', allHeaders: async () => ({}) }),
    fetch: async () => { fetches++; throw fault },
    fulfill: async () => assert.fail('transport failure must not become a response'),
  }
  await assert.rejects(handler(route), error => error === fault)
  await assert.rejects(handler(route), error => error === fault)
  assert.equal(fetches, 2)
})

test('context teardown during full-header retrieval cancels only its own handler', async () => {
  let handler, onClose
  const headers = deferred(), started = deferred()
  await cacheVendorAssets({ once: (_event, callback) => { onClose = callback }, route: async (_match, callback) => { handler = callback } }, 'http://localhost:8787')
  const run = handler({
    request: () => ({ method: () => 'GET', allHeaders: () => { started.resolve(); return headers.promise } }),
    fetch: async () => assert.fail('closed context must not fetch'),
    fulfill: async () => assert.fail('closed context must not fulfill'),
  })
  await started.promise
  onClose()
  headers.reject(new Error('Target page, context or browser has been closed'))
  await run
})
