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
    request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/fixture@1/index.js', headers: () => ({ 'user-agent': 'test' }) }),
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
    request: () => ({ method: () => 'GET', url: () => 'https://cdn.jsdelivr.net/npm/error-fixture@1/index.js', headers: () => ({}) }),
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
    request: () => ({ method: () => 'GET', url: () => url, headers: () => ({}) }),
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
    request: () => ({ method: () => 'GET', url: () => url, headers: () => ({}) }),
    fetch: async () => { assert.fail('page-owned client must not own vendor downloads') },
    fulfill: async response => { fulfilled++; assert.equal(response.body.toString(), 'real worker bytes') },
  })
  assert.equal(fetched, 1)
  assert.equal(fulfilled, 1)
})
