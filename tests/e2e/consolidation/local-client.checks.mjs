import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

// Keep the Node checks compatible with CI versions without native TS stripping.
const source = readFileSync(new URL('../utils/local-client.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
const { localClientHeaders, prepareLocalRequest } = await import('data:text/javascript;base64,' + Buffer.from(compiled).toString('base64'))

test('local files get distinct clients; hooks and tests in one file share the limiter', () => {
  const api = localClientHeaders('http://localhost:8787', '/suite/auth-api.spec.ts', {})
  const ui = localClientHeaders('http://localhost:8787', '/suite/auth-ui.spec.ts', {})
  assert.notEqual(api['CF-Connecting-IP'], ui['CF-Connecting-IP'])
  assert.deepEqual(api, localClientHeaders('http://localhost:8787', '/suite/auth-api.spec.ts', {}))
  assert.match(api['CF-Connecting-IP'], /^2001:db8:/)
  for (const origin of ['http://127.0.0.1:8787', 'http://[::1]:8787']) {
    assert.deepEqual(api, localClientHeaders(origin, '/suite/auth-api.spec.ts', {}))
  }
})

test('API isolation sends mutations once, preserves options, and leaves external assets untouched', async () => {
  const response = { status: () => 200 }
  const calls = []
  const originalFetch = async (url, options) => { calls.push({ url, options }); return response }
  const request = {
    fetch: originalFetch,
    post(url, options) { return this.fetch(url, { ...options, method: 'POST' }) },
  }
  prepareLocalRequest(request, 'http://localhost:8787', '/suite/auth-api.spec.ts')
  const wrapped = request.fetch
  assert.equal(prepareLocalRequest(request, 'http://localhost:8787', '/suite/auth-api.spec.ts'), request)
  assert.equal(request.fetch, wrapped)
  const data = { email: 'test@example.invalid' }
  assert.equal(await request.post('/auth/login', { data, timeout: 41, headers: { Origin: 'http://localhost:8787' } }), response)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].options.data, data)
  assert.equal(calls[0].options.timeout, 41)
  assert.equal(calls[0].options.method, 'POST')
  assert.equal(calls[0].options.headers.Origin, 'http://localhost:8787')
  assert.match(calls[0].options.headers['CF-Connecting-IP'], /^2001:db8:/)
  const externalOptions = { headers: { Accept: 'text/javascript' }, timeout: 19 }
  await request.fetch('https://cdn.example/element.js', externalOptions)
  assert.equal(calls.length, 2)
  assert.equal(calls[1].options, externalOptions)
  const explicit = { headers: { 'cf-connecting-ip': '192.0.2.1' } }
  await request.fetch('/auth/login', explicit)
  assert.equal(calls[2].options, explicit)
  const remote = { fetch: originalFetch }
  assert.equal(prepareLocalRequest(remote, 'https://preview.example', '/suite/auth-api.spec.ts'), remote)
  assert.equal(remote.fetch, originalFetch)
  const configured = { fetch: originalFetch }
  prepareLocalRequest(configured, 'http://localhost:8787', '/suite/auth-api.spec.ts', { 'X-Forwarded-For': '192.0.2.2' })
  await configured.fetch('/auth/login', externalOptions)
  assert.equal(calls[3].options, externalOptions)
})

test('remote targets and explicit client headers keep their original identities', () => {
  const original = { Authorization: 'test-only-token', Accept: 'application/json' }
  assert.equal(localClientHeaders('https://preview.example', '/suite/auth-api.spec.ts', original), original)
  assert.equal(localClientHeaders('http://localhost.example', '/suite/auth-api.spec.ts', original), original)
  for (const key of ['x-forwarded-for', 'X-Forwarded-For', 'CF-Connecting-IP']) {
    const explicit = { ...original, [key]: '192.0.2.1' }
    assert.equal(localClientHeaders('http://localhost:8787', '/suite/auth-api.spec.ts', explicit), explicit)
  }
  const local = localClientHeaders('http://localhost:8787', '/suite/auth-api.spec.ts', original)
  assert.equal(local.Authorization, original.Authorization)
  assert.equal(local.Accept, original.Accept)
  assert.equal(Object.keys(original).length, 2)
})
