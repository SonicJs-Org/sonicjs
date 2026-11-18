import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import ts from 'typescript'

const source = ts.createSourceFile('plugin-catalog.spec.ts', readFileSync(new URL('../plugin-catalog.spec.ts', import.meta.url), 'utf8'), ts.ScriptTarget.Latest, true)
const callbacks = []
function visit(node) {
  if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'test' && ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === 'activity tab shows entries after toggling a plugin') callbacks.push(node.arguments[1])
  ts.forEachChild(node, visit)
}
visit(source)
assert.equal(callbacks.length, 1)
const callback = ts.transpile(`(${callbacks[0].getText(source)})`, { target: ts.ScriptTarget.ESNext })

for (const initial of ['missing', 'active', 'inactive']) for (const failAssertion of [false, true]) for (const cleanup of (initial === 'missing' ? ['ok', 'http-error', 'unsuccessful', 'transport-error'] : ['ok'])) test(`activity prerequisite preserves ${initial} with assertion failure=${failAssertion}, cleanup=${cleanup}`, async () => {
  const primary = new Error('forced original activity assertion failure')
  const cleanupFault = new Error('forced cleanup transport failure')
  let status = initial
  const events = []
  const button = name => ({
    count: async () => Number(name === (status === 'missing' ? 'Install' : status === 'active' ? 'Deactivate' : 'Activate')),
    click: async () => {
      assert.equal(await button(name).count(), 1)
      events.push(name)
      status = name === 'Activate' ? 'active' : 'inactive'
    },
    visible: async () => Boolean(await button(name).count()),
  })
  const panel = { visible: async () => true, text: '', locator: () => ({ count: async () => 1 }), getByText: () => ({ isVisible: async () => false }) }
  const page = {
    url: () => 'http://localhost:8787/admin',
    goto: async path => { assert.equal(path, '/admin/plugins/hello-world'); events.push('detail') },
    getByRole: (role, { name, exact }) => { assert.equal(role, 'button'); assert.equal(exact, true); return button(name) },
    request: { post: async (path, options) => {
      assert.equal(options.headers.Origin, 'http://localhost:8787')
      if (path === '/admin/plugins/hello-world/uninstall') {
        assert.equal(initial, 'missing', 'never uninstall a preexisting plugin')
        events.push('uninstall')
        if (cleanup === 'transport-error') throw cleanupFault
        if (cleanup === 'ok') status = 'missing'
        return { ok: () => cleanup !== 'http-error', json: async () => ({ success: cleanup !== 'unsuccessful' }) }
      }
      assert.equal(path, '/admin/plugins/install')
      assert.deepEqual(JSON.parse(JSON.stringify(options.data)), { name: 'hello-world', id: 'hello-world' })
      events.push('install')
      // Production installPlugin explicitly activates existing inactive plugins.
      status = 'active'
      return { ok: () => true }
    } },
    locator: selector => selector === '#activity-tab' ? { click: async () => {} } : panel,
  }
  const expect = actual => ({
    toBe: expected => assert.equal(actual, expected),
    toBeVisible: async () => assert.equal(await actual.visible(), true),
    not: { toContainText: text => {
      if (failAssertion) throw primary
      assert.equal(actual.text.includes(text), false)
    } },
  })
  const run = vm.runInNewContext(callback, { expect, URL })({ page })
  if (cleanup !== 'ok') await assert.rejects(run, error => {
    const failure = failAssertion ? error.errors?.[1] : error
    if (failAssertion) {
      assert.equal(error.name, 'AggregateError')
      assert.equal(error.errors.length, 2)
      assert.equal(error.errors[0], primary, 'retain original assertion error')
    }
    if (cleanup === 'transport-error') assert.equal(failure, cleanupFault)
    else assert.equal(failure.name, 'AssertionError', 'cleanup failure must surface')
    return true
  })
  else if (failAssertion) await assert.rejects(run, error => error === primary)
  else await run
  assert.equal(events.filter(event => event === 'install').length, Number(initial === 'missing'))
  assert.equal(events[0], 'detail', 'observe original detail before installing')
  assert.deepEqual(events.filter(event => ['Activate', 'Deactivate'].includes(event)), initial === 'inactive' ? ['Activate', 'Deactivate'] : ['Deactivate', 'Activate'])
  assert.equal(events.filter(event => event === 'uninstall').length, Number(initial === 'missing'))
  assert.equal(status, initial === 'missing' && cleanup !== 'ok' ? 'active' : initial)
})
