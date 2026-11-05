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

for (const initial of ['missing', 'active', 'inactive']) test(`activity prerequisite preserves ${initial} starting state and toggle branch`, async () => {
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
    not: { toContainText: text => assert.equal(actual.text.includes(text), false) },
  })
  await vm.runInNewContext(callback, { expect, URL })({ page })
  assert.equal(events.filter(event => event === 'install').length, Number(initial === 'missing'))
  assert.equal(events[0], 'detail', 'observe original detail before installing')
  assert.deepEqual(events.filter(event => ['Activate', 'Deactivate'].includes(event)), initial === 'inactive' ? ['Activate', 'Deactivate'] : ['Deactivate', 'Activate'])
  assert.equal(status, initial === 'missing' ? 'active' : initial)
})
