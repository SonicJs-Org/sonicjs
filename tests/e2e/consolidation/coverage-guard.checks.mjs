import { test } from 'node:test'
import assert from 'node:assert/strict'
import { fileURLToPath } from 'node:url'
import { compareMultisets, statementInventory } from './coverage-guard.mjs'

test('multiplicities detect removal even when another title is duplicated', () => {
  assert.throws(() => compareMultisets(['a', 'a', 'b'], ['a', 'b', 'b']), /coverage/)
  compareMultisets(['a', 'b', 'a'], ['a', 'a', 'b'])
})

test('AST inventory preserves dynamic declarations, assertions, skips, locks and timeout', () => {
  const source = `const test = base.extend({ owned: async ({}, use) => use('id') });
  test.describe('isolated @lock-state', () => {
    test.beforeEach(async () => prepare());
    for (const mode of ['a', 'b']) test(mode, async () => {
      test.setTimeout(123); test.skip(remote, 'local only'); expect(await read(mode)).toBe(mode);
    });
  });`
  const original = statementInventory(source)
  assert.deepEqual(original, statementInventory('// comment\n' + source.replaceAll(';', ';\n')))
  for (const mutated of [source.replace('toBe(mode)', 'toBeTruthy()'), source.replace('123', '124'), source.replace('@lock-state', '@lock-other'), source.replace("test.skip(remote, 'local only');", ''), source.replace('base.extend', 'other.extend'), source.replace('beforeEach', 'beforeAll')]) {
    assert.notDeepEqual(original, statementInventory(mutated))
  }
})

// Exercise the actual verifier with in-memory files: never mutate live .ts sources.
const fixture = () => {
  const helper = 'function uniqueEmail(prefix: string): string { return `${prefix}@example.com`; }'
  const imports = "import { test as base, expect, type Page } from './fixtures';"
  const body = `const test = base.extend({ owned: async ({}, use) => use('id') });
    test.describe.configure({ mode: 'serial' });
    test.beforeEach(async () => prepare());
    test.describe('group @lock-state', () => {
      for (const mode of ['a', 'b']) test(mode, async () => {
        test.setTimeout(123); test.skip(remote, 'local only'); expect(await read(mode)).toBe(mode);
      });
    });`
  const original = `${imports}\n${helper}\n${body}`
  const current = `import { test, test as base, expect, type Page } from './fixtures';
    import { uniqueEmail as extractedEmail } from './fixtures/auth-fixtures';
    test.describe('Source: source-a.spec.ts', () => {
      const uniqueEmail = extractedEmail;
      ${body}
    });`
  const data = { base: 'test-base', sources: [{ source: 'source-a.spec.ts', target: 'merged.spec.ts', sourceHash: createHash('sha256').update(original).digest('hex'), extracts: [{ name: 'uniqueEmail', fixture: 'fixtures/auth-fixtures.ts' }], aliases: ['const uniqueEmail = extractedEmail;'] }] }
  const files = new Map([['merged.spec.ts', current], ['fixtures/auth-fixtures.ts', `export ${helper}`]])
  return { data, files, readOriginal: () => original, readCurrent: path => files.get(path), listCurrent: () => ['merged.spec.ts'] }
}

import { createHash } from 'node:crypto'
import { verifySources, collectLeaves, verifyCollection } from './coverage-guard.mjs'

function activityPreparation() {
  const source = '68-plugin-activity-log.spec.ts'
  const body = `test('activity tab shows entries after toggling a plugin', async ({ page }) => {
    const pluginId = 'hello-world';
    await page.goto('/admin/plugins/' + pluginId);
    expect(await page.title()).toBe('Plugin');
  });`
  const installation = `
  let installedByTest = false;
  const primaryErrors: unknown[] = [];
  try {
    await page.goto(\`/admin/plugins/\${pluginId}\`);
    if (await page.getByRole('button', { name: 'Install', exact: true }).count()) {
      const installResponse = await page.request.post('/admin/plugins/install', {
        data: { name: pluginId, id: pluginId },
        headers: { Origin: new URL(page.url()).origin },
      });
      installedByTest = installResponse.ok();
      expect(installResponse.ok(), 'Activity fixture plugin installation failed').toBe(true);
    }
  `
  const cleanup = `
  } catch (error) {
    primaryErrors.push(error);
    throw error;
  } finally {
    if (installedByTest) {
      try {
        const uninstallResponse = await page.request.post(\`/admin/plugins/\${pluginId}/uninstall\`, {
          headers: { Origin: new URL(page.url()).origin },
        });
        expect(uninstallResponse.ok(), 'Activity fixture plugin cleanup failed').toBe(true);
        expect((await uninstallResponse.json()).success, 'Activity fixture plugin cleanup unsuccessful').toBe(true);
      } catch (cleanupError) {
        if (primaryErrors.length) throw new AggregateError([...primaryErrors, cleanupError], 'Activity test and plugin cleanup failed');
        throw cleanupError;
      }
    }
  }
  `
  const original = "import { test, expect } from './fixtures';\n" + body
  const current = original.split('\n')[0] + `\ntest.describe('Source: ${source}', () => {\n` + body.replace("const pluginId = 'hello-world';", "const pluginId = 'hello-world';\n" + installation).replace("toBe('Plugin');", "toBe('Plugin');\n" + cleanup) + '\n});'
  const data = { base: 'test-base', sources: [{ source, target: 'plugin-catalog.spec.ts', sourceHash: createHash('sha256').update(original).digest('hex'), preparation: 'install-activity-plugin' }] }
  return { data, readOriginal: () => original, readCurrent: () => current, listCurrent: () => ['plugin-catalog.spec.ts'], current }
}

test('activity prerequisite pins owned cleanup and preserves every original body statement', () => {
  assert.deepEqual(verifySources(activityPreparation()), { originalSpecs: 1, activeSpecs: 1 })
  for (const mutate of [
    text => text.replace("if (await page.getByRole('button', { name: 'Install', exact: true }).count())", 'if (true)'),
    text => text.replace("name: 'Install'", "name: 'Activate'"),
    text => text.replace("'/admin/plugins/install'", "'/admin/plugins/uninstall'"),
    text => text.replace(".ok(), 'Activity", ".status(), 'Activity"),
    text => text.replace("toBe('Plugin')", 'toBeTruthy()'),
    text => text.replace('if (installedByTest)', 'if (true)'),
    text => text.replace('installedByTest = installResponse.ok()', 'installedByTest = true'),
    text => text.replace('primaryErrors.push(error)', 'primaryErrors.push(cleanupError)'),
    text => text.replace('throw cleanupError;', ''),
    text => text.replace('new AggregateError([...primaryErrors, cleanupError]', 'new AggregateError([cleanupError]'),
    text => text.replace('uninstallResponse.json()).success', 'uninstallResponse.json()).error'),
    text => text.replace("toBe('Plugin');", "toBe('Plugin'); doSomething();"),
    text => text.replace("expect(await page.title()).toBe('Plugin');", ''),
    text => text.replace("'Activity fixture plugin installation failed').toBe(true)", "'Activity fixture plugin installation failed').toBe(false)"),
  ]) {
    const sample = activityPreparation()
    sample.readCurrent = () => mutate(sample.current)
    assert.throws(() => verifySources(sample), /preservation/i)
  }
  const unknown = activityPreparation()
  unknown.data.sources[0].preparation = 'skip-activity-test'
  assert.throws(() => verifySources(unknown), /preservation/i)
})

function sharedHelpers() {
  const sample = fixture()
  const original = sample.readOriginal() + "\nimport { saveNewContent } from './utils/test-helpers';"
  sample.readOriginal = () => original
  sample.data.sources[0].sourceHash = createHash('sha256').update(original).digest('hex')
  sample.data.sources[0].redirects = { saveNewContent: './fixtures/content-fixtures' }
  sample.files.set('merged.spec.ts', "import { saveNewContent } from './fixtures/content-fixtures';\n" + sample.files.get('merged.spec.ts'))
  sample.files.set('fixtures/content-fixtures.ts', "export { saveNewContent } from '../utils/test-helpers';")
  return sample
}

test('shared fixture modules preserve original helper implementations by exact re-export', () => {
  assert.deepEqual(verifySources(sharedHelpers()), { originalSpecs: 1, activeSpecs: 1 })
})

for (const [label, text] of [
  ['implementation origin', "export { saveNewContent } from '../utils/other';"],
  ['export identity', "export { other as saveNewContent } from '../utils/test-helpers';"],
  ['extra effects', "export { saveNewContent } from '../utils/test-helpers'; doSomething();"],
  ['stub', 'export async function saveNewContent() {}'],
]) test(`shared fixture rejects changed ${label}`, () => {
  const sample = sharedHelpers()
  sample.files.set('fixtures/content-fixtures.ts', text)
  assert.throws(() => verifySources(sample), /preservation|fixture|import|export/i)
})

test('actual verifier accepts scoped extended factories and validated extraction aliases', () => {
  assert.deepEqual(verifySources(fixture()), { originalSpecs: 1, activeSpecs: 1 })
})

for (const [label, mutate] of [
  ['changed hardened fixture import', text => text.replace("from './fixtures'", "from '@playwright/test'")],
  ['added outer skip hook', text => text + '\ntest.beforeEach(() => test.skip());'],
  ['unapproved outer import', text => "import { test as extra } from '@playwright/test';\n" + text],
  ['empty named side-effect import', text => "import {} from './side-effects';\n" + text],
  ['changed extracted helper module', text => text.replace("from './fixtures/auth-fixtures'", "from './fixtures/other-fixtures'")],
  ['added outer configuration', text => text + "\ntest.use({ storageState: 'other.json' });"],
  ['serial wrapper tampering', text => text.replace("test.describe('Source:", "test.describe.serial('Source:")],
  ['async wrapper tampering', text => text.replace("source-a.spec.ts', () =>", "source-a.spec.ts', async () =>")],
  ['renamed wrapper source', text => text.replace('Source: source-a.spec.ts', 'Source: renamed.spec.ts')],
  ['changed extended fixture', text => text.replace('base.extend', 'test.extend')],
  ['changed scoped configuration', text => text.replace("mode: 'serial'", "mode: 'parallel'")],
  ['changed scoped hook', text => text.replace('beforeEach', 'beforeAll')],
  ['changed assertion', text => text.replace('toBe(mode)', 'toBeTruthy()')],
  ['removed skip condition', text => text.replace("test.skip(remote, 'local only');", '')],
  ['changed test timeout', text => text.replace('setTimeout(123)', 'setTimeout(124)')],
  ['changed inherited lock', text => text.replace('@lock-state', '@lock-other')],
  ['changed extraction alias', text => text.replace('uniqueEmail = extractedEmail', 'uniqueEmail = expect')],
  ['extra executable fixture statement', text => text],
]) {
  test(`actual verifier rejects ${label}`, () => {
    const sample = fixture()
    if (label === 'extra executable fixture statement') sample.files.set('fixtures/auth-fixtures.ts', sample.files.get('fixtures/auth-fixtures.ts') + '\nprocess.env.CI = "";')
    else sample.files.set('merged.spec.ts', mutate(sample.files.get('merged.spec.ts')))
    assert.throws(() => verifySources(sample), /preservation|import|wrapper|alias|fixture|outer/i)
  })
}

test('actual verifier rejects unapproved alias metadata and moved target ownership', () => {
  const sample = fixture()
  sample.data.sources[0].aliases.push('test.beforeEach(() => test.skip());')
  sample.files.set('merged.spec.ts', sample.files.get('merged.spec.ts').replace('const uniqueEmail = extractedEmail;', 'const uniqueEmail = extractedEmail;\ntest.beforeEach(() => test.skip());'))
  assert.throws(() => verifySources(sample), /alias/i)
  const moved = fixture()
  moved.listCurrent = () => ['renamed.spec.ts']
  assert.throws(() => verifySources(moved), /target|coverage|missing/i)
})

const report = (file, annotationFile, wrapped = false) => ({ suites: [{ title: file, file, line: 0, specs: [], suites: [{ title: wrapped ? 'Source: source-a.spec.ts' : 'group', file, line: 5, specs: [{ file, title: 'case', tags: ['lock-state'], tests: [{ projectName: 'chromium', timeout: 123, expectedStatus: 'skipped', annotations: [{ type: 'skip', description: 'local only', location: { file: annotationFile, line: 6, column: 3 } }] }] }], suites: [] }] }] })

test('collection preserves annotation meaning across checkout roots and moved spec paths', () => {
  const data = fixture().data
  const before = report('source-a.spec.ts', '/old/checkout/tests/e2e/source-a.spec.ts')
  const after = report('merged.spec.ts', 'C:\\new\\checkout\\tests\\e2e\\merged.spec.ts', true)
  // Keep the logical suite identical; the extra source scope is structural only.
  after.suites[0].suites[0].suites = [{ ...after.suites[0].suites[0], title: 'group', suites: [] }]
  after.suites[0].suites[0].specs = []
  compareMultisets(collectLeaves(before, data), collectLeaves(after, data))
  for (const change of [t => { t.timeout = 124 }, t => { t.annotations[0].description = 'different reason' }, t => { t.annotations[0].type = 'fixme' }]) {
    const changed = structuredClone(after)
    change(changed.suites[0].suites[0].suites[0].specs[0].tests[0])
    assert.throws(() => compareMultisets(collectLeaves(before, data), collectLeaves(changed, data)), /coverage/)
  }
  const tampered = structuredClone(after)
  tampered.suites[0].suites[0].title = 'Source: renamed.spec.ts'
  assert.throws(() => collectLeaves(tampered, data), /source|ownership|mapping/i)
})

test('collection uses baseline-equivalent environment independently of caller CI and BASE_URL', () => {
  let called = false
  const data = fixture().data
  const sample = report('source-a.spec.ts', '/checkout/tests/e2e/source-a.spec.ts')
  const baseline = collectLeaves(sample, data)
  const result = verifyCollection({ data, baseline, environment: { CI: 'true', BASE_URL: 'https://remote.invalid', E2E_REUSE_SERVER: '1', PATH: '/original/path' }, execute: (binary, args, options) => {
    called = true
    assert.equal(binary, process.execPath)
    assert.equal(args[0], fileURLToPath(new URL('../../../node_modules/playwright/cli.js', import.meta.url)))
    assert.equal(options.env.CI, undefined)
    assert.equal(options.env.BASE_URL, undefined)
    assert.equal(options.env.E2E_REUSE_SERVER, undefined)
    assert.equal(options.env.PATH, '/original/path')
    assert.ok(args.includes('--list'))
    return JSON.stringify(sample)
  } })
  assert.equal(called, true)
  assert.deepEqual(result, { collected: 1 })
})


test('standalone verification rejects changed imports and added executable statements', () => {
  const sample = fixture()
  const original = sample.readOriginal()
  sample.listCurrent = () => ['source-a.spec.ts']
  sample.files.set('source-a.spec.ts', original)
  assert.deepEqual(verifySources(sample), { originalSpecs: 1, activeSpecs: 1 })
  sample.files.set('source-a.spec.ts', original.replace("from './fixtures'", "from '@playwright/test'"))
  assert.throws(() => verifySources(sample), /standalone imports\/body/)
  sample.files.set('source-a.spec.ts', original + '\ntest.beforeEach(() => test.skip());')
  assert.throws(() => verifySources(sample), /standalone imports\/body/)
})


test('extraction alias metadata cannot authorize a different imported implementation', () => {
  const sample = fixture()
  sample.data.sources[0].aliases = ['const uniqueEmail = expect;']
  sample.files.set('merged.spec.ts', sample.files.get('merged.spec.ts').replace('uniqueEmail = extractedEmail', 'uniqueEmail = expect'))
  assert.throws(() => verifySources(sample), /import alias origin/)
})


test('extracted helper implementation must retain its export and exported name', () => {
  for (const change of [text => text.replace('export function', 'function'), text => text.replace('function uniqueEmail', 'function renamedEmail')]) {
    const sample = fixture()
    sample.files.set('fixtures/auth-fixtures.ts', change(sample.files.get('fixtures/auth-fixtures.ts')))
    assert.throws(() => verifySources(sample), /fixture|export/i)
  }
})
