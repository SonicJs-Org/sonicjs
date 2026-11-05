import ts from 'typescript'
import { readFileSync, readdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, resolve, posix } from 'node:path'
import { createHash } from 'node:crypto'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const printer = ts.createPrinter({ removeComments: true })
const parse = text => {
  if (typeof text !== 'string') throw new Error('Missing source/target/fixture file')
  const source = ts.createSourceFile('spec.ts', text, ts.ScriptTarget.Latest, true)
  if (source.parseDiagnostics.length) throw new Error('Source preservation: invalid TypeScript syntax')
  return source
}
const printed = (node, source) => printer.printNode(ts.EmitHint.Unspecified, node, source)
const normalized = (nodes, source) => nodes.map(n => printed(n, source))
const hash = text => createHash('sha256').update(text).digest('hex')
const manifest = () => JSON.parse(readFileSync(resolve(here, 'source-manifest.json'), 'utf8'))
const readCurrent = path => readFileSync(resolve(root, 'tests/e2e', path), 'utf8')
const readOriginal = (entry, data) => execFileSync('git', ['show', `${data.base}:tests/e2e/${entry.source}`], { cwd: root, encoding: 'utf8' })
const fail = message => { throw new Error(`Source preservation: ${message}`) }

export function statementInventory(text) {
  const source = parse(text)
  return normalized(source.statements.filter(n => !ts.isImportDeclaration(n)), source)
}
export function compareMultisets(expected, actual) {
  const count = items => items.reduce((m, item) => m.set(item, (m.get(item) || 0) + 1), new Map())
  const before = count(expected), after = count(actual)
  const differences = [...new Set([...before.keys(), ...after.keys()])]
    .filter(key => before.get(key) !== after.get(key))
    .map(key => ({ key, expected: before.get(key) || 0, actual: after.get(key) || 0 }))
  if (differences.length) throw new Error(`Test coverage differs: ${JSON.stringify(differences)}`)
}
function same(expected, actual, message) {
  if (JSON.stringify(expected) !== JSON.stringify(actual)) fail(message)
}
function imports(source) {
  const result = new Map()
  for (const node of source.statements.filter(ts.isImportDeclaration)) {
    const clause = node.importClause
    if (!clause || clause.name || !clause.namedBindings || !ts.isNamedImports(clause.namedBindings) || node.attributes || !ts.isStringLiteral(node.moduleSpecifier)) fail('unsupported import shape')
    for (const element of clause.namedBindings.elements) {
      const local = element.name.text, imported = (element.propertyName || element.name).text
      if (result.has(local)) fail(`duplicate import binding: ${local}`)
      // These three are type-only Playwright exports even in older non-type imports.
      const type = clause.isTypeOnly || element.isTypeOnly || ['Page', 'Locator', 'APIRequestContext'].includes(imported)
      result.set(local, { module: node.moduleSpecifier.text, imported, type })
    }
  }
  return result
}
function declarationName(node) {
  if (ts.isFunctionDeclaration(node)) return node.name?.text
  if (ts.isVariableStatement(node) && node.declarationList.declarations.length === 1 && ts.isIdentifier(node.declarationList.declarations[0].name)) return node.declarationList.declarations[0].name.text
}
function extractedModule(fixture) {
  if (!fixture.startsWith('fixtures/') || posix.normalize(fixture) !== fixture || !fixture.endsWith('.ts')) fail(`invalid extraction fixture: ${fixture}`)
  return './' + fixture.slice(0, -3)
}
function parseAlias(text) {
  const source = parse(text)
  if (source.statements.length !== 1) fail('alias metadata must contain one declaration')
  const node = source.statements[0]
  if (ts.isVariableStatement(node) && !node.modifiers?.length && node.declarationList.flags === ts.NodeFlags.Const && node.declarationList.declarations.length === 1) {
    const declaration = node.declarationList.declarations[0]
    if (ts.isIdentifier(declaration.name) && declaration.initializer && ts.isIdentifier(declaration.initializer) && !declaration.type && !declaration.exclamationToken) return { local: declaration.name.text, outer: declaration.initializer.text, type: false, statement: printed(node, source) }
  }
  if (ts.isTypeAliasDeclaration(node) && !node.modifiers?.length && !node.typeParameters?.length && ts.isTypeReferenceNode(node.type) && ts.isIdentifier(node.type.typeName) && !node.type.typeArguments?.length) return { local: node.name.text, outer: node.type.typeName.text, type: true, statement: printed(node, source) }
  fail('alias metadata must only rename an imported binding')
}
function wrappers(source, entries) {
  const result = new Map()
  const expected = new Set(entries.map(entry => `Source: ${entry.source}`))
  for (const node of source.statements) {
    if (ts.isImportDeclaration(node)) continue
    const call = ts.isExpressionStatement(node) && ts.isCallExpression(node.expression) ? node.expression : null
    const callee = call?.expression
    const callback = call?.arguments[1]
    const title = call?.arguments[0]
    if (!call || call.questionDotToken || call.typeArguments?.length || !ts.isPropertyAccessExpression(callee) || !ts.isIdentifier(callee.expression) || callee.expression.text !== 'test' || callee.name.text !== 'describe' || callee.questionDotToken || call.arguments.length !== 2 || !ts.isStringLiteral(title) || !expected.has(title.text) || !callback || !ts.isArrowFunction(callback) || callback.modifiers?.length || callback.parameters.length || callback.typeParameters?.length || callback.type || !ts.isBlock(callback.body)) fail('unexpected outer statement or invalid Source wrapper shape')
    if (result.has(title.text)) fail(`duplicate Source wrapper: ${title.text}`)
    result.set(title.text, callback.body.statements)
  }
  same([...expected].sort(), [...result.keys()].sort(), 'missing/renamed Source wrapper')
  return result
}

// Injectable readers let negative checks exercise this exact verifier without touching
// live test sources, including while a parent browser campaign is running.
export function verifySources(options = {}) {
  const data = options.data || manifest()
  const getOriginal = options.readOriginal || readOriginal
  const getCurrent = options.readCurrent || readCurrent
  const active = (options.listCurrent || (() => readdirSync(resolve(root, 'tests/e2e')).filter(f => f.endsWith('.spec.ts'))))()
  const activeSet = new Set(active)
  const groups = new Map(), originals = new Map(), fixtures = new Map()
  for (const entry of data.sources) {
    const original = getOriginal(entry, data)
    if (entry.sourceHash !== hash(original)) fail(`baseline source hash mismatch: ${entry.source}`)
    originals.set(entry.source, parse(original))
    const target = activeSet.has(entry.source) ? entry.source : entry.target
    if (!activeSet.has(target)) fail(`missing target: ${target}`)
    const entries = groups.get(target) || []
    entries.push(entry); groups.set(target, entries)
  }
  compareMultisets([...groups.keys()], active)
  for (const [target, entries] of groups) {
    const after = parse(getCurrent(target))
    if (entries.length === 1 && target === entries[0].source) {
      // Standalone sources have no permitted injected statements or altered imports.
      same(normalized(originals.get(target).statements, originals.get(target)), normalized(after.statements, after), `standalone imports/body changed: ${target}`)
      continue
    }
    const blocks = wrappers(after, entries)
    const outerImports = imports(after)
    same(outerImports.get('test'), { module: './fixtures', imported: 'test', type: false }, `wrapper test import must retain hardened fixtures: ${target}`)
    const usedImports = new Set(['test'])
    for (const entry of entries) {
      const before = originals.get(entry.source)
      const expectedImports = imports(before)
      const extracts = entry.extracts || []
      const seenExtracts = new Set()
      for (const extraction of extracts) {
        if (seenExtracts.has(extraction.name) || expectedImports.has(extraction.name)) fail(`duplicate/colliding fixture extraction: ${extraction.name}`)
        seenExtracts.add(extraction.name)
        const matches = before.statements.filter(n => declarationName(n) === extraction.name)
        if (matches.length !== 1) fail(`missing/ambiguous extracted helper: ${entry.source}:${extraction.name}`)
        expectedImports.set(extraction.name, { module: extractedModule(extraction.fixture), imported: extraction.name, type: false })
        const expectedFixture = fixtures.get(extraction.fixture) || new Map()
        const expected = printed(matches[0], before)
        if (expectedFixture.has(extraction.name) && expectedFixture.get(extraction.name) !== expected) fail(`conflicting shared fixture helper: ${extraction.name}`)
        expectedFixture.set(extraction.name, expected); fixtures.set(extraction.fixture, expectedFixture)
      }
      const statements = blocks.get(`Source: ${entry.source}`)
      const aliases = (entry.aliases || []).map(parseAlias)
      const renamed = new Map()
      for (let index = 0; index < aliases.length; index++) {
        const alias = aliases[index], expected = expectedImports.get(alias.local)
        if (!expected || renamed.has(alias.local) || expected.type !== alias.type || alias.outer === alias.local) fail(`unapproved extraction/import alias: ${alias.local}`)
        same(expected, outerImports.get(alias.outer), `import alias origin changed: ${entry.source}:${alias.local}`)
        if (!statements[index] || printed(statements[index], after) !== alias.statement) fail(`alias declaration changed: ${entry.source}:${alias.local}`)
        renamed.set(alias.local, alias.outer)
      }
      for (const [local, expected] of expectedImports) {
        const outer = renamed.get(local) || local
        same(expected, outerImports.get(outer), `import binding/module changed: ${entry.source}:${local}`)
        usedImports.add(outer)
      }
      const expectedStatements = before.statements.filter(n => !ts.isImportDeclaration(n) && !seenExtracts.has(declarationName(n)))
      same(normalized(expectedStatements, before), normalized(statements.slice(aliases.length), after), `statement/body/fixture factory/config/hook changed: ${entry.source} → ${target}`)
    }
    same([...outerImports.keys()].sort(), [...usedImports].sort(), `unapproved outer import: ${target}`)
  }
  for (const [file, expectedHelpers] of fixtures) {
    const fixture = parse(getCurrent(file))
    // Current extractions are self-contained; future dependency-bearing extractions
    // must explicitly extend this verification, never silently permit fixture effects.
    if (fixture.statements.length !== expectedHelpers.size) fail(`unexpected fixture outer statement: ${file}`)
    for (const node of fixture.statements) {
      const name = declarationName(node), expected = expectedHelpers.get(name)
      if (!expected || printed(node, fixture).replace(/^export /, '') !== expected) fail(`extracted fixture helper changed: ${file}:${name}`)
      if (node.modifiers?.length !== 1 || node.modifiers[0].kind !== ts.SyntaxKind.ExportKeyword) fail(`fixture helper must be an explicit export: ${file}:${name}`)
    }
  }
  return { originalSpecs: data.sources.length, activeSpecs: active.length }
}

function portablePath(file) {
  const path = file.replaceAll('\\', '/')
  const marker = '/tests/e2e/'
  if (path.includes(marker)) return path.slice(path.lastIndexOf(marker) + marker.length)
  if (path.startsWith('tests/e2e/')) return path.slice('tests/e2e/'.length)
  const prefix = root.replaceAll('\\', '/') + '/'
  if (path.startsWith(prefix)) return path.slice(prefix.length)
  for (const marker of ['/packages/', '/node_modules/', '/www/']) {
    if (path.includes(marker)) return path.slice(path.lastIndexOf(marker) + 1)
  }
  if (posix.isAbsolute(path) || /^[A-Z]:\//i.test(path)) throw new Error(`Cannot normalize annotation source path: ${file}`)
  return path
}
function normalizeAnnotations(annotations, logicalSource, physicalSource) {
  return (annotations || []).map(annotation => {
    const result = { ...annotation }
    if (result.location) {
      const file = portablePath(result.location.file)
      // Relocation changes coordinates. Keep logical origin and annotation semantics;
      // line/column are diagnostics, not a coverage invariant.
      result.location = { file: file === physicalSource ? logicalSource : file }
    }
    return result
  })
}
export function normalizeLeaf(value) {
  const leaf = typeof value === 'string' ? JSON.parse(value) : structuredClone(value)
  leaf[0] = portablePath(leaf[0])
  leaf[7] = normalizeAnnotations(leaf[7], leaf[0], leaf[0])
  return JSON.stringify(leaf)
}
export function collectLeaves(report, data = manifest()) {
  if (report.errors?.length) throw new Error(JSON.stringify(report.errors))
  const result = []
  function walk(suite, parents) {
    const path = suite.line === 0 ? [] : [...parents, suite.title]
    for (const spec of suite.specs || []) {
      const physical = portablePath(spec.file)
      const sourceScopes = path.filter(t => t.startsWith('Source: '))
      if (sourceScopes.length > 1) throw new Error('Invalid nested Source ownership mapping')
      const logical = sourceScopes[0]?.slice(8)
      const entries = data.sources.filter(e => e.source === physical || e.target === physical)
      const entry = logical ? entries.find(e => e.source === logical && e.target === physical) : entries.find(e => e.source === physical)
      if (!entry) throw new Error(`Unknown source/target ownership mapping: ${logical || physical}`)
      for (const test of spec.tests || []) result.push(JSON.stringify([entry.source, path.filter(t => !t.startsWith('Source: ')), spec.title, test.projectName, [...spec.tags || []].sort(), test.timeout, test.expectedStatus, normalizeAnnotations(test.annotations, entry.source, physical)]))
    }
    for (const child of suite.suites || []) walk(child, path)
  }
  for (const suite of report.suites || []) walk(suite, [])
  return result
}
export function verifyCollection(options = {}) {
  const data = options.data || manifest()
  const environment = { ...(options.environment || process.env) }
  // The baseline was local and non-CI. Do not inherit a remote URL or CI's
  // longer default timeout; explicit per-test timeouts still compare exactly.
  for (const key of ['CI', 'BASE_URL', 'E2E_REUSE_SERVER', 'PLAYWRIGHT_STATS_API_KEY']) delete environment[key]
  const raw = (options.execute || execFileSync)(resolve(root, 'node_modules/.bin/playwright'), ['test', '--config=tests/playwright.config.ts', '--list', '--reporter=json', '--workers=2', '--retries=0'], { cwd: root, env: environment, encoding: 'utf8', maxBuffer: 20_000_000 })
  const current = collectLeaves(JSON.parse(raw), data)
  const baseline = options.baseline || JSON.parse(readFileSync(resolve(here, 'baseline-leaves.json'), 'utf8'))
  compareMultisets(baseline.map(normalizeLeaf), current.map(normalizeLeaf))
  return { collected: current.length }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(JSON.stringify({ ...verifySources(), ...verifyCollection() }))
}
