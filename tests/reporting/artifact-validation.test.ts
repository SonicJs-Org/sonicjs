import { expect, test, vi } from 'vitest'
import { validateNativeReport } from '../../scripts/testing/validate-flakiness-artifacts.mjs'
const sha = 'a'.repeat(40)
function report() {
  return { category: 'vitest', commitId: sha, environments: [{ name: 'vitest', metadata: { suite: 'core-unit', target: 'none', source: 'ci' } }], startTimestamp: 1, duration: 1, tests: [{ title: 'path/title', attempts: [{}] }] }
}
test('native parser preserves default passed/env0 and diagnostic paths', () => {
  expect(validateNativeReport(Buffer.from(JSON.stringify(report())))).toEqual(report())
})
test.each(['endpoint', 'hooks', 'unknown'])('rejects stripped nested %s', key => {
  const input = report()
  Object.assign(input.tests[0]!.attempts[0]!, { [key]: 'hostile' })
  expect(() => validateNativeReport(Buffer.from(JSON.stringify(input)))).toThrow()
})
test('preflight rejects depth before recursive schema', () => {
  let value: unknown = 'leaf'
  for (let i = 0; i < 100; i++) value = { nested: value }
  expect(() => validateNativeReport(Buffer.from(JSON.stringify(value)))).toThrow(/depth/)
})

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, readdirSync, symlinkSync, linkSync, chmodSync, lstatSync } from 'node:fs'
import { join } from 'node:path'
import { createHash, randomBytes } from 'node:crypto'
import { validateArtifactPayload, verifyUploadSnapshots, type ProducerProvenanceInput } from '../../scripts/testing/validate-flakiness-artifacts.mjs'
import { reportingScratch } from './scratch'
const scratch = reportingScratch('artifact-validation-')
function context(): ProducerProvenanceInput {
  return { trigger: { repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2 }, producer: { repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2, workflowId: 207092903, workflowName: 'PR Tests', workflowPath: '.github/workflows/pr-tests.yml', event: 'push', status: 'completed', conclusion: 'failure', headBranch: 'main', headSha: sha }, jobs: [{ id: 456, key: 'test', runId: 123, runAttempt: 2, status: 'completed', steps: [{ number: 4, name: 'Run unit tests with coverage', status: 'completed', conclusion: 'success' }, { number: 7, name: 'Run full E2E regression suite', status: 'completed', conclusion: 'skipped' }] }] }
}
function payload() {
  const root = mkdtempSync(join(scratch, 'input-'))
  const invocation = 'test-local-2-12345678-1234-4234-8234-123456789abc'
  const dir = join(root, 'core-unit', invocation)
  mkdirSync(join(dir, 'vendor/attachments'), { recursive: true })
  const native = { ...report(), url: 'https://github.com/SonicJs-Org/sonicjs/actions/runs/123' }
  const manifest = { suite: 'core-unit', target: 'none', source: 'ci', invocation, commit: sha, startedAt: '2026-01-01T00:00:00.000Z', endedAt: '2026-01-01T00:00:01.000Z', outcome: 'passed', runId: '123', attempt: '2', job: 'test', workflow: 'PR Tests', runURL: native.url, pullRequestStatus: 'no-pr' }
  const save = () => { writeFileSync(join(dir, 'invocation.json'), JSON.stringify(manifest)); writeFileSync(join(dir, 'vendor/report.json'), JSON.stringify(native)) }
  save()
  return { root, dir, native, manifest, save }
}
async function validate(root: string, trusted = context()) { return validateArtifactPayload({ input: { kind: 'directory', path: root }, stagingParent: scratch, trusted }) }
test('owns frozen snapshots; original mutation cannot change upload bytes; snapshot mutation detected', async () => {
  const p = payload()
  const result = await validate(p.root)
  expect(Object.isFrozen(result.invocations[0])).toBe(true)
  expect(result.invocations[0]!.counts).toMatchObject({ tests: 1, attempts: 1, passed: 1 })
  p.native.tests[0]!.title = 'changed'; p.save()
  await verifyUploadSnapshots(result)
  expect(readFileSync(result.invocations[0]!.reportPath, 'utf8')).toContain('path/title')
  chmodSync(result.invocations[0]!.reportPath, 0o600)
  writeFileSync(result.invocations[0]!.reportPath, '{}')
  await expect(verifyUploadSnapshots(result)).rejects.toThrow()
  rmSync(result.root, { recursive: true, force: true })
})
test.each(['category', 'metadata', 'commit', 'manifest', 'step', 'unknown-file', 'missing-report', 'empty', 'interrupted'])('rejects %s before snapshot exposure', async mode => {
  const p = payload(); const trusted = context()
  if (mode === 'category') p.native.category = 'playwright'
  if (mode === 'metadata') p.native.environments[0]!.metadata.source = 'local'
  if (mode === 'commit') p.manifest.commit = 'b'.repeat(40)
  if (mode === 'manifest') p.manifest.runId = '124'
  if (mode === 'step') trusted.jobs[0]!.steps[0]!.conclusion = 'failure'
  if (mode === 'empty') p.native.tests = []
  if (mode === 'interrupted') p.manifest.outcome = 'interrupted'
  p.save()
  if (mode === 'unknown-file') writeFileSync(join(p.dir, 'vendor/script.sh'), 'bad')
  if (mode === 'missing-report') rmSync(join(p.dir, 'vendor/report.json'))
  const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  await expect(validate(p.root, trusted)).rejects.toThrow()
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})
test.each(['symlink', 'hardlink', 'missing', 'digest'])('attachment %s rejects', async mode => {
  const p = payload(); const data = Buffer.from('attachment'); const id = createHash('sha1').update(data).digest('hex')
  Object.assign(p.native.tests[0]!.attempts[0]!, { attachments: [{ id, name: 'log', contentType: 'text/plain' }] }); p.save()
  const dest = join(p.dir, 'vendor/attachments', id)
  if (mode === 'symlink') symlinkSync(join(p.dir, 'invocation.json'), dest)
  if (mode === 'hardlink') linkSync(join(p.dir, 'invocation.json'), dest)
  if (mode === 'digest') writeFileSync(dest, 'wrong')
  await expect(validate(p.root)).rejects.toThrow()
})

import { zip } from './fixtures/artifact-zip'
function archive(p: ReturnType<typeof payload>) {
  const prefix = `core-unit/${p.manifest.invocation}`
  return [{ name: `${prefix}/invocation.json`, bytes: Buffer.from(JSON.stringify(p.manifest)) }, { name: `${prefix}/vendor/report.json`, bytes: Buffer.from(JSON.stringify(p.native)), method: 8 }]
}
async function validateZip(bytes: Buffer) {
  const file = join(mkdtempSync(join(scratch, 'zip-')), 'artifact.zip'); writeFileSync(file, bytes)
  return validateArtifactPayload({ input: { kind: 'zip', path: file }, stagingParent: scratch, trusted: context() })
}
test('ZIP positive preserves native bytes in private snapshots', async () => {
  const p = payload(); const result = await validateZip(zip(archive(p)))
  await verifyUploadSnapshots(result)
  expect(readFileSync(result.invocations[0]!.reportPath)).toEqual(Buffer.from(JSON.stringify(p.native)))
  rmSync(result.root, { recursive: true, force: true })
})
test.each(['../outside', '/absolute', 'C:/drive', 'a\\b', 'a/../b', 'core-unit//x'])('ZIP rejects hostile path %s before staging', async name => {
  const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  await expect(validateZip(zip([{ name }]))).rejects.toThrow()
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})
test.each(['duplicate', 'case', 'prefix', 'symlink', 'fifo', 'method', 'encrypted', 'crc', 'size', 'bomb'])('ZIP rejects %s', async mode => {
  const p = payload(); const entries = archive(p)
  if (mode === 'duplicate') entries.push(entries[0]!)
  if (mode === 'case') entries.push({ ...entries[0]!, name: entries[0]!.name.toUpperCase() })
  if (mode === 'prefix') entries.push({ name: 'core-unit', bytes: Buffer.alloc(0) })
  const first = entries[0]!
  if (mode === 'symlink') Object.assign(first, { mode: 0o120777 })
  if (mode === 'fifo') Object.assign(first, { mode: 0o010644 })
  if (mode === 'method') first.method = 99
  if (mode === 'encrypted') Object.assign(first, { flags: 1 })
  if (mode === 'crc') Object.assign(first, { crc: 123 })
  if (mode === 'size') Object.assign(first, { size: first.bytes!.length + 1 })
  if (mode === 'bomb') Object.assign(first, { size: 512 * 1024 * 1024 })
  await expect(validateZip(zip(entries))).rejects.toThrow()
})

import { spawnSync } from 'node:child_process'
import { repositoryRoot } from './options'
test('actual native reporter subprocess parses and snapshots offline CI metadata', async () => {
  const p = payload()
  const home = mkdtempSync(join(scratch, 'native-home-'))
  const child = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(repositoryRoot, 'tests/reporting/fixtures/artifact-native.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25000,
    env: { PATH: process.env.PATH, HOME: home, TMPDIR: scratch, CI: '1', GITHUB_REPOSITORY: 'SonicJs-Org/sonicjs', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', FK_ENV_SUITE: 'core-unit', FK_ENV_SOURCE: 'ci', FK_ENV_TARGET: 'none', ARTIFACT_NATIVE_OUTPUT: join(p.dir, 'vendor'), NODE_OPTIONS: `--require=${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}` },
  })
  expect(child.error).toBeUndefined(); expect(child.status, child.stdout + child.stderr).toBe(0)
  const native = validateNativeReport(readFileSync(join(p.dir, 'vendor/report.json')))
  expect(native.generatedBy?.name).toBe('@flakiness/vitest')
  expect(native.environments[0]!.metadata).toEqual({ suite: 'core-unit', target: 'none', source: 'ci' })
  const result = await validate(p.root)
  await verifyUploadSnapshots(result)
  expect(result.invocations[0]!.counts).toMatchObject({ tests: 1, passed: 1 })
  rmSync(result.root, { recursive: true, force: true })
})

test('rejects environment name masquerading as current suite', async () => {
  const p = payload(); p.native.environments[0]!.name = 'invented'; p.save()
  await expect(validate(p.root)).rejects.toThrow(/environment/)
})

test.each(['retry', 'expected-failure', 'failed', 'runner-error'])('preserves honest native %s semantics', async mode => {
  const p = payload(); const trusted = context()
  if (mode === 'retry') Object.assign(p.native.tests[0]!, { attempts: [{ status: 'failed' }, {}] })
  if (mode === 'expected-failure') Object.assign(p.native.tests[0]!, { attempts: [{ expectedStatus: 'failed', status: 'failed' }] })
  if (mode === 'failed' || mode === 'runner-error') {
    p.manifest.outcome = 'failed'; trusted.jobs[0]!.steps[0]!.conclusion = 'failure'
    if (mode === 'failed') Object.assign(p.native.tests[0]!.attempts[0]!, { status: 'failed' })
    else Object.assign(p.native, { unattributedErrors: [{ message: 'source/path diagnostic' }] })
  }
  p.save(); const result = await validate(p.root, trusted)
  expect(result.invocations[0]!.counts).toMatchObject({ tests: 1, attempts: mode === 'retry' ? 2 : 1, failed: mode === 'failed' ? 1 : 0 })
  expect(readFileSync(result.invocations[0]!.reportPath)).toEqual(Buffer.from(JSON.stringify(p.native)))
  rmSync(result.root, { recursive: true, force: true })
})
test.each(['root', 'suite', 'deep-step'])('resolves every %s attachment ref using content ID only', async mode => {
  const p = payload(); const data = Buffer.from('safe attachment'); const id = createHash('sha1').update(data).digest('hex')
  const refs = [{ id, name: '../../display/name', contentType: 'text/plain' }]
  const attempt = mode === 'deep-step' ? { steps: [{ title: 'outer', steps: [{ title: 'inner', attachments: refs }] }] } : { attachments: refs }
  const testCase = { title: 'native', attempts: [attempt] }
  if (mode === 'suite') { p.native.tests = []; Object.assign(p.native, { suites: [{ type: 'file', title: '/embedded/file', suites: [{ type: 'suite', title: 'nested', tests: [testCase] }] }] }) }
  else Object.assign(p.native.tests[0]!, testCase)
  writeFileSync(join(p.dir, 'vendor/attachments', id), data); p.save()
  const result = await validate(p.root); await verifyUploadSnapshots(result)
  expect(result.invocations[0]!.files).toHaveLength(3)
  rmSync(result.root, { recursive: true, force: true })
  rmSync(join(p.dir, 'vendor/attachments', id))
  await expect(validate(p.root)).rejects.toThrow(/missing attachment/)
})
test.each(['all-skipped', 'no-attempts', 'bad-env-index', 'partial-interrupted', 'hostile-project', 'hostile-endpoint', 'user-data', 'metadata-extra', 'prototype', 'nonfinite', 'string-budget', 'report-budget', 'unknown-suite', 'duplicate-invocation', 'missing-suite', 'unreferenced', 'extra-directory', 'stale-pr', 'source-attempt', 'source-query'])('fails closed: %s', async mode => {
  const p = payload(); const trusted = context()
  if (mode === 'all-skipped') Object.assign(p.native.tests[0]!.attempts[0]!, { status: 'skipped' })
  if (mode === 'no-attempts') p.native.tests[0]!.attempts = []
  if (mode === 'bad-env-index') Object.assign(p.native.tests[0]!.attempts[0]!, { environmentIdx: 0.5 })
  if (mode === 'partial-interrupted') Object.assign(p.native.tests[0]!, { attempts: [{ status: 'interrupted' }, {}] })
  if (mode === 'hostile-project') Object.assign(p.native, { flakinessProject: 'attacker/project' })
  if (mode === 'hostile-endpoint') Object.assign(p.native, { endpoint: 'https://attacker.invalid' })
  if (mode === 'user-data') Object.assign(p.native.environments[0]!, { userSuppliedData: { hooks: 'evil' } })
  if (mode === 'metadata-extra') Object.assign(p.native.environments[0]!.metadata, { arbitrary: 'evil' })
  if (mode === 'prototype') Object.assign(p.native, { constructor: 'evil' })
  if (mode === 'string-budget') p.native.tests[0]!.title = 'a'.repeat(8 * 1024 * 1024 + 1)
  if (mode === 'source-attempt') p.native.url += '/attempts/1'
  if (mode === 'source-query') p.native.url += '?attempt=2&attempt=1'
  if (mode === 'missing-suite') trusted.jobs[0]!.steps[1]!.conclusion = 'success'
  if (mode === 'stale-pr') {
    trusted.producer.event = 'pull_request_target'
    trusted.originalPullRequests = [{ number: 1, baseRepository: 'SonicJs-Org/sonicjs', headRepository: 'Contributor/sonicjs', headSha: sha }]
    trusted.currentPullRequest = { ...trusted.originalPullRequests[0]!, headSha: 'b'.repeat(40) }
  }
  p.save()
  if (mode === 'nonfinite') writeFileSync(join(p.dir, 'vendor/report.json'), JSON.stringify(p.native).replace('"duration":1', '"duration":1e999'))
  if (mode === 'report-budget') writeFileSync(join(p.dir, 'vendor/report.json'), ' '.repeat(16 * 1024 * 1024 + 1))
  if (mode === 'unreferenced') writeFileSync(join(p.dir, 'vendor/attachments', 'f'.repeat(40)), 'unreferenced')
  if (mode === 'extra-directory') mkdirSync(join(p.root, 'unexpected'))
  if (mode === 'unknown-suite' || mode === 'duplicate-invocation') {
    const dir = join(p.root, mode === 'unknown-suite' ? 'synthetic' : 'core-unit', p.manifest.invocation.replace('123456789abc', '123456789abd'))
    mkdirSync(join(dir, 'vendor'), { recursive: true }); writeFileSync(join(dir, 'invocation.json'), JSON.stringify({ ...p.manifest, invocation: p.manifest.invocation.replace('123456789abc', '123456789abd') })); writeFileSync(join(dir, 'vendor/report.json'), JSON.stringify(p.native))
  }
  await expect(validate(p.root, trusted)).rejects.toThrow()
})
test('validates complete batch before creating any snapshots', async () => {
  const p = payload(); const trusted = context(); trusted.jobs[0]!.steps[1]!.conclusion = 'success'
  const invocation = p.manifest.invocation
  const second = join(p.root, 'cms-e2e', invocation); mkdirSync(join(second, 'vendor'), { recursive: true })
  writeFileSync(join(second, 'invocation.json'), JSON.stringify({ ...p.manifest, suite: 'cms-e2e', target: 'local-worker' }))
  writeFileSync(join(second, 'vendor/report.json'), JSON.stringify({ ...p.native, category: 'playwright', environments: [{ name: 'chromium', metadata: { suite: 'cms-e2e', target: 'local-worker', source: 'ci' } }] }))
  const result = await validate(p.root, trusted); expect(result.invocations).toHaveLength(2)
  rmSync(result.root, { recursive: true, force: true })
  writeFileSync(join(second, 'vendor/report.json'), '{}')
  const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  await expect(validate(p.root, trusted)).rejects.toThrow()
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})

import { execFileSync } from 'node:child_process'
test.each(['fifo', 'ancestor-link', 'root-link', 'case-collision', 'depth', 'count', 'executable'])('filesystem rejects %s without unsafe reads', async mode => {
  const p = payload(); let root = p.root
  if (mode === 'executable') chmodSync(join(p.dir, 'vendor/report.json'), 0o755)
  if (mode === 'fifo') execFileSync('mkfifo', [join(p.dir, 'vendor/attachments', 'a'.repeat(40))])
  if (mode === 'ancestor-link') {
    const container = mkdtempSync(join(scratch, 'link-parent-')); symlinkSync(p.root, join(container, 'alias')); root = join(container, 'alias')
  }
  if (mode === 'root-link') { const path = join(scratch, `alias-${Date.now()}`); symlinkSync(p.root, path); root = path }
  if (mode === 'case-collision') writeFileSync(join(p.dir, 'INVOCATION.json'), '{}')
  if (mode === 'depth') mkdirSync(join(p.dir, 'vendor/a/b/c/d/e/f'), { recursive: true })
  if (mode === 'count') for (let i = 0; i < 2049; i++) writeFileSync(join(p.dir, `f${i}`), '')
  await expect(validate(root)).rejects.toThrow()
})
test.each(['count', 'depth', 'actual-over-declared', 'directory-payload', 'directory-prefix', 'executable', 'setuid', 'case-prefix', 'drive-relative'])('ZIP bounded structural rejection: %s', async mode => {
  let entries: Parameters<typeof zip>[0] = [{ name: 'safe', bytes: Buffer.from('safe') }]
  if (mode === 'count') entries = Array.from({ length: 2049 }, (_, i) => ({ name: `f${i}` }))
  if (mode === 'depth') entries[0]!.name = 'a/b/c/d/e/f/g'
  if (mode === 'actual-over-declared') Object.assign(entries[0]!, { bytes: Buffer.alloc(1024 * 1024, 97), method: 8, size: 1 })
  if (mode === 'directory-payload') Object.assign(entries[0]!, { name: 'safe/', mode: 0o040755 })
  if (mode === 'directory-prefix') entries.push({ name: 'safe/nested' })
  if (mode === 'executable') entries[0]!.mode = 0o100755
  if (mode === 'setuid') entries[0]!.mode = 0o104644
  if (mode === 'case-prefix') entries = [{ name: 'parent/a' }, { name: 'PARENT/b' }]
  if (mode === 'drive-relative') entries[0]!.name = 'C:escape'
  const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  await expect(validateZip(zip(entries))).rejects.toThrow()
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})
test('iterative preflight bounds total nodes and rejects dangerous keys inside schema-any', () => {
  const input = { ...report(), extra: Array.from({ length: 1_000_001 }, () => 0) }
  expect(() => validateNativeReport(Buffer.from(JSON.stringify(input)))).toThrow(/nodes/)
  const text = JSON.stringify(report()).replace('"source":"ci"', '"source":"ci","__proto__":{"evil":true}')
  expect(() => validateNativeReport(Buffer.from(text))).toThrow(/prototype/)
})
test('ZIP order cannot change snapshot content identity', async () => {
  const p = payload(); const first = await validate(p.root); const second = await validateZip(zip(archive(p).reverse()))
  expect(first.invocations[0]!.id).toBe(second.invocations[0]!.id)
  rmSync(first.root, { recursive: true, force: true }); rmSync(second.root, { recursive: true, force: true })
})
test('recheck rejects new files and links even when native bytes unchanged', async () => {
  const p = payload(); const result = await validate(p.root)
  symlinkSync(join(p.dir, 'invocation.json'), join(result.root, 'outside'))
  await expect(verifyUploadSnapshots(result)).rejects.toThrow()
  rmSync(result.root, { recursive: true, force: true })
})

test.each(['local-worker', 'preview-worker'])('actual Playwright reporter preserves CMS %s report offline', async target => {
  const p = payload(); const trusted = context()
  trusted.jobs[0]!.steps[0]!.conclusion = 'skipped'; trusted.jobs[0]!.steps[1]!.conclusion = 'success'
  const dir = join(p.root, 'cms-e2e', p.manifest.invocation); mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'invocation.json'), JSON.stringify({ ...p.manifest, suite: 'cms-e2e', target, commit: 'placeholder' }))
  rmSync(join(p.root, 'core-unit'), { recursive: true, force: true })
  const home = mkdtempSync(join(scratch, 'playwright-home-'))
  const child = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/@playwright/test/cli.js'), 'test', '--config', join(repositoryRoot, 'tests/reporting/fixtures/artifact-playwright.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25000,
    env: { PATH: process.env.PATH, HOME: home, TMPDIR: scratch, CI: '1', GITHUB_REPOSITORY: 'SonicJs-Org/sonicjs', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', FK_ENV_SUITE: 'cms-e2e', FK_ENV_SOURCE: 'ci', FK_ENV_TARGET: target, ARTIFACT_NATIVE_OUTPUT: join(dir, 'vendor'), ARTIFACT_NATIVE_RESULTS: join(home, 'results'), NODE_OPTIONS: `--require=${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}` },
  })
  expect(child.error).toBeUndefined(); expect(child.status, child.stdout + child.stderr).toBe(0)
  const native = validateNativeReport(readFileSync(join(dir, 'vendor/report.json')))
  // Real reporter uses actual git HEAD; synthetic trusted adapter binds that producer SHA.
  trusted.producer.headSha = native.commitId
  writeFileSync(join(dir, 'invocation.json'), JSON.stringify({ ...p.manifest, suite: 'cms-e2e', target, targetURL: target === 'preview-worker' ? 'https://sonicjs-pr-123.example.workers.dev/' : 'http://localhost:8787/', commit: native.commitId }))
  const result = await validate(p.root, trusted); await verifyUploadSnapshots(result)
  expect(native.generatedBy?.name).toBe('@flakiness/playwright')
  expect(result.invocations[0]!.counts).toMatchObject({ tests: 1, passed: 1 })
  expect(result.invocations[0]!.files.length).toBeGreaterThan(2)
  rmSync(result.root, { recursive: true, force: true })
})


const fsFault = vi.hoisted(() => ({ failSnapshotWrite: false, writes: 0, bridgeWarning: 0, malformedProtocol: false }))
vi.mock('node:child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('node:child_process')>()
  return { ...actual,
    execFile: (...args: Parameters<typeof actual.execFile>) => {
      const child = actual.execFile(...args)
      if (fsFault.malformedProtocol) { child.stdout?.emit('data', Buffer.from('PROTOCOL-SENTINEL')); fsFault.malformedProtocol = false }
      if (fsFault.bridgeWarning) {
        child.stderr?.emit('data', Buffer.alloc(fsFault.bridgeWarning, 87))
        fsFault.bridgeWarning = 0
      }
      return child
    },
  }
})
vi.mock('node:fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('node:fs/promises')>()
  return { ...actual,
    writeFile: async (...args: Parameters<typeof actual.writeFile>) => {
      if (fsFault.failSnapshotWrite && String(args[0]).includes('/snapshot-') && fsFault.writes++ > 0) {
        fsFault.failSnapshotWrite = false
        throw new Error('fixture staging failure after first regular file')
      }
      return actual.writeFile(...args)
    },
  }
})
test('partial staging failure cleans only unique private snapshot root', async () => {
  const p = payload(); const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  fsFault.failSnapshotWrite = true; fsFault.writes = 0
  try { await expect(validate(p.root)).rejects.toThrow(/fixture staging failure/) }
  finally { fsFault.failSnapshotWrite = false }
  expect(fsFault.writes).toBe(2)
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
  expect(readFileSync(join(p.dir, 'vendor/report.json'))).toEqual(Buffer.from(JSON.stringify(p.native)))
})


test('filesystem special permission requests either reject or are stripped before safe snapshot creation', async () => {
  const p = payload(); const file = join(p.dir, 'vendor/report.json')
  chmodSync(file, 0o4644)
  const actualMode = lstatSync(file).mode
  if (actualMode & 0o7000) await expect(validate(p.root)).rejects.toThrow(/safe POSIX intake/)
  else {
    // This host strips setuid on chmod. Assert actual input is ordinary; never pretend
    // it exercised the dangerous-mode rejection (ZIP fixtures cover declared modes).
    expect(actualMode & 0o7777).toBe(0o644)
    const result = await validate(p.root)
    expect(lstatSync(result.invocations[0]!.reportPath).mode & 0o7777).toBe(0o400)
    rmSync(result.root, { recursive: true, force: true })
  }
})

test.each(['directory', 'file'].flatMap(kind => ['ancestor', 'leaf', 'fifo', 'mutation', 'clean'].map(mode => [kind, mode] as const)))('held-FD syscall seam %s %s forbids outside reads and closes handles', (kind, mode) => {
  const root = mkdtempSync(join(scratch, 'fd-seam-')); mkdirSync(join(root, 'vendor'))
  writeFileSync(join(root, 'vendor/report.json'), 'ORIGINAL-BYTES')
  const outside = mkdtempSync(join(scratch, 'outside-')); writeFileSync(join(outside, 'report.json'), 'OUTSIDE-SENTINEL')
  const child = spawnSync('/usr/bin/python3', ['-I', '-S', '-B', join(repositoryRoot, 'tests/reporting/fixtures/artifact-intake-harness.py'), join(repositoryRoot, 'scripts/testing/read-flakiness-artifacts.py'), root, outside, mode, kind], { cwd: '/', env: { TMPDIR: scratch }, encoding: 'utf8', timeout: 5000, maxBuffer: 65536 })
  expect(child.error).toBeUndefined(); expect(child.status, child.stderr).toBe(0)
  const result = JSON.parse(child.stdout)
  expect(result.swapped).toBe(true); expect(result.outsideReads).toBe(0); expect(result.remainingFDs).toBe(0)
  expect(result.rejected).toBe(mode !== 'clean')
  expect(Buffer.from(result.insideBytes, 'base64')).toEqual(Buffer.from(mode === 'ancestor' || mode === 'clean' ? 'ORIGINAL-BYTES' : ''))
  if (mode === 'clean') expect(Buffer.from(result.result.files[0][1], 'base64')).toEqual(Buffer.from('ORIGINAL-BYTES'))
  expect(readFileSync(join(outside, 'report.json'), 'utf8')).toBe('OUTSIDE-SENTINEL')
})

test.each([
  ['local-worker', 'http://[::1]:9000/base/', true],
  ['local-worker', 'https://localhost:9443/', true],
  ['local-worker', 'https://LOCALHOST:9443/', false],
  ['preview-worker', 'https://preview.example.workers.dev/path/', true],
  ['local-worker', 'https://preview.example.workers.dev/', false],
  ['preview-worker', 'http://127.0.0.1:8787/', false],
  ['preview-worker', 'https://u:p@preview.example.workers.dev/', false],
  ['preview-worker', 'https://preview.example.workers.dev/?token=secret', false],
  ['preview-worker', 'https://preview.example.workers.dev/#fragment', false],
  ['preview-worker', 'https://preview.example.workers.dev/?', false],
  ['preview-worker', 'https://preview.example.workers.dev/#', false],
  ['preview-worker', 'file:///outside', false],
] as const)('CMS target metadata %s %s accepted=%s', async (target, targetURL, accepted) => {
  const p = payload(); const trusted = context(); trusted.jobs[0]!.steps[0]!.conclusion = 'skipped'; trusted.jobs[0]!.steps[1]!.conclusion = 'success'
  const dir = join(p.root, 'cms-e2e', p.manifest.invocation); mkdirSync(join(dir, 'vendor'), { recursive: true })
  writeFileSync(join(dir, 'invocation.json'), JSON.stringify({ ...p.manifest, suite: 'cms-e2e', target, targetURL }))
  writeFileSync(join(dir, 'vendor/report.json'), JSON.stringify({ ...p.native, category: 'playwright', environments: [{ name: 'chromium', metadata: { suite: 'cms-e2e', target, source: 'ci' } }] }))
  rmSync(join(p.root, 'core-unit'), { recursive: true, force: true })
  if (!accepted) await expect(validate(p.root, trusted)).rejects.toThrow()
  else { const result = await validate(p.root, trusted); await verifyUploadSnapshots(result); rmSync(result.root, { recursive: true, force: true }) }
})

function zipInput(entries: Parameters<typeof zip>[0]): { kind: 'zip'; path: string } {
  const path = join(mkdtempSync(join(scratch, 'batch-zip-')), 'artifact.zip'); writeFileSync(path, zip(entries)); return { kind: 'zip', path }
}
function suiteArchives() {
  const p = payload()
  const core = archive(p)
  const cms = core.map(e => ({ ...e, name: e.name.replace('core-unit/', 'cms-e2e/'), bytes: Buffer.from(e.name.endsWith('invocation.json')
    ? JSON.stringify({ ...p.manifest, suite: 'cms-e2e', target: 'preview-worker' })
    : JSON.stringify({ ...p.native, category: 'playwright', environments: [{ name: 'chromium', metadata: { suite: 'cms-e2e', target: 'preview-worker', source: 'ci' } }] })) }))
  const trusted = context(); trusted.jobs[0]!.steps[1]!.conclusion = 'success'
  return { p, core, cms, trusted }
}
test('whole-batch accepts two per-suite ZIPs with full trusted context', async () => {
  const { core, cms, trusted } = suiteArchives()
  const result = await validateArtifactPayload({ input: [zipInput(core), zipInput(cms)], stagingParent: scratch, trusted })
  expect(result.invocations.map(i => i.suite)).toEqual(['core-unit', 'cms-e2e']); await verifyUploadSnapshots(result)
  rmSync(result.root, { recursive: true, force: true })
})
test.each(['bad-member', 'missing-suite', 'duplicate', 'case', 'prefix', 'global-count', 'global-bytes', 'too-many-inputs'])('whole-batch rejects %s before snapshots', async mode => {
  const { core, cms, trusted } = suiteArchives()
  let inputs = [zipInput(core), zipInput(cms)]
  if (mode === 'bad-member') writeFileSync(inputs[1]!.path, 'not a ZIP')
  if (mode === 'missing-suite') inputs = [inputs[0]!]
  if (mode === 'duplicate') inputs[1] = zipInput(core)
  if (mode === 'case') inputs[1] = zipInput(core.map(e => ({ ...e, name: e.name.toUpperCase() })))
  if (mode === 'prefix') inputs[1] = zipInput([{ name: 'core-unit', bytes: Buffer.from('collision') }])
  if (mode === 'global-count') inputs = [zipInput(Array.from({ length: 1025 }, (_, i) => ({ name: `core-unit/f${i}` }))), zipInput(Array.from({ length: 1025 }, (_, i) => ({ name: `cms-e2e/f${i}` })))]
  if (mode === 'global-bytes') {
    const large = Buffer.alloc(24 * 1024 * 1024).fill(randomBytes(4096))
    inputs = ['core-unit', 'cms-e2e'].map(suite => zipInput(Array.from({ length: 3 }, (_, i) => ({ name: `${suite}/f${i}`, bytes: large, method: 8 }))))
  }
  if (mode === 'too-many-inputs') inputs.push(inputs[0]!)
  const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  await expect(validateArtifactPayload({ input: inputs, stagingParent: scratch, trusted })).rejects.toThrow(mode === 'global-bytes' ? /total budget|actual decompression budget/ : mode === 'global-count' ? /entry count budget/ : ['duplicate', 'case', 'prefix'].includes(mode) ? /cross-input/ : undefined)
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})
test('whole-batch accepts failed unit suite with CMS skipped', async () => {
  const p = payload(); const trusted = context(); trusted.jobs[0]!.steps[0]!.conclusion = 'failure'
  p.manifest.outcome = 'failed'; Object.assign(p.native.tests[0]!.attempts[0]!, { status: 'failed' }); p.save()
  const result = await validateArtifactPayload({ input: [zipInput(archive(p))], stagingParent: scratch, trusted })
  expect(result.invocations[0]!.counts.failed).toBe(1); expect(result.invocations).toHaveLength(1)
  rmSync(result.root, { recursive: true, force: true })
})

test('whole-batch composes two actual native per-suite ZIPs offline', async () => {
  const p = payload(); const trusted = context(); trusted.jobs[0]!.steps[1]!.conclusion = 'success'
  const cms = join(p.root, 'cms-e2e', p.manifest.invocation); mkdirSync(cms, { recursive: true })
  const home = mkdtempSync(join(scratch, 'batch-native-home-'))
  const env = { PATH: process.env.PATH, HOME: home, TMPDIR: scratch, CI: '1', GITHUB_REPOSITORY: 'SonicJs-Org/sonicjs', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', FK_ENV_SOURCE: 'ci', NODE_OPTIONS: `--require=${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}` }
  const playwright = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/@playwright/test/cli.js'), 'test', '--config', join(repositoryRoot, 'tests/reporting/fixtures/artifact-playwright.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25000,
    env: { ...env, FK_ENV_SUITE: 'cms-e2e', FK_ENV_TARGET: 'preview-worker', ARTIFACT_NATIVE_OUTPUT: join(cms, 'vendor'), ARTIFACT_NATIVE_RESULTS: join(home, 'results') },
  })
  expect(playwright.error).toBeUndefined(); expect(playwright.status, playwright.stdout + playwright.stderr).toBe(0)
  const cmsReport = validateNativeReport(readFileSync(join(cms, 'vendor/report.json')))
  trusted.producer.headSha = cmsReport.commitId
  p.manifest.commit = cmsReport.commitId; p.save()
  writeFileSync(join(cms, 'invocation.json'), JSON.stringify({ ...p.manifest, suite: 'cms-e2e', target: 'preview-worker' }))
  const vitest = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(repositoryRoot, 'tests/reporting/fixtures/artifact-native.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25000,
    env: { ...env, FK_ENV_SUITE: 'core-unit', FK_ENV_TARGET: 'none', ARTIFACT_NATIVE_OUTPUT: join(p.dir, 'vendor'), ARTIFACT_NATIVE_COMMIT: cmsReport.commitId },
  })
  expect(vitest.error).toBeUndefined(); expect(vitest.status, vitest.stdout + vitest.stderr).toBe(0)
  const entries: Parameters<typeof zip>[0] = []
  const walk = (dir: string, prefix = '') => { for (const name of readdirSync(dir)) { const path = join(dir, name); const key = prefix ? `${prefix}/${name}` : name; if (lstatSync(path).isDirectory()) walk(path, key); else entries.push({ name: key, bytes: readFileSync(path) }) } }
  walk(p.root)
  const core = entries.filter(e => e.name.startsWith('core-unit/')); const cmsEntries = entries.filter(e => e.name.startsWith('cms-e2e/'))
  const result = await validateArtifactPayload({ input: [zipInput(core), zipInput(cmsEntries)], stagingParent: scratch, trusted })
  expect(result.invocations).toHaveLength(2); await verifyUploadSnapshots(result)
  for (const invocation of result.invocations) expect(readFileSync(invocation.reportPath)).toEqual(readFileSync(join(p.root, invocation.suite, invocation.invocation, 'vendor/report.json')))
  // Exercise native vendor reports, attachments and actual upload command together.
  const runtimeDir = mkdtempSync(join(scratch, 'native-runtime-'))
  mkdirSync(join(runtimeDir, 'node_modules/.bin'), { recursive: true })
  writeFileSync(join(runtimeDir, 'package-lock.json'), '{}')
  writeFileSync(join(runtimeDir, 'node_modules/.bin/flakiness'), `#!/bin/sh\nexec "${process.execPath}" --require "${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}" "${join(repositoryRoot, 'tests/reporting/fixtures/fake-cli-upload-command.mjs')}" "$@"\n`, { mode: 0o755 })
  const { executeUpload } = await import('../../scripts/testing/upload-flakiness.mjs')
  const uploaded = await executeUpload(result, { runtimeDir, ledgerDir: mkdtempSync(join(scratch, 'native-ledger-')), privateScratchDir: join(runtimeDir, 'cli-private') }, { accessToken: 'fake' }, { enableUpload: true })
  expect(uploaded.results.map(r => r.state)).toEqual(['accepted-unverified', 'accepted-unverified'])
  rmSync(result.root, { recursive: true, force: true })
})

test('native import failure with zero tests preserves explicit suite-error failure', async () => {
  const p = payload(); const trusted = context(); trusted.jobs[0]!.steps[0]!.conclusion = 'failure'
  p.manifest.outcome = 'failed'; p.save()
  const home = mkdtempSync(join(scratch, 'import-error-home-'))
  const child = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(repositoryRoot, 'tests/reporting/fixtures/artifact-native.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25000,
    env: { PATH: process.env.PATH, HOME: home, TMPDIR: scratch, CI: '1', GITHUB_REPOSITORY: 'SonicJs-Org/sonicjs', GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', FK_ENV_SUITE: 'core-unit', FK_ENV_SOURCE: 'ci', FK_ENV_TARGET: 'none', ARTIFACT_NATIVE_IMPORT_ERROR: '1', ARTIFACT_NATIVE_OUTPUT: join(p.dir, 'vendor'), NODE_OPTIONS: `--require=${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}` },
  })
  expect(child.error).toBeUndefined(); expect(child.status, child.stdout + child.stderr).toBe(1)
  const bytes = readFileSync(join(p.dir, 'vendor/report.json')); const native = validateNativeReport(bytes)
  expect(native.unattributedErrors?.length).toBeGreaterThan(0)
  const result = await validate(p.root, trusted)
  expect(result.invocations[0]).toMatchObject({ outcome: 'failed', counts: { tests: 0, attempts: 0, passed: 0, failed: 0, skipped: 0, suiteErrors: native.unattributedErrors!.length } })
  expect(readFileSync(result.invocations[0]!.reportPath)).toEqual(bytes); await verifyUploadSnapshots(result)
  rmSync(result.root, { recursive: true, force: true })
})
test.each(['failed-no-error', 'success-with-error', 'success-empty', 'interrupted-with-error', 'skipped-with-error'])('zero-test evidence rejects %s', async mode => {
  const p = payload(); const trusted = context(); p.native.tests = []
  if (mode !== 'failed-no-error' && mode !== 'success-empty') Object.assign(p.native, { unattributedErrors: [{ message: 'controlled runner diagnostic' }] })
  if (mode === 'failed-no-error' || mode === 'interrupted-with-error' || mode === 'skipped-with-error') { trusted.jobs[0]!.steps[0]!.conclusion = 'failure'; p.manifest.outcome = mode === 'interrupted-with-error' ? 'interrupted' : 'failed' }
  if (mode === 'skipped-with-error') trusted.jobs[0]!.steps[0]!.conclusion = 'skipped'
  p.save(); const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-'))
  await expect(validate(p.root, trusted)).rejects.toThrow()
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})

test('trusted intake leaves source free of interpreter caches', async () => {
  const p = payload(); const result = await validate(p.root); await verifyUploadSnapshots(result)
  expect(readdirSync(join(repositoryRoot, 'scripts/testing'))).not.toContain('xcrun_db')
  expect(readdirSync(join(repositoryRoot, 'scripts/testing'))).not.toContain('__pycache__')
  expect(readdirSync(join(repositoryRoot, 'tests/reporting/fixtures'))).not.toContain('__pycache__')
  rmSync(result.root, { recursive: true, force: true })
})

test('trusted bridge tolerates bounded interpreter startup warning with valid success protocol', async () => {
  const p = payload(); fsFault.bridgeWarning = 128
  try {
    const result = await validate(p.root); expect(readFileSync(result.invocations[0]!.reportPath)).toEqual(Buffer.from(JSON.stringify(p.native)))
    await verifyUploadSnapshots(result); rmSync(result.root, { recursive: true, force: true })
  } finally { fsFault.bridgeWarning = 0 }
})
test('trusted bridge stderr overflow rejects generically without snapshots or raw diagnostics', async () => {
  const p = payload(); const before = readdirSync(scratch).filter(x => x.startsWith('snapshot-')); fsFault.bridgeWarning = 8192
  try { await expect(validate(p.root)).rejects.toThrow('Invalid artifact: safe POSIX intake failed') }
  finally { fsFault.bridgeWarning = 0 }
  expect(readdirSync(scratch).filter(x => x.startsWith('snapshot-'))).toEqual(before)
})

test('trusted bridge malformed protocol rejects generically without data excerpts', async () => {
  const p = payload(); fsFault.malformedProtocol = true
  try {
    let failure: unknown
    try { const result = await validate(p.root); rmSync(result.root, { recursive: true, force: true }) } catch (error) { failure = error }
    expect(failure).toBeInstanceOf(Error)
    expect((failure as Error).message).toBe('Invalid artifact: safe POSIX intake failed')
  } finally { fsFault.malformedProtocol = false }
})


test.each(['root', 'nested'])('streaming enumeration consumes only remaining global budget+1: %s', mode => {
  const root = mkdtempSync(join(scratch, 'enumeration-'))
  const dir = mode === 'root' ? root : join(root, 'a-child')
  if (mode === 'nested') { mkdirSync(dir); writeFileSync(join(root, 'z-sibling'), '') }
  for (let i = 0; i < 10; i++) writeFileSync(join(dir, `entry-${i}`), '')
  const child = spawnSync('/usr/bin/python3', ['-I', '-S', '-B', join(repositoryRoot, 'tests/reporting/fixtures/artifact-intake-harness.py'), join(repositoryRoot, 'scripts/testing/read-flakiness-artifacts.py'), root, root, `enumeration-${mode}`, 'directory'], { cwd: '/', env: { TMPDIR: scratch }, encoding: 'utf8', timeout: 5000 })
  expect(child.error).toBeUndefined(); expect(child.status, child.stderr).toBe(0)
  expect(JSON.parse(child.stdout)).toEqual({ consumed: mode === 'root' ? [4] : [2, 2], closed: true, rejected: true })
})


// Synthetic schema-valid stress cases, not live producer evidence.
test.each(['suites', 'tests', 'steps'])('synthetic wide %s reaches recursive helpers within documented budgets', async mode => {
  const p = payload()
  const width = 140_000
  const data = Buffer.from('wide-step-attachment')
  const id = createHash('sha1').update(data).digest('hex')
  const attachments = [{ id, name: 'log', contentType: 'text/plain' }]
  if (mode === 'suites') {
    Object.assign(p.native, { suites: [{ type: 'suite', title: 'outer', suites: Array.from({ length: width }, () => ({ type: 'suite', title: 's' })), tests: [{ title: 'nested', attempts: [{}] }] }] })
  } else if (mode === 'tests') {
    p.native.tests = []
    Object.assign(p.native, { suites: [{ type: 'suite', title: 'outer', tests: Array.from({ length: width }, () => ({ title: 't', attempts: [{}] })) }] })
  } else {
    let steps: unknown[] = Array.from({ length: width }, () => ({ title: 's' }))
    steps[width - 1] = { title: 'attachment', attachments }
    for (let i = 0; i < 12; i++) steps = [{ title: 'nested', steps }]
    Object.assign(p.native.tests[0]!.attempts[0]!, { steps })
    writeFileSync(join(p.dir, 'vendor/attachments', id), data)
  }
  const bytes = Buffer.from(JSON.stringify(p.native))
  expect(bytes.length).toBeLessThan(16 * 1024 * 1024)
  // Native parsing/preflight succeeds before intake: no unrelated budget rejection.
  expect(validateNativeReport(bytes).category).toBe('vitest')
  p.save()
  const result = await validate(p.root)
  expect(result.invocations[0]!.counts).toEqual({ tests: mode === 'tests' ? width : mode === 'suites' ? 2 : 1, attempts: mode === 'tests' ? width : mode === 'suites' ? 2 : 1, passed: mode === 'tests' ? width : mode === 'suites' ? 2 : 1, failed: 0, skipped: 0, suiteErrors: 0 })
  expect(readFileSync(result.invocations[0]!.reportPath)).toEqual(bytes)
  await verifyUploadSnapshots(result)
  rmSync(result.root, { recursive: true, force: true })
  if (mode === 'steps') {
    rmSync(join(p.dir, 'vendor/attachments', id))
    await expect(validate(p.root)).rejects.toThrow(/missing attachment/)
  }
})


test('trusted intake requires Python FD-scandir capability before reading request', () => {
  const child = spawnSync('/usr/bin/python3', ['-I', '-S', '-B', join(repositoryRoot, 'tests/reporting/fixtures/artifact-intake-harness.py'), join(repositoryRoot, 'scripts/testing/read-flakiness-artifacts.py'), scratch, scratch, 'capability', 'directory'], { cwd: '/', encoding: 'utf8', timeout: 5000 })
  expect(child.error).toBeUndefined(); expect(child.status, child.stderr).toBe(0)
  expect(child.stderr.trim()).toBe('Invalid artifact: safe POSIX intake failed')
  expect(JSON.parse(child.stdout)).toEqual({ rejected: true })
})
