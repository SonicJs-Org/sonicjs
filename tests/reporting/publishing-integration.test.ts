import { expect, test, vi, afterEach } from 'vitest'
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, cpSync, readdirSync, rmSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { fetchProducerProvenance } from '../../scripts/testing/fetch-producer-provenance.mjs'
import { validateArtifactPayload } from '../../scripts/testing/validate-flakiness-artifacts.mjs'
import { executeUpload } from '../../scripts/testing/upload-flakiness.mjs'
import { repositoryRoot } from './options'
import { reportingScratch } from './scratch'
import { spawnSync } from 'node:child_process'
import { symlinkSync, chmodSync } from 'node:fs'
import { resolve } from 'node:path'

const scratch = reportingScratch('publishing-')
const repo = 'SonicJs-Org/sonicjs'
const sha = 'a'.repeat(40)
const apiRoot = `/repos/${repo}`
/** Exact, synthetic GitHub API fixtures; no network or credentials. */
function apiFixture(event = 'push', headRepo = repo) {
  const identityName = `authorize:123:2:${event}:${event === 'push' ? 0 : 42}:${headRepo}:${sha}`
  const job = (name: string, id: number, step: string, conclusion = 'success') => ({ name, id, run_id: 123, run_attempt: 2, status: 'completed', conclusion, steps: step ? [{ number: 4, name: step, status: 'completed', conclusion }] : [] })
  const jobs = [job(identityName, 1, ''), job('unit-tests', 10, 'Run unit tests with coverage'), job('e2e-local', 11, 'Run full E2E regression suite'), job('e2e-shard', 12, '', 'skipped'), job('e2e-locked', 13, '', 'skipped')]
  const run = { id: 123, run_attempt: 2, repository: { full_name: repo }, workflow_id: 207092903, path: '.github/workflows/pr-tests.yml', name: 'PR Tests', event, status: 'completed', conclusion: 'success', head_branch: 'main', head_sha: event === 'push' ? sha : 'b'.repeat(40), pull_requests: [] }
  const pr = { number: 42, base: { repo: { full_name: repo } }, head: { sha, repo: { full_name: headRepo } } }
  const responses: Record<string, unknown> = { [`${apiRoot}/actions/runs/123/attempts/2`]: run, [`${apiRoot}/actions/runs/123`]: run, [`${apiRoot}/actions/runs/123/attempts/2/jobs?per_page=100&page=1`]: { jobs, total_count: jobs.length }, [`${apiRoot}/actions/runs/123/attempts/2/jobs`]: { jobs, total_count: jobs.length }, [`${apiRoot}/pulls/42`]: pr }
  for (const value of Object.values(responses)) if (value && typeof value === 'object' && 'jobs' in value) Object.defineProperty(value, 'total_count', { get: () => jobs.length, enumerable: true })
  vi.stubGlobal('fetch', vi.fn(async (url: string) => { const path = url.replace('https://api.github.com', ''); if (!(path in responses)) throw new Error(`Unexpected API: ${path}`); return { ok: true, json: async () => structuredClone(responses[path]) } }))
  return { run, jobs, pr, responses }
}
async function provenance() { return fetchProducerProvenance({ repository: repo, runId: 123, runAttempt: 2, token: 'fake' }) }
afterEach(() => vi.unstubAllGlobals())

test.each([['push', repo], ['pull_request_target', repo], ['pull_request_target', 'Contributor/sonicjs'], ['pull_request_target', 'dependabot/sonicjs']])('API adapter binds %s %s with empty run PR array', async (event, headRepo) => {
  apiFixture(event, headRepo)
  const p = await provenance()
  expect(p.jobs.find(j => j.key === 'unit-tests')?.id).toBe(10)
  if (event !== 'push') expect(p.originalPullRequests).toEqual([{ number: 42, baseRepository: repo, headRepository: headRepo, headSha: sha }])
})
test.each(['stale', 'changed-repo', 'deleted-repo', 'missing-auth', 'wrong-auth-attempt', 'cancelled', 'rerun'])('API adapter rejects %s without live-head fallback', async mode => {
  const f = apiFixture('pull_request_target', 'Contributor/sonicjs')
  if (mode === 'stale') f.pr.head.sha = 'c'.repeat(40)
  if (mode === 'changed-repo') f.pr.head.repo.full_name = 'Other/sonicjs'
  if (mode === 'deleted-repo') f.pr.head.repo = null as any
  if (mode === 'missing-auth') f.jobs.shift()
  if (mode === 'wrong-auth-attempt') f.jobs[0]!.name = f.jobs[0]!.name.replace(':2:', ':1:')
  if (mode === 'cancelled') f.run.conclusion = 'cancelled'
  if (mode === 'rerun') f.run.run_attempt = 3
  await expect(provenance()).rejects.toThrow()
})
test('API adapter collects all four shards and locked job', async () => {
  const f = apiFixture()
  f.jobs.splice(2)
  for (let shard = 1; shard <= 4; shard++) f.jobs.push({ name: `e2e-shard (${shard})`, id: 20 + shard, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'success', steps: [{ number: 4, name: `Run E2E regression suite — shard ${shard}/4 (non-locked tests)`, status: 'completed', conclusion: 'success' }] })
  f.jobs.push({ name: 'e2e-locked', id: 25, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'success', steps: [{ number: 4, name: 'Run @lock-* tagged E2E tests (serial — shared auth/plugin state)', status: 'completed', conclusion: 'success' }] }, { name: 'e2e-local', id: 26, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'skipped', steps: [] })
  const p = await provenance()
  expect(p.jobs.filter(j => j.key === 'e2e-shard').map(j => j.shard)).toEqual(['1-of-4', '2-of-4', '3-of-4', '4-of-4'])
})

/** Model upload-artifact's single-directory root and download's merged tree. */
function artifactTree() {
  const producer = mkdtempSync(join(scratch, 'producer-'))
  const downloaded = mkdtempSync(join(scratch, 'download-'))
  for (const [suite, job, target, category, name] of [['core-unit', 'unit-tests', 'none', 'vitest', 'vitest'], ['cms-e2e', 'e2e-local', 'local-worker', 'playwright', 'chromium']]) {
    const inv = `${job}-local-2-12345678-1234-4234-8234-123456789abc`
    const dir = join(producer, 'flakiness-reports', suite!, inv)
    mkdirSync(join(dir, 'vendor'), { recursive: true })
    const manifest = { suite, job, target, invocation: inv, source: 'ci', commit: sha, runId: '123', attempt: '2', workflow: 'PR Tests', startedAt: '2026-01-01T00:00:00Z', endedAt: '2026-01-01T00:00:01Z', outcome: 'passed', pullRequestStatus: 'no-pr', runURL: `https://github.com/${repo}/actions/runs/123` }
    writeFileSync(join(dir, 'invocation.json'), JSON.stringify(manifest))
    writeFileSync(join(dir, 'vendor/report.json'), JSON.stringify({ category, commitId: sha, environments: [{ name, metadata: { suite, target, source: 'ci' } }], startTimestamp: 1, duration: 1, url: manifest.runURL, tests: [{ title: `${suite}/passing`, attempts: [{}] }] }))
  }
  const workflow = parse(readFileSync(join(repositoryRoot, '.github/workflows/pr-tests.yml'), 'utf8'))
  for (const [key, suite] of [['unit-tests', 'core-unit'], ['e2e-local', 'cms-e2e']]) {
    const artifact = workflow.jobs[key!].steps.find((s: any) => s.name?.includes(`${suite} Flakiness reports`))
    // Match the archive root that upload-artifact uses for a single directory.
    // Every job has a separate workspace; only its own suite exists in that root.
    const uploadRoot = join(producer, artifact.with.path)
    const jobRoot = mkdtempSync(join(scratch, 'job-artifact-'))
    cpSync(uploadRoot, jobRoot, { recursive: true })
    const other = suite === 'core-unit' ? 'cms-e2e' : 'core-unit'
    rmSync(join(jobRoot, other), { recursive: true, force: true })
    cpSync(jobRoot, downloaded, { recursive: true })
  }
  return downloaded
}
function runtime(script: string) {
  const root = mkdtempSync(join(scratch, 'runtime-'))
  mkdirSync(join(root, 'node_modules/.bin'), { recursive: true })
  writeFileSync(join(root, 'package-lock.json'), '{}')
  writeFileSync(join(root, 'node_modules/.bin/flakiness'), `#!/bin/sh\nexec "${process.execPath}" --require "${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}" "${fileURLToPath(new URL(`fixtures/${script}`, import.meta.url))}" "$@"\n`, { mode: 0o755 })
  return relative(repositoryRoot, root)
}
test('actual artifact layout → complete validation → relative runtime CLI; rerun blocks duplicate', async () => {
  apiFixture()
  const snapshots = await validateArtifactPayload({ input: { kind: 'directory', path: artifactTree() }, stagingParent: scratch, trusted: await provenance() })
  const ledgerDir = mkdtempSync(join(scratch, 'ledger-'))
  const config = { runtimeDir: runtime('fake-cli-url.mjs'), ledgerDir, privateScratchDir: join(scratch, 'cli-private') }
  const result = await executeUpload(snapshots, config, { accessToken: 'fake' }, { enableUpload: true })
  expect(result.results.map(r => r.state)).toEqual(['accepted-unverified', 'accepted-unverified'])
  const rerun = await executeUpload(snapshots, config, { accessToken: 'fake' }, { enableUpload: true })
  expect(rerun.results.map(r => r.state)).toEqual(['blocked', 'blocked'])
  expect(readdirSync(ledgerDir).filter(x => x.endsWith('.json'))).toHaveLength(2)
})
test('missing executed suite fails closed before any delivery', async () => {
  apiFixture()
  const input = artifactTree()
  const { rmSync } = await import('node:fs')
  rmSync(join(input, 'cms-e2e'), { recursive: true })
  await expect(validateArtifactPayload({ input: { kind: 'directory', path: input }, stagingParent: scratch, trusted: await provenance() })).rejects.toThrow('missing suite evidence')
})

test('first CLI failure does not suppress second suite; failed delivery cannot be blindly retried', async () => {
  apiFixture()
  const snapshots = await validateArtifactPayload({ input: { kind: 'directory', path: artifactTree() }, stagingParent: scratch, trusted: await provenance() })
  const config = { runtimeDir: runtime('fake-cli-core-fail.mjs'), ledgerDir: mkdtempSync(join(scratch, 'independent-')), privateScratchDir: join(scratch, 'cli-private') }
  const ordered = { ...snapshots, invocations: [...snapshots.invocations].sort((a, b) => a.suite === 'core-unit' ? -1 : 1) }
  const r = await executeUpload(ordered, config, { accessToken: 'fake' }, { enableUpload: true })
  expect(r.results.map(x => x.state)).toEqual(['failed', 'accepted-unverified'])
  expect(r.anyFailed).toBe(true)
  const retry = await executeUpload(snapshots, config, { accessToken: 'fake' }, { enableUpload: true })
  expect(retry.results.map(x => x.state)).toEqual(['blocked', 'blocked'])
  expect(retry.anyFailed).toBe(true)
})

test('trusted project configuration controls CLI destination, never native report fields', async () => {
  apiFixture()
  const input = artifactTree()
  const { readdirSync } = await import('node:fs')
  const inv = readdirSync(join(input, 'core-unit'))[0]!
  const path = join(input, 'core-unit', inv, 'vendor/report.json')
  const native = JSON.parse(readFileSync(path, 'utf8')); native.flakinessProject = 'Configured/project'
  writeFileSync(path, JSON.stringify(native))
  const snapshots = await validateArtifactPayload({ input: { kind: 'directory', path: input }, stagingParent: scratch, trusted: await provenance(), project: 'Configured/project' })
  expect(snapshots.invocations).toHaveLength(2)
})

test('all sharded manifests bind independently; missing or forged shard never masquerades as complete', async () => {
  const f = apiFixture()
  f.jobs.splice(2)
  for (let shard = 1; shard <= 4; shard++) f.jobs.push({ name: `e2e-shard (${shard})`, id: 20 + shard, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'success', steps: [{ number: 4, name: `Run E2E regression suite — shard ${shard}/4 (non-locked tests)`, status: 'completed', conclusion: 'success' }] })
  f.jobs.push({ name: 'e2e-locked', id: 25, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'success', steps: [{ number: 4, name: 'Run @lock-* tagged E2E tests (serial — shared auth/plugin state)', status: 'completed', conclusion: 'success' }] }, { name: 'e2e-local', id: 26, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'skipped', steps: [] })
  const input = artifactTree()
  const { rmSync } = await import('node:fs')
  const original = join(input, 'cms-e2e', readdirSync(join(input, 'cms-e2e'))[0]!)
  const manifest = JSON.parse(readFileSync(join(original, 'invocation.json'), 'utf8'))
  const native = JSON.parse(readFileSync(join(original, 'vendor/report.json'), 'utf8'))
  rmSync(original, { recursive: true })
  for (const shard of ['1-of-4', '2-of-4', '3-of-4', '4-of-4', undefined]) {
    const job = shard ? 'e2e-shard' : 'e2e-locked'
    const invocation = `${job}-${shard ?? 'local'}-2-12345678-1234-4234-8234-123456789abc`
    const dir = join(input, 'cms-e2e', invocation)
    mkdirSync(join(dir, 'vendor'), { recursive: true })
    writeFileSync(join(dir, 'invocation.json'), JSON.stringify({ ...manifest, job, shard, invocation, target: 'preview-worker' }))
    native.environments[0].metadata.target = 'preview-worker'
    writeFileSync(join(dir, 'vendor/report.json'), JSON.stringify(native))
  }
  const trusted = await provenance()
  const batch = await validateArtifactPayload({ input: { kind: 'directory', path: input }, stagingParent: scratch, trusted })
  expect(batch.invocations).toHaveLength(6)
  expect(batch.invocations.map(i => i.jobId).sort((a, b) => a - b)).toEqual([10, 21, 22, 23, 24, 25])
  // A failing shard remains publishable failure evidence while locked may be skipped.
  const failedDir = join(input, 'cms-e2e', 'e2e-shard-1-of-4-2-12345678-1234-4234-8234-123456789abc')
  const failedManifest = JSON.parse(readFileSync(join(failedDir, 'invocation.json'), 'utf8'))
  const failedNative = JSON.parse(readFileSync(join(failedDir, 'vendor/report.json'), 'utf8'))
  failedManifest.outcome = 'failed'; failedNative.tests[0].attempts[0].status = 'failed'
  writeFileSync(join(failedDir, 'invocation.json'), JSON.stringify(failedManifest))
  writeFileSync(join(failedDir, 'vendor/report.json'), JSON.stringify(failedNative))
  trusted.producer.conclusion = 'failure'
  trusted.jobs.find(j => j.id === 21)!.steps[0]!.conclusion = 'failure'
  const failures = await validateArtifactPayload({ input: { kind: 'directory', path: input }, stagingParent: scratch, trusted })
  expect(failures.invocations.find(i => i.jobId === 21)).toMatchObject({ outcome: 'failed', counts: { failed: 1 } })
  const path = join(input, 'cms-e2e', 'e2e-shard-4-of-4-2-12345678-1234-4234-8234-123456789abc', 'invocation.json')
  const fourth = JSON.parse(readFileSync(path, 'utf8'))
  writeFileSync(path, JSON.stringify({ ...fourth, shard: '3-of-4' }))
  await expect(validateArtifactPayload({ input: { kind: 'directory', path: input }, stagingParent: scratch, trusted })).rejects.toThrow()
  rmSync(join(path, '..'), { recursive: true })
  await expect(validateArtifactPayload({ input: { kind: 'directory', path: input }, stagingParent: scratch, trusted })).rejects.toThrow('missing suite evidence')
})


test.each(['skipped', 'cancelled', 'neutral'])('non-publishable run conclusion %s fails explicitly', async conclusion => {
  const f = apiFixture(); f.run.conclusion = conclusion
  await expect(provenance()).rejects.toThrow('run not publishable')
})
test('failed unit with all E2E jobs skipped retains failure and not-run outcomes', async () => {
  const f = apiFixture(); f.run.conclusion = 'failure'
  f.jobs[1]!.conclusion = 'failure'; f.jobs[1]!.steps[0]!.conclusion = 'failure'
  f.jobs[2]!.conclusion = 'skipped'; f.jobs[2]!.steps = []
  const { validateProducerProvenance } = await import('../../scripts/testing/validate-flakiness-artifacts.mjs')
  const p = validateProducerProvenance(await provenance())
  expect(p.suites.filter(s => s.ran)).toMatchObject([{ suite: 'core-unit', conclusion: 'failure' }])
  expect(p.suites.filter(s => !s.ran)).toHaveLength(3)
})
test('historical association repository is checked independently of live PR identity', async () => {
  const f = apiFixture('pull_request_target', 'Contributor/sonicjs')
  f.run.pull_requests = [{ number: 42, head: { sha, repo: { id: 2, name: 'sonicjs', url: 'https://api.github.com/repos/Other/sonicjs' } } }] as any
  await expect(provenance()).rejects.toThrow('Historical PR association mismatch')
})
test('metadata pagination is complete and unrelated jobs never become suites', async () => {
  const f = apiFixture()
  f.responses[`${apiRoot}/actions/runs/123/attempts/2/jobs?per_page=100&page=1`] = { jobs: f.jobs.slice(0, 2), total_count: 6 }
  f.responses[`${apiRoot}/actions/runs/123/attempts/2/jobs?per_page=100&page=2`] = { jobs: [...f.jobs.slice(2), { id: 70, name: 'cleanup', run_id: 123, run_attempt: 2 }], total_count: 6 }
  expect((await provenance()).jobs).toHaveLength(4)
})

function entrypointFixture(script = 'fake-cli-upload-command.mjs', event = 'push') {
  const f = apiFixture(event)
  const dir = mkdtempSync(join(scratch, 'entrypoint-'))
  const apiPath = join(dir, 'api.json'); writeFileSync(apiPath, JSON.stringify(f.responses))
  const runtimeDir = resolve(repositoryRoot, runtime(script))
  for (const name of ['validate-flakiness-artifacts.mjs', 'read-flakiness-artifacts.py', 'upload-flakiness.mjs', 'fetch-producer-provenance.mjs', 'run-flakiness-upload.mjs', 'delivery-ledger.mjs', 'export-flakiness-ledger.mjs']) cpSync(join(repositoryRoot, 'scripts/testing', name), join(runtimeDir, name))
  // Use existing pinned validator dependencies; never install or execute package hooks.
  mkdirSync(join(runtimeDir, 'node_modules/@flakiness'), { recursive: true })
  symlinkSync(join(repositoryRoot, 'node_modules/@flakiness/flakiness-report'), join(runtimeDir, 'node_modules/@flakiness/flakiness-report'))
  symlinkSync(join(repositoryRoot, 'node_modules/yauzl'), join(runtimeDir, 'node_modules/yauzl'))
  const ledger = mkdtempSync(join(dir, 'ledger-'))
  const env = { PATH: process.env.PATH, TMPDIR: scratch, GITHUB_REPOSITORY: repo, GITHUB_TOKEN: 'fake', GITHUB_RUN_ID: '900', GITHUB_RUN_ATTEMPT: '1', PRODUCER_RUN_ID: '123', PRODUCER_RUN_ATTEMPT: '2', FLAKINESS_PROJECT: 'Configured/project', ARTIFACT_DIR: artifactTree(), STAGING_DIR: join(dir, 'staging'), LEDGER_DIR: ledger, RUNTIME_DIR: runtimeDir, ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.invalid', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fake', PUBLISH_API_FIXTURE: apiPath, GITHUB_STEP_SUMMARY: join(dir, 'summary.md') }
  const args = ['--require', join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs'), '--import', fileURLToPath(new URL('fixtures/fake-github-api.mjs', import.meta.url)), join(runtimeDir, 'run-flakiness-upload.mjs')]
  return { f, dir, runtimeDir, ledger, env: { ...env, CLI_SCRATCH_DIR: join(dir, 'cli-private') }, args }
}

test('main-only copied entrypoint executes both suites, persists history and refuses fresh-runner resubmission', async () => {
  const { dir, ledger, env, args } = entrypointFixture()
  const first = spawnSync(process.execPath, args, { cwd: dir, env, encoding: 'utf8', timeout: 15000 })
  expect(first.error).toBeUndefined(); expect(first.status, first.stdout + first.stderr).toBe(0)
  expect(first.stdout.match(/accepted-unverified/g)).toHaveLength(2)
  const accepted = readdirSync(ledger).filter(x => x !== 'checkpoint.json').map(x => readFileSync(join(ledger, x), 'utf8'))
  expect(accepted).toHaveLength(2)
  const restored = mkdtempSync(join(dir, 'restored-')); cpSync(ledger, restored, { recursive: true })
  const second = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: restored, GITHUB_RUN_ATTEMPT: '2' }, encoding: 'utf8', timeout: 15000 })
  expect(second.status, second.stdout + second.stderr).toBe(1)
  expect(second.stdout.match(/: blocked/g)).toHaveLength(2)
  expect(readdirSync(restored).filter(x => x !== 'checkpoint.json').map(x => readFileSync(join(restored, x), 'utf8'))).toEqual(accepted)
  const empty = mkdtempSync(join(dir, 'lost-'))
  const third = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: empty, GITHUB_RUN_ATTEMPT: '3' }, encoding: 'utf8', timeout: 15000 })
  expect(third.status, third.stdout + third.stderr).toBe(1)
  expect(readdirSync(empty)).toEqual([])
})

test('spawn EACCES is not-started; sealed exported ledger permits corrected runtime on fresh runner', async () => {
  const { dir, runtimeDir, ledger, env, args } = entrypointFixture()
  const cli = join(runtimeDir, 'node_modules/.bin/flakiness')
  chmodSync(cli, 0o600) // Real spawn error, not a fake nonzero child exit.
  const first = spawnSync(process.execPath, args, { cwd: dir, env, encoding: 'utf8', timeout: 15000 })
  expect(first.error).toBeUndefined(); expect(first.status, first.stdout + first.stderr).toBe(1)
  expect(first.stdout.match(/: not-started/g)).toHaveLength(2)
  expect(JSON.parse(readFileSync(join(ledger, 'checkpoint.json'), 'utf8')).consumerAttempt).toBe(1)
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const restored = join(dir, 'restored')
  await exportDeliveryLedger(ledger, restored)
  chmodSync(cli, 0o755)
  const second = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: restored, GITHUB_RUN_ATTEMPT: '2' }, encoding: 'utf8', timeout: 15000 })
  expect(second.status, second.stdout + second.stderr).toBe(0)
  expect(second.stdout.match(/accepted-unverified/g)).toHaveLength(2)
  expect(JSON.parse(readFileSync(join(restored, 'checkpoint.json'), 'utf8')).consumerAttempt).toBe(2)
})

test.each([['first', false], ['second', false], ['first', true], ['second', true]])('POSIX %s scratch allocation EACCES (controlled UID 0=%s) leaves no started record; sealed fresh-runner retry is safe', async (allocation, controlledRoot) => {
  const { dir, ledger, env, args } = entrypointFixture()
  mkdirSync(env.CLI_SCRATCH_DIR, { mode: 0o700 })
  let first: ReturnType<typeof spawnSync>
  try {
    const failingArgs = ['--import', fileURLToPath(new URL('fixtures/scratch-allocation-eacces.mjs', import.meta.url)), ...args]
    first = spawnSync(process.execPath, failingArgs, { cwd: dir, env: { ...env, SCRATCH_FAIL_ALLOCATION: allocation as string, ...(controlledRoot ? { SCRATCH_TEST_UID_ZERO: '1' } : {}) }, encoding: 'utf8', timeout: 15000 })
  } finally { chmodSync(env.CLI_SCRATCH_DIR, 0o700) }
  expect(first.error).toBeUndefined(); expect(first.status, String(first.stdout) + first.stderr).toBe(1)
  expect(String(first.stderr)).toMatch(/EACCES.*mkdtemp/)
  expect(String(first.stderr)).toContain(controlledRoot || process.getuid?.() === 0 ? 'Test-only boundary: synthetic UID 0 allocation EACCES' : 'Test-only boundary: real POSIX allocation EACCES')
  expect(String(first.stdout)).not.toMatch(/accepted-unverified|: not-started|: blocked/)
  expect(readdirSync(env.CLI_SCRATCH_DIR)).toEqual([])
  expect(readdirSync(ledger)).toEqual(['checkpoint.json'])
  const seal = JSON.parse(readFileSync(join(ledger, 'checkpoint.json'), 'utf8'))
  expect(seal.consumerAttempt).toBe(1)
  expect(seal.records).toEqual([])
  const { exportDeliveryLedger } = await import('../../scripts/testing/export-flakiness-ledger.mjs')
  const restored = join(dir, 'restored')
  await exportDeliveryLedger(ledger, restored)
  const freshPrivate = join(dir, 'fresh-runner-private')
  const second = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: restored, CLI_SCRATCH_DIR: freshPrivate, GITHUB_RUN_ATTEMPT: '2' }, encoding: 'utf8', timeout: 15000 })
  expect(second.error).toBeUndefined(); expect(second.status, second.stdout + second.stderr).toBe(0)
  expect(second.stdout.match(/accepted-unverified/g)).toHaveLength(2)
  expect(readdirSync(freshPrivate)).toEqual([])
  expect(JSON.parse(readFileSync(join(restored, 'checkpoint.json'), 'utf8')).consumerAttempt).toBe(2)
  const third = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: restored, CLI_SCRATCH_DIR: freshPrivate, GITHUB_RUN_ATTEMPT: '3' }, encoding: 'utf8', timeout: 15000 })
  expect(third.status, third.stdout + third.stderr).toBe(1)
  expect(third.stdout.match(/: blocked/g)).toHaveLength(2)
})

test('abrupt uploader SIGKILL preserves started record, exports no credential caches before cleanup', async () => {
  const { dir, runtimeDir, ledger, env, args } = entrypointFixture('fake-cli-kill-parent.mjs')
  const killed = spawnSync(process.execPath, args, { cwd: dir, env, encoding: 'utf8', timeout: 15000 })
  expect(killed.error).toBeUndefined(); expect(killed.signal).toBe('SIGKILL')
  // Caches survived because finally never ran; must be outside durable ledger.
  const cachePaths = readdirSync(dir, { recursive: true }).map(String).filter(p => p.endsWith('cached-token.json'))
  expect(cachePaths).toHaveLength(2)
  expect(cachePaths.every(p => p.startsWith('cli-private/'))).toBe(true)
  const records = readdirSync(ledger)
  expect(records).toHaveLength(1)
  expect(records[0]).toMatch(/^[a-f0-9]{64}\.json$/)
  expect(JSON.parse(readFileSync(join(ledger, records[0]!), 'utf8')).state).toBe('started')
  const exported = join(dir, 'exported')
  const exportedRun = spawnSync(process.execPath, [join(runtimeDir, 'export-flakiness-ledger.mjs')], { cwd: dir, env: { LEDGER_DIR: ledger, LEDGER_EXPORT_DIR: exported }, encoding: 'utf8', timeout: 15000 })
  expect(exportedRun.status, exportedRun.stdout + exportedRun.stderr).toBe(0)
  expect(readdirSync(exported, { recursive: true })).toEqual(records)
  expect(readFileSync(join(exported, records[0]!), 'utf8')).not.toContain('FAKE-NO-NETWORK-CREDENTIAL')
  const retry = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: exported, GITHUB_RUN_ATTEMPT: '2' }, encoding: 'utf8', timeout: 15000 })
  expect(retry.status, retry.stdout + retry.stderr).toBe(1)
  expect(retry.stderr).toContain('Prior delivery checkpoint unavailable')
})

test.each(['valid', 'cancelled', 'stale', 'unauthorized'])('no executed suites: %s provenance controls full entrypoint before artifacts or CLI/auth', mode => {
  const { f, dir, env, args } = entrypointFixture('fake-cli-upload-command.mjs', 'pull_request_target')
  f.run.conclusion = mode === 'cancelled' ? 'cancelled' : 'failure'
  for (const j of f.jobs.slice(1)) { j.conclusion = 'skipped'; j.steps = [] }
  if (mode === 'stale') f.pr.head.sha = 'c'.repeat(40)
  if (mode === 'unauthorized') f.jobs[0]!.conclusion = 'failure'
  writeFileSync(env.PUBLISH_API_FIXTURE, JSON.stringify(f.responses))
  const safeEnv: Record<string, string | undefined> = { ...env }
  for (const key of ['ARTIFACT_DIR', 'STAGING_DIR', 'RUNTIME_DIR', 'CLI_SCRATCH_DIR', 'FLAKINESS_PROJECT', 'ACTIONS_ID_TOKEN_REQUEST_URL', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN']) delete safeEnv[key]
  const result = spawnSync(process.execPath, args, { cwd: dir, env: safeEnv, encoding: 'utf8', timeout: 15000 })
  expect(result.error).toBeUndefined(); expect(result.status, result.stdout + result.stderr).toBe(mode === 'valid' ? 0 : 1)
  const summary = readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8')
  if (mode === 'valid') expect(summary).toContain('nothing to publish; suites not run')
  else { expect(summary).toContain('Publishing failed'); expect(summary).not.toContain('nothing to publish') }
  expect(readdirSync(env.LEDGER_DIR)).toEqual(['checkpoint.json'])
})

test.each([false, true])('dynamic unrelated PR associations ignored; matching association included=%s', async matching => {
  const f = apiFixture('pull_request_target', 'Contributor/sonicjs')
  const unrelated = [43, 44].map(number => ({ number, head: { sha: 'c'.repeat(40), repo: { id: 2, name: 'sonicjs', url: 'https://api.github.com/repos/Other/sonicjs' } } }))
  f.run.pull_requests = [...unrelated, ...(matching ? [{ number: 42, head: { sha, repo: { id: 3, name: 'sonicjs', url: 'https://api.github.com/repos/Contributor/sonicjs' } } }] : [])] as any
  expect((await provenance()).originalPullRequests?.[0]?.number).toBe(42)
})
test.each(['sha', 'repo'])('matching dynamic association with wrong %s rejects even beside unrelated PRs', async field => {
  const f = apiFixture('pull_request_target', 'Contributor/sonicjs')
  f.run.pull_requests = [{ number: 43 }, { number: 42, head: { sha: field === 'sha' ? 'c'.repeat(40) : sha, repo: { id: 3, name: 'sonicjs', url: `https://api.github.com/repos/${field === 'repo' ? 'Other/sonicjs' : 'Contributor/sonicjs'}` } } }] as any
  await expect(provenance()).rejects.toThrow('Historical PR association mismatch')
})
test.each(['deleted', 'modified', 'added'])('copied entrypoint partial restore %s fails before CLI or auth', mode => {
  const { dir, ledger, env, args } = entrypointFixture()
  const first = spawnSync(process.execPath, args, { cwd: dir, env, encoding: 'utf8', timeout: 15000 })
  expect(first.status, first.stdout + first.stderr).toBe(0)
  const restored = mkdtempSync(join(dir, 'partial-')); cpSync(ledger, restored, { recursive: true })
  const record = readdirSync(restored).find(n => /^[a-f0-9]{64}\.json$/.test(n))!
  if (mode === 'deleted') rmSync(join(restored, record))
  if (mode === 'modified') writeFileSync(join(restored, record), '{"state":"not-started"}')
  if (mode === 'added') writeFileSync(join(restored, `${'f'.repeat(64)}.json`), '{}')
  const before = readFileSync(join(restored, 'checkpoint.json'), 'utf8')
  // Real spawn EACCES would be reported as not-started if ledger preflight were bypassed.
  chmodSync(join(env.RUNTIME_DIR, 'node_modules/.bin/flakiness'), 0o600)
  const result = spawnSync(process.execPath, args, { cwd: dir, env: { ...env, LEDGER_DIR: restored, GITHUB_RUN_ATTEMPT: '2' }, encoding: 'utf8', timeout: 15000 })
  expect(result.status, result.stdout + result.stderr).toBe(1)
  expect(result.stderr).toMatch(/checkpoint.*(inventory|record)/i)
  expect(result.stdout).not.toMatch(/accepted-unverified|: not-started|: blocked/)
  expect(readFileSync(join(restored, 'checkpoint.json'), 'utf8')).toBe(before)
})

test('fixed authorize check coexists with immutable producer metadata job without becoming suite evidence', async () => {
  const f = apiFixture('pull_request_target', 'Contributor/sonicjs')
  f.jobs.push({ name: 'authorize', id: 80, run_id: 123, run_attempt: 2, status: 'completed', conclusion: 'success', steps: [] })
  const p = await provenance()
  expect(p.originalPullRequests?.[0]?.headRepository).toBe('Contributor/sonicjs')
  expect(p.jobs.map(j => j.id)).toEqual([10, 11, 12, 13])
})

test.each(['invocation.json', 'vendor/report.json'].flatMap(file => ['::error::', '::add-mask::', '::stop-commands::'].map(command => [file, command])))('malformed hostile %s with %s never reaches entrypoint logs or summary', async (file, command) => {
  const { dir, ledger, env, args } = entrypointFixture()
  const invocation = readdirSync(join(env.ARTIFACT_DIR, 'core-unit'))[0]!
  const hostile = `\n${command}S\nINJECTION_SENTINEL`
  writeFileSync(join(env.ARTIFACT_DIR, 'core-unit', invocation, file), hostile)
  const { validateNativeReport } = await import('../../scripts/testing/validate-flakiness-artifacts.mjs')
  const safeEnv: Record<string, string | undefined> = { ...env }
  delete safeEnv.ACTIONS_ID_TOKEN_REQUEST_URL; delete safeEnv.ACTIONS_ID_TOKEN_REQUEST_TOKEN
  const result = spawnSync(process.execPath, args, { cwd: dir, env: safeEnv, encoding: 'utf8', timeout: 15000 })
  expect(result.error).toBeUndefined(); expect(result.status).toBe(1)
  const rendered = result.stdout + result.stderr + readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8')
  for (const value of ['INJECTION_SENTINEL', '::error::', '::add-mask::', '::stop-commands::', 'SyntaxError', 'at JSON.parse']) expect(rendered).not.toContain(value)
  expect(result.stderr).toBe('Invalid artifact: JSON syntax\n')
  expect(() => validateNativeReport(Buffer.from(hostile))).toThrow('Invalid artifact: JSON syntax')
  expect(readdirSync(ledger)).toEqual(['checkpoint.json'])
  expect(JSON.parse(readFileSync(join(ledger, 'checkpoint.json'), 'utf8')).records).toEqual([])
  expect(readdirSync(dir)).not.toContain('cli-private')
})

test.each(['https://api.github.com/repos/Other/sonicjs', 'https://user@api.github.com/repos/Contributor/sonicjs', 'https://api.github.com/repos/Contributor/sonicjs?auth=1', 'https://evil.invalid/repos/Contributor/sonicjs'])('matching association repo URL %s fails closed with valid SHA', async url => {
  const f = apiFixture('pull_request_target', 'Contributor/sonicjs')
  f.run.pull_requests = [{ number: 42, head: { sha, repo: { id: 3, name: 'sonicjs', url } } }] as any
  await expect(provenance()).rejects.toThrow('Historical PR association mismatch')
})

test('top-level catch emits fixed category for unexpected upstream text, never raw error or stack', () => {
  const { dir, env, args } = entrypointFixture()
  const hostile = 'Unexpected upstream\n::error::UPSTREAM_SENTINEL\n::add-mask::UPSTREAM_SENTINEL\n::stop-commands::UPSTREAM_SENTINEL'
  const result = spawnSync(process.execPath, [...args.slice(0, -1), '--import', fileURLToPath(new URL('fixtures/hostile-consumer-error.mjs', import.meta.url)), args.at(-1)!], {
    cwd: dir, env: { ...env, PUBLISH_UNTRUSTED_ERROR: hostile }, encoding: 'utf8', timeout: 15000,
  })
  expect(result.error).toBeUndefined(); expect(result.status).toBe(1)
  const rendered = result.stdout + result.stderr + readFileSync(env.GITHUB_STEP_SUMMARY, 'utf8')
  for (const marker of ['UPSTREAM_SENTINEL', '::error::', '::add-mask::', '::stop-commands::', 'at globalThis.fetch']) expect(rendered).not.toContain(marker)
  expect(result.stderr).toBe('Publishing operation failed.\n')
})
