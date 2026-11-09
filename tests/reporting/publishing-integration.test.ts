import { expect, test, vi, afterEach } from 'vitest'
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync, cpSync, readdirSync, rmSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'yaml'
import { fetchProducerProvenance } from '../../scripts/testing/fetch-producer-provenance.mjs'
import { validateArtifactPayload } from '../../scripts/testing/validate-flakiness-artifacts.mjs'
import { executeUpload } from '../../scripts/testing/upload-flakiness.mjs'
import { repositoryRoot } from './options'

const scratch = mkdtempSync(join(process.env.TMPDIR!, 'publishing-'))
const repo = 'SonicJs-Org/sonicjs'
const sha = 'a'.repeat(40)
const apiRoot = `/repos/${repo}`
/** Exact, synthetic GitHub API fixtures; no network or credentials. */
function apiFixture(event = 'push', headRepo = repo) {
  const authName = `authorize:123:2:${event}:${event === 'push' ? 0 : 42}:${headRepo}:${sha}`
  const job = (name: string, id: number, step: string, conclusion = 'success') => ({ name, id, run_id: 123, run_attempt: 2, status: 'completed', conclusion, steps: step ? [{ number: 4, name: step, status: 'completed', conclusion }] : [] })
  const jobs = [job(authName, 1, ''), job('unit-tests', 10, 'Run unit tests with coverage'), job('e2e-local', 11, 'Run full E2E regression suite'), job('e2e-shard', 12, '', 'skipped'), job('e2e-locked', 13, '', 'skipped')]
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
  writeFileSync(join(root, 'node_modules/.bin/flakiness'), `#!/bin/sh\nexec "${process.execPath}" "${fileURLToPath(new URL(`fixtures/${script}`, import.meta.url))}" "$@"\n`, { mode: 0o755 })
  return relative(repositoryRoot, root)
}
test('actual artifact layout → complete validation → relative runtime CLI; rerun blocks duplicate', async () => {
  apiFixture()
  const snapshots = await validateArtifactPayload({ input: { kind: 'directory', path: artifactTree() }, stagingParent: scratch, trusted: await provenance() })
  const ledgerDir = mkdtempSync(join(scratch, 'ledger-'))
  const config = { runtimeDir: runtime('fake-cli-url.mjs'), ledgerDir }
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
  const config = { runtimeDir: runtime('fake-cli-core-fail.mjs'), ledgerDir: mkdtempSync(join(scratch, 'independent-')) }
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
  f.run.pull_requests = [{ number: 42, head: { sha, repo: { full_name: 'Other/sonicjs' } } }] as any
  await expect(provenance()).rejects.toThrow('Historical PR association mismatch')
})
test('metadata pagination is complete and unrelated jobs never become suites', async () => {
  const f = apiFixture()
  f.responses[`${apiRoot}/actions/runs/123/attempts/2/jobs?per_page=100&page=1`] = { jobs: f.jobs.slice(0, 2), total_count: 6 }
  f.responses[`${apiRoot}/actions/runs/123/attempts/2/jobs?per_page=100&page=2`] = { jobs: [...f.jobs.slice(2), { id: 70, name: 'cleanup', run_id: 123, run_attempt: 2 }], total_count: 6 }
  expect((await provenance()).jobs).toHaveLength(4)
})

test('main-only copied entrypoint executes both suites, persists history and refuses fresh-runner resubmission', async () => {
  const { spawnSync } = await import('node:child_process')
  const { symlinkSync } = await import('node:fs')
  const { resolve } = await import('node:path')
  const f = apiFixture()
  const dir = mkdtempSync(join(scratch, 'entrypoint-'))
  const apiPath = join(dir, 'api.json'); writeFileSync(apiPath, JSON.stringify(f.responses))
  const runtimeDir = resolve(repositoryRoot, runtime('fake-cli-upload-command.mjs'))
  for (const name of ['validate-flakiness-artifacts.mjs', 'read-flakiness-artifacts.py', 'upload-flakiness.mjs', 'fetch-producer-provenance.mjs', 'run-flakiness-upload.mjs', 'delivery-ledger.mjs']) cpSync(join(repositoryRoot, 'scripts/testing', name), join(runtimeDir, name))
  // Use existing pinned validator dependencies; never install or execute package hooks.
  mkdirSync(join(runtimeDir, 'node_modules/@flakiness'), { recursive: true })
  symlinkSync(join(repositoryRoot, 'node_modules/@flakiness/flakiness-report'), join(runtimeDir, 'node_modules/@flakiness/flakiness-report'))
  symlinkSync(join(repositoryRoot, 'node_modules/yauzl'), join(runtimeDir, 'node_modules/yauzl'))
  const ledger = mkdtempSync(join(dir, 'ledger-'))
  const env = { PATH: process.env.PATH, TMPDIR: scratch, GITHUB_REPOSITORY: repo, GITHUB_TOKEN: 'fake', GITHUB_RUN_ID: '900', GITHUB_RUN_ATTEMPT: '1', PRODUCER_RUN_ID: '123', PRODUCER_RUN_ATTEMPT: '2', FLAKINESS_PROJECT: 'Configured/project', ARTIFACT_DIR: artifactTree(), STAGING_DIR: join(dir, 'staging'), LEDGER_DIR: ledger, RUNTIME_DIR: runtimeDir, ACTIONS_ID_TOKEN_REQUEST_URL: 'https://oidc.invalid', ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'fake', PUBLISH_API_FIXTURE: apiPath, GITHUB_STEP_SUMMARY: join(dir, 'summary.md') }
  const args = ['--import', fileURLToPath(new URL('fixtures/fake-github-api.mjs', import.meta.url)), join(runtimeDir, 'run-flakiness-upload.mjs')]
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
