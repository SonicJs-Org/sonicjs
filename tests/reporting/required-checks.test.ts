import { expect, test } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { parse } from 'yaml'
import { repositoryRoot } from './options'

function workflow(name: string) { return parse(readFileSync(join(repositoryRoot, `.github/workflows/${name}.yml`), 'utf8')) }
function assertRestoreGate(w: any) {
  const restore = w.jobs.upload.steps.find((s: any) => s.name === 'Restore previous consumer ledger')
  const upload = w.jobs.upload.steps.find((s: any) => s.run === 'node scripts/testing/flakiness-runtime/run-flakiness-upload.mjs')
  expect(restore.id).toBe('restore')
  expect(upload.if).toBe("${{ !cancelled() && (github.run_attempt == 1 || steps.restore.outcome == 'success') }}")
}
test('restore failure blocks helper; removing restore outcome gate fails contract', () => {
  const w = workflow('flakiness-upload'); assertRestoreGate(w)
  w.jobs.upload.steps.find((s: any) => s.run === 'node scripts/testing/flakiness-runtime/run-flakiness-upload.mjs').if = '${{ !cancelled() }}'
  expect(() => assertRestoreGate(w)).toThrow()
})

const needed = ['authorize', 'producer-identity', 'unit-tests', 'e2e-setup', 'e2e-shard', 'e2e-locked', 'e2e-local', 'cleanup']
function aggregateStatus(job: any, needs: any) {
  const result = spawnSync('bash', ['--noprofile', '--norc', '-euo', 'pipefail', '-c', job.steps[0].run], {
    cwd: repositoryRoot, env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR, NEEDS_JSON: JSON.stringify(needs) }, encoding: 'utf8', timeout: 5000,
  })
  expect(result.error).toBeUndefined()
  return result.status
}
function assertAggregate(job: any) {
  expect(job).toBeDefined()
  expect(job.name).toBe('test')
  expect(job.permissions).toEqual({})
  expect(job.if).toBe('always()')
  expect(job.needs).toEqual(needed)
  expect(job.steps).toHaveLength(1)
  expect(job.steps[0].env).toEqual({ NEEDS_JSON: '${{ toJSON(needs) }}' })
  expect(JSON.stringify(job)).not.toMatch(/uses|checkout|secrets|outputs|id-token/)
  for (const local of [true, false]) {
    const needs = Object.fromEntries(needed.map(key => [key, { result: ['authorize', 'producer-identity', 'unit-tests'].includes(key) || (local ? key === 'e2e-local' : key !== 'e2e-local') ? 'success' : 'skipped' }]))
    expect(aggregateStatus(job, needs)).toBe(0)
    for (const key of needed) for (const state of ['success', 'failure', 'skipped', 'cancelled', 'missing']) {
      if (state === needs[key]!.result) continue
      const bad = structuredClone(needs)
      if (state === 'missing') delete bad[key]
      else bad[key] = { result: state }
      expect(aggregateStatus(job, bad), `${local ? 'local' : 'remote'} ${key}=${state}`).not.toBe(0)
    }
  }
  expect(aggregateStatus(job, Object.fromEntries(needed.map(k => [k, { result: 'skipped' }])))).not.toBe(0)
}
test('fixed required test executes strict full-path matrix using immutable needs JSON', () => {
  assertAggregate(workflow('pr-tests').jobs.test)
}, 30000)
test('aggregate mutation permitting arbitrary outcomes is rejected by executable matrix', () => {
  const job = workflow('pr-tests').jobs.test
  expect(job).toBeDefined()
  for (const script of [
    'node -e "JSON.parse(process.env.NEEDS_JSON)"',
    job.steps[0].run.replace("'e2e-locked', 'cleanup'", "'e2e-locked'"),
    job.steps[0].run.replace("['authorize', 'producer-identity', 'unit-tests']", "['authorize', 'unit-tests']"),
  ]) {
    expect(script).not.toBe(job.steps[0].run)
    const mutant = structuredClone(job); mutant.steps[0].run = script
    expect(() => assertAggregate(mutant)).toThrow()
  }
})
test('fixed authorize preserved and identity precedes parallel PR jobs without privileged capabilities', () => {
  const { jobs } = workflow('pr-tests')
  expect(jobs.authorize.name ?? 'authorize').toBe('authorize')
  const identity = jobs['producer-identity']
  expect(identity).toBeDefined()
  expect(identity.name).toContain('authorize:${{ github.run_id }}:${{ github.run_attempt }}:')
  expect(identity.needs).toBe('authorize')
  expect(identity.permissions).toEqual({})
  expect(identity.environment).toBeUndefined()
  expect(identity.steps).toEqual([{ name: 'Record producer identity', run: "echo 'Original producer identity recorded.'" }])
  expect(JSON.stringify(identity)).not.toMatch(/secrets|id-token|checkout|uses:/)
  for (const key of ['unit-tests', 'e2e-setup']) expect(jobs[key].needs).toBe('producer-identity')
})
function assertBestEffort(w: any) {
  let count = 0
  for (const job of Object.values(w.jobs) as any[]) {
    expect(job['continue-on-error']).toBeUndefined()
    for (const step of job.steps) {
      const vendor = /Upload (core-unit|cms-e2e) Flakiness reports/.test(step.name ?? '')
      if (vendor) { expect(step['continue-on-error']).toBe(true); count++ }
      else expect(step['continue-on-error']).toBeUndefined()
    }
  }
  expect(count).toBe(4)
}
test('only four new vendor uploads are best effort; real test failures remain gating', () => {
  const w = workflow('pr-tests'); assertBestEffort(w)
  for (const key of ['unit-tests', 'e2e-shard', 'e2e-locked', 'e2e-local']) {
    const bad = structuredClone(w)
    bad.jobs[key].steps.find((s: any) => s.run?.includes(key === 'unit-tests' ? 'npm run test:cov' : 'npx playwright test'))['continue-on-error'] = true
    expect(() => assertBestEffort(bad)).toThrow()
  }
  const jobMutation = structuredClone(w)
  jobMutation.jobs['unit-tests']['continue-on-error'] = true
  expect(() => assertBestEffort(jobMutation)).toThrow()
  const bad = structuredClone(w)
  delete bad.jobs['unit-tests'].steps.find((s: any) => s.name === 'Upload core-unit Flakiness reports')['continue-on-error']
  expect(() => assertBestEffort(bad)).toThrow()
})

function assertHead(w: any) {
  expect(w.on).toEqual({ push: { branches: ['ci/flakiness-publishing'] } })
  expect(w.permissions).toEqual({ contents: 'read' })
  expect(Object.keys(w.jobs)).toEqual(['test'])
  const job = w.jobs.test
  expect(job.name).toBe('test')
  expect(job['timeout-minutes']).toBe(150)
  expect(job.permissions).toEqual({ contents: 'read' })
  expect(job.env).toMatchObject({ CI: 'true', SONICJS_TEST_UPLOAD: '0', FLAKINESS_DISABLE_UPLOAD: '1', E2E_DISPOSABLE_TARGET: '1', BASE_URL: '', E2E_REUSE_SERVER: '0' })
  expect(JSON.stringify(w)).not.toMatch(/secrets\.|id-token|actions\/cache|cache:|--remote|wrangler deploy|workflow_run|pull_request_target|continue-on-error/)
  expect(job.if).toBeUndefined()
  expect(job.environment).toBeUndefined()
  for (const s of job.steps) {
    expect(s['continue-on-error']).toBeUndefined()
    if (!s.uses?.startsWith('actions/upload-artifact@')) expect(s.if).toBeUndefined()
  }
  const checkout = job.steps.find((s: any) => s.uses?.startsWith('actions/checkout@'))
  expect(checkout.uses).toBe('actions/checkout@11d5960a326750d5838078e36cf38b85af677262')
  expect(checkout.with).toEqual({ 'persist-credentials': false, 'fetch-depth': 0 })
  const node = job.steps.find((s: any) => s.uses?.startsWith('actions/setup-node@'))
  expect(node.uses).toBe('actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020')
  expect(node.with).toEqual({ 'node-version': '22.23.1' })
  const commands = job.steps.map((s: any) => s.run ?? '').join('\n')
  for (const command of ['npm ci', 'npm run type-check', 'npm run test:cov', 'npm run test:reporting', 'npm run build:core', 'npx playwright install --with-deps chromium']) expect(job.steps.some((s: any) => s.run === command)).toBe(true)
  expect(job.steps.find((s: any) => s.name === 'Lint E2E skip patterns and tags').run).toBe('bash scripts/lint-e2e-no-skip.sh\nbash scripts/lint-e2e-tags.sh\n')
  const local = workflow('pr-tests').jobs['e2e-local']
  for (const name of ['Prepare isolated local D1 for rollout, forks and Dependabot', 'Run full E2E regression suite']) {
    const original = local.steps.find((s: any) => s.name === name)
    const actual = job.steps.find((s: any) => s.name === name)
    expect(actual.run).toBe(original.run)
    expect(actual['working-directory']).toBe(original['working-directory'])
    expect(actual['timeout-minutes']).toBe(original['timeout-minutes'])
  }
  expect(commands).toContain('E2E_PERSIST_DIR=$RUNNER_TEMP/sonicjs-head-validation-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT')
  expect(commands).not.toMatch(/--grep|--workers|--retries|\|\| true/)
  const artifact = job.steps.find((s: any) => s.uses?.startsWith('actions/upload-artifact@'))
  expect(artifact.if).toBe('always()')
  expect(artifact.with.name).toBe('head-validation-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}')
  for (const path of ['flakiness-reports/', 'packages/core/coverage/', 'playwright-report/', 'test-results/', 'e2e-logs/']) expect(artifact.with.path).toContain(path)
}
test('push-only head validation gates real full suite with isolated local state and no credentials', () => { assertHead(workflow('flakiness-head-validation')) })
test('head validation contracts reject trigger, privilege, command and failure mutations', () => {
  const w = workflow('flakiness-head-validation'); assertHead(w)
  for (const mutate of [
    (x: any) => x.on.push.branches.push('main'),
    (x: any) => { x.on.workflow_run = {} },
    (x: any) => { x.jobs.test.env.TOKEN = '${{ secrets.TOKEN }}' },
    (x: any) => { x.jobs.test.steps.find((s: any) => s.run === 'npm run test:cov').run = 'echo coverage' },
    (x: any) => { x.jobs.test.steps.find((s: any) => s.run === 'npm run type-check').if = 'false' },
    (x: any) => { x.jobs.test.steps.find((s: any) => s.run === 'npm run test:reporting').run = 'exit 0\nnpm run test:reporting' },
    (x: any) => { x.jobs.test.steps.find((s: any) => s.name === 'Run full E2E regression suite')['continue-on-error'] = true },
    (x: any) => { x.jobs.test.steps.find((s: any) => s.name === 'Run full E2E regression suite').run += '\ntrue' },
  ]) { const bad = structuredClone(w); mutate(bad); expect(() => assertHead(bad)).toThrow() }
})
