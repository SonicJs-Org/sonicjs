import { expect, test } from 'vitest'
import { parse } from 'yaml'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { validateProducerProvenance, type ProducerProvenanceInput } from '../../scripts/testing/validate-flakiness-artifacts.mjs'

/** Load checked-in workflow; parser must also catch unresolved merge markers. */
function workflow(name: string) { return parse(readFileSync(fileURLToPath(new URL(`../../.github/workflows/${name}.yml`, import.meta.url)), 'utf8')) }
/** Apply secret policy to complete job, including env and nested action inputs. */
function assertUploadBoundary(job: unknown) {
  for (const forbidden of ['CLOUDFLARE_', 'CODECOV_', 'NPM_TOKEN', 'PLAYWRIGHT_STATS', 'FLAKINESS_ACCESS_TOKEN']) expect(JSON.stringify(job)).not.toContain(forbidden)
}

test('consumer only handles completed PR Tests and scopes minimal permissions to uploader', () => {
  const w = workflow('flakiness-upload')
  expect(w.on).toEqual({ workflow_run: { workflows: ['PR Tests'], types: ['completed'] } })
  expect(w.permissions).toEqual({ contents: 'read' })
  expect(w.jobs.upload.permissions).toEqual({ contents: 'read', actions: 'read', 'id-token': 'write' })
  expect(w.jobs.upload.if).toContain('207092903')
  expect(w.jobs.upload.if).toContain('SonicJs-Org/sonicjs')
  expect(w.concurrency.group).toContain('workflow_run.id')
  expect(w.concurrency.group).toContain('workflow_run.run_attempt')
  expect(w.concurrency['cancel-in-progress']).toBe(false)
})
test('complete uploader secret guard rejects job-level and step-level mutations', () => {
  const job = workflow('flakiness-upload').jobs.upload
  assertUploadBoundary(job)
  for (const location of ['env', 'steps']) {
    const mutation = structuredClone(job)
    if (location === 'env') mutation.env.CLOUDFLARE_API_TOKEN = '${{ secrets.CLOUDFLARE_API_TOKEN }}'
    else mutation.steps.push({ env: { CODECOV_TOKEN: '${{ secrets.CODECOV_TOKEN }}' } })
    expect(() => assertUploadBoundary(mutation)).toThrow()
  }
})
test('consumer checks out main, uses pinned actions and independent ignore-scripts runtime only', () => {
  const steps = workflow('flakiness-upload').jobs.upload.steps
  const checkout = steps.find((s: any) => s.uses?.startsWith('actions/checkout@'))
  expect(checkout.uses).toBe('actions/checkout@11d5960a326750d5838078e36cf38b85af677262')
  expect(steps.find((s: any) => s.uses?.startsWith('actions/setup-node@')).uses).toBe('actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020')
  expect(checkout.with).toMatchObject({ ref: 'main', 'persist-credentials': false })
  for (const s of steps.filter((s: any) => s.uses)) expect(s.uses).toMatch(/@[a-f0-9]{40}$/)
  for (const s of steps.filter((s: any) => s.uses?.startsWith('actions/download-artifact@'))) expect(s.uses).toBe('actions/download-artifact@fa0a91b85d4f404e444e00e005971372dc801d16')
  const scripts = steps.map((s: any) => s.run ?? '').join('\n')
  expect(scripts).not.toMatch(/^npm ci$/m)
  expect(scripts).toContain('--ignore-scripts')
  expect(scripts).toContain('fetch-producer-provenance.mjs')
})
test('consumer restores ledger, processes complete batch once, and preserves ledger even on failure', () => {
  const steps = workflow('flakiness-upload').jobs.upload.steps
  const downloads = steps.filter((s: any) => s.uses?.startsWith('actions/download-artifact@'))
  const reports = downloads.find((s: any) => s.with.pattern)
  expect(reports.with['merge-multiple']).toBe(true)
  expect(reports.with['run-id']).toContain('PRODUCER_RUN_ID')
  const upload = steps.filter((s: any) => s.run?.includes('node scripts/testing/flakiness-runtime/run-flakiness-upload.mjs'))
  expect(upload).toHaveLength(1)
  expect(upload[0].if).toContain('!cancelled()')
  expect(upload[0].env.ARTIFACT_DIR).toBe('${{ runner.temp }}/artifacts')
  const ledger = steps.find((s: any) => s.name === 'Preserve delivery ledger')
  expect(ledger.if).toBe('always()')
  expect(ledger.with.name).toContain('github.run_attempt')
  const restore = downloads.find((s: any) => s.name === 'Restore previous consumer ledger')
  expect(restore.if).toContain('github.run_attempt > 1')
  expect(restore['continue-on-error']).toBeUndefined()
})
test('producer preserves main parallel unit, four shards, serial locks, local path and cleanup', () => {
  const w = workflow('pr-tests')
  expect(w.permissions).toEqual({ contents: 'read' })
  for (const job of Object.values(w.jobs)) expect(JSON.stringify(job)).not.toMatch(/id-token|FLAKINESS_ACCESS_TOKEN|ACTIONS_ID_TOKEN/)
  expect(w.jobs['unit-tests'].needs).toBe('producer-identity')
  expect(w.jobs['e2e-setup'].needs).toBe('producer-identity')
  expect(w.jobs['e2e-shard'].strategy.matrix.shard).toEqual([1, 2, 3, 4])
  expect(w.jobs['e2e-shard'].strategy['fail-fast']).toBe(false)
  expect(w.jobs['e2e-locked'].needs).toEqual(['unit-tests', 'e2e-setup', 'e2e-shard'])
  expect(w.jobs.cleanup.needs).toEqual(['e2e-setup', 'e2e-shard', 'e2e-locked'])
  expect(w.jobs.authorize.name ?? 'authorize').toBe('authorize')
  expect(w.jobs['producer-identity'].name).toContain('authorize:')
  expect(w.jobs['producer-identity'].name).toContain('pull_request.head.repo.full_name')
  expect(w.jobs.authorize.steps).toHaveLength(1)
  for (const [key, suite] of [['unit-tests', 'core-unit'], ['e2e-shard', 'cms-e2e'], ['e2e-locked', 'cms-e2e'], ['e2e-local', 'cms-e2e']]) {
    const job = w.jobs[key!]
    expect(JSON.stringify(job)).not.toMatch(/id-token|FLAKINESS_ACCESS_TOKEN|ACTIONS_ID_TOKEN/)
    const artifact = job.steps.find((s: any) => s.name?.includes(`${suite} Flakiness reports`))
    expect(artifact, key).toBeDefined()
    const testIndex = job.steps.findIndex((s: any) => s.run?.includes(key === 'unit-tests' ? 'npm run test:cov' : 'npx playwright test'))
    expect(testIndex).toBeGreaterThan(-1)
    expect(job.steps.indexOf(artifact)).toBeGreaterThan(testIndex)
    expect(artifact.with['retention-days']).toBe(7)
    expect(artifact.if).toBe('always()')
    expect(artifact.with.path).toBe('flakiness-reports/')
    expect(artifact.with.name).toContain(key)
    expect(artifact.with.name).toContain('github.run_attempt')
  }
  expect(w.jobs['e2e-shard'].env.SONICJS_TEST_SHARD).toContain('matrix.shard')
  expect(w.jobs['e2e-shard'].steps.some((s: any) => s.run?.includes('--grep-invert "@lock-"'))).toBe(true)
  expect(w.jobs['e2e-locked'].steps.some((s: any) => s.run?.includes('--workers 1'))).toBe(true)
})

/** Exact fail-closed activation clause; absent/false vars cannot enter privileged job. */
function assertActivation(job: any) {
  const normalized = job.if.replace(/\s+/g, ' ').trim()
  expect(normalized).toBe([
    "github.event.workflow_run.repository.full_name == 'SonicJs-Org/sonicjs'",
    'github.event.workflow_run.workflow_id == 207092903',
    "contains(fromJSON('[\"push\",\"pull_request_target\"]'), github.event.workflow_run.event)",
    "vars.FLAKINESS_UPLOAD_ENABLED == 'true'",
  ].join(' && '))
}
test('upload requires explicit approval switch; bypass, removal or false comparison fails contract', () => {
  const job = workflow('flakiness-upload').jobs.upload
  assertActivation(job)
  for (const condition of [
    `true || ${job.if}`, `${job.if} || true`,
    `true || (${job.if})`, `(${job.if}) || true`,
    job.if.replace(/&&\s*vars\.FLAKINESS_UPLOAD_ENABLED == 'true'/, ''),
    job.if.replace("== 'true'", "== 'false'"),
    job.if.replace(' && ', ' || '),
    job.if.replace('SonicJs-Org/sonicjs', 'Other/sonicjs'),
    job.if.replace('207092903', '1'),
    job.if.replace(/&&\s*contains\([^\n]+/, ''),
    job.if.replace('pull_request_target', 'pull_request'),
  ]) {
    expect(() => assertActivation({ ...job, if: condition })).toThrow()
  }
})
test('ledger publication uses only filtered export even after failure or cancellation', () => {
  const steps = workflow('flakiness-upload').jobs.upload.steps
  const stage = steps.find((s: any) => s.name === 'Export safe delivery records')
  const artifact = steps.find((s: any) => s.name === 'Preserve delivery ledger')
  expect(stage?.if).toBe('always()')
  expect(stage?.run).toBe('node scripts/testing/flakiness-runtime/export-flakiness-ledger.mjs')
  expect(stage?.env.LEDGER_DIR).toBe('${{ runner.temp }}/ledger')
  expect(stage?.env.LEDGER_EXPORT_DIR).toBe('${{ runner.temp }}/ledger-export')
  expect(artifact.with.path).toBe('${{ runner.temp }}/ledger-export/')
  expect(steps.indexOf(stage)).toBeLessThan(steps.indexOf(artifact))
  const upload = steps.find((s: any) => s.run === 'node scripts/testing/flakiness-runtime/run-flakiness-upload.mjs')
  expect(upload.env.CLI_SCRATCH_DIR).toBe('${{ runner.temp }}/cli-private')
  expect(steps.find((s: any) => s.run?.includes('npm ci')).run).toContain('scripts/testing/export-flakiness-ledger.mjs')
})

/** Feed actual rendered workflow names through production provenance policy. */
function assertRenderedSuiteNames(w: any) {
  const sha = 'a'.repeat(40)
  const step = (key: string, shard?: number) => {
    const s = w.jobs[key].steps.find((s: any) => s.run?.includes(key === 'unit-tests' ? 'npm run test:cov' : 'npx playwright test'))
    return { number: 4, name: s.name.replace('${{ matrix.shard }}', String(shard)), status: 'completed', conclusion: 'success' }
  }
  for (const local of [false, true]) {
    const job = (id: number, key: string, ran: boolean, shard?: number) => ({ id, key, ...(shard ? { shard: `${shard}-of-4` } : {}), runId: 123, runAttempt: 2, status: 'completed', conclusion: ran ? 'success' : 'skipped', steps: ran ? [step(key, shard)] : [] })
    const input: ProducerProvenanceInput = {
      trigger: { repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2 },
      producer: { repository: 'SonicJs-Org/sonicjs', runId: 123, runAttempt: 2, workflowId: 207092903, workflowName: 'PR Tests', workflowPath: '.github/workflows/pr-tests.yml', event: 'push', status: 'completed', conclusion: 'success', headBranch: 'main', headSha: sha },
      jobs: [job(10, 'unit-tests', true), job(11, 'e2e-local', local), job(12, 'e2e-locked', !local), ...w.jobs['e2e-shard'].strategy.matrix.shard.map((n: number) => job(20 + n, 'e2e-shard', !local, n))],
    }
    const result = validateProducerProvenance(input)
    expect(result.suites.filter(s => s.ran).map(s => s.jobId).sort((a, b) => a - b)).toEqual(local ? [10, 11] : [10, 12, 21, 22, 23, 24])
  }
}
test('workflow-rendered unit, local, locked and all four shard names match validator', () => {
  assertRenderedSuiteNames(workflow('pr-tests'))
})
test.each(['unit-tests', 'e2e-local', 'e2e-locked', 'e2e-shard'])('renaming actual %s test step fails workflow-derived contract', key => {
  const w = workflow('pr-tests')
  w.jobs[key].steps.find((s: any) => s.run?.includes(key === 'unit-tests' ? 'npm run test:cov' : 'npx playwright test')).name += ' renamed'
  expect(() => assertRenderedSuiteNames(w)).toThrow(/missing or non-publishable suite/)
})

// Evaluate the actual fixed GitHub expression over permitted and hostile events.
test('privileged activation rejects other events before job downloads or OIDC scope', () => {
  const job = workflow('flakiness-upload').jobs.upload
  assertActivation(job)
  const expression = job.if.replace(/github\.event\.workflow_run\./g, 'run.').replace('vars.FLAKINESS_UPLOAD_ENABLED', 'flag')
  const active = new Function('run', 'flag', 'contains', 'fromJSON', `return (${expression})`)
  for (const event of ['push', 'pull_request_target', 'pull_request', 'workflow_dispatch', 'workflow_run', '', undefined]) {
    for (const repository of ['SonicJs-Org/sonicjs', 'Other/sonicjs']) for (const workflow_id of [207092903, 1]) for (const flag of ['true', 'false', '', undefined]) {
      expect(active({ event, repository: { full_name: repository }, workflow_id }, flag, (xs: unknown[], x: unknown) => xs.includes(x), JSON.parse))
        .toBe(['push', 'pull_request_target'].includes(event as string) && repository === 'SonicJs-Org/sonicjs' && workflow_id === 207092903 && flag === 'true')
    }
  }
})
