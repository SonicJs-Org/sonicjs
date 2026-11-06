import { expect, test, describe } from 'vitest'
import { parse } from 'yaml'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const uploadPath = fileURLToPath(new URL('../../.github/workflows/flakiness-upload.yml', import.meta.url))
const prTestsPath = fileURLToPath(new URL('../../.github/workflows/pr-tests.yml', import.meta.url))

function loadUpload() { return parse(readFileSync(uploadPath, 'utf8')) as Record<string, unknown> }
function loadPrTests() { return parse(readFileSync(prTestsPath, 'utf8')) as Record<string, unknown> }
function getUploadJob(w: Record<string, unknown>) { return (w.jobs as Record<string, unknown>)['upload'] as Record<string, unknown> }
function getSteps(job: Record<string, unknown>) { return (job.steps ?? []) as Array<Record<string, unknown>> }

describe('flakiness-upload.yml', () => {
  test('name is Flakiness Upload', () => { expect(loadUpload().name).toBe('Flakiness Upload') })

  test('triggers on workflow_run of PR Tests completed', () => {
    const on = loadUpload().on as Record<string, unknown>
    const wr = on.workflow_run as Record<string, unknown>
    expect((wr.workflows as string[]).includes('PR Tests')).toBe(true)
    expect((wr.types as string[]).includes('completed')).toBe(true)
  })

  test('NO other triggers besides workflow_run', () => {
    const on = loadUpload().on as Record<string, unknown>
    expect(Object.keys(on)).toEqual(['workflow_run'])
  })

  test('global permissions: actions:read, contents:read, id-token:write only', () => {
    const perms = loadUpload().permissions as Record<string, unknown>
    expect(perms['actions']).toBe('read')
    expect(perms['contents']).toBe('read')
    expect(perms['id-token']).toBe('write')
    // No other permissions
    expect(Object.keys(perms).sort()).toEqual(['actions', 'contents', 'id-token'].sort())
  })

  test('job has if-condition restricting to trusted repo and correct workflow_id', () => {
    const job = getUploadJob(loadUpload())
    const condition = String(job.if)
    expect(condition).toContain('SonicJs-Org/sonicjs')
    expect(condition).toContain('207092903')
    expect(condition).toContain('success')
    expect(condition).toContain('failure')
  })

  test('job does NOT trigger on cancelled or skipped', () => {
    const job = getUploadJob(loadUpload())
    const condition = String(job.if)
    expect(condition).not.toContain('cancelled')
    expect(condition).not.toContain('skipped')
  })

  test('NO Cloudflare, Codecov, npm-publish secrets in job', () => {
    const steps = getSteps(getUploadJob(loadUpload()))
    const text = JSON.stringify(steps)
    for (const forbidden of ['CLOUDFLARE_', 'CODECOV_', 'NPM_TOKEN', 'PLAYWRIGHT_STATS']) {
      expect(text).not.toContain(forbidden)
    }
  })

  test('NO services block', () => {
    expect(getUploadJob(loadUpload())).not.toHaveProperty('services')
  })

  test('checkout is main ref with persist-credentials:false', () => {
    const steps = getSteps(getUploadJob(loadUpload()))
    const checkout = steps.find(s => String(s.uses ?? '').startsWith('actions/checkout@'))
    expect(checkout).toBeDefined()
    expect(String((checkout!.with as Record<string, unknown>)['ref'])).toBe('main')
    expect((checkout!.with as Record<string, unknown>)['persist-credentials']).toBe(false)
  })

  test('setup-node uses exact pinned SHA', () => {
    const steps = getSteps(getUploadJob(loadUpload()))
    const setup = steps.find(s => String(s.uses ?? '').startsWith('actions/setup-node@'))
    expect(setup!.uses).toBe('actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020')
  })

  test('download-artifact uses pinned SHA (not @v4 floating)', () => {
    const steps = getSteps(getUploadJob(loadUpload()))
    const dl = steps.filter(s => String(s.uses ?? '').startsWith('actions/download-artifact@'))
    expect(dl.length).toBeGreaterThan(0)
    for (const step of dl) {
      expect(String(step.uses)).toMatch(/actions\/download-artifact@[0-9a-f]{40}/)
    }
  })

  test('GITHUB_TOKEN used for download, not Flakiness secrets', () => {
    const steps = getSteps(getUploadJob(loadUpload()))
    const dl = steps.filter(s => String(s.uses ?? '').startsWith('actions/download-artifact@'))
    for (const step of dl) {
      const withBlock = (step.with ?? {}) as Record<string, unknown>
      expect(String(withBlock['github-token'])).toContain('GITHUB_TOKEN')
    }
  })

  test('mutation guard: adding CLOUDFLARE_ secret is detectable', () => {
    const w = loadUpload()
    const job = getUploadJob(w)
    const env = (job.env ?? {}) as Record<string, unknown>
    env['CLOUDFLARE_API_TOKEN'] = '${{ secrets.CLOUDFLARE_API_TOKEN }}'
    expect(JSON.stringify(job)).toContain('CLOUDFLARE_')
    // Original does not have it
    expect(JSON.stringify(getUploadJob(loadUpload()))).not.toContain('CLOUDFLARE_')
  })
})

describe('pr-tests.yml Flakiness artifact upload', () => {
  test('uploads core-unit artifact after unit test step', () => {
    const steps = getSteps((loadPrTests().jobs as Record<string, unknown>)['test'] as Record<string, unknown>)
    const unitIdx = steps.findIndex(s => String(s.name ?? '').includes('unit tests'))
    const uploadStep = steps.find(s => String(s.name ?? '').includes('core-unit Flakiness'))
    expect(uploadStep).toBeDefined()
    const uploadIdx = steps.indexOf(uploadStep!)
    expect(uploadIdx).toBeGreaterThan(unitIdx)
  })

  test('uploads cms-e2e artifact after E2E step', () => {
    const steps = getSteps((loadPrTests().jobs as Record<string, unknown>)['test'] as Record<string, unknown>)
    const e2eIdx = steps.findIndex(s => String(s.name ?? '').includes('E2E regression'))
    const uploadStep = steps.find(s => String(s.name ?? '').includes('cms-e2e Flakiness'))
    expect(uploadStep).toBeDefined()
    const uploadIdx = steps.indexOf(uploadStep!)
    expect(uploadIdx).toBeGreaterThan(e2eIdx)
  })

  test('artifact uploads use always() so reports are preserved on failure', () => {
    const steps = getSteps((loadPrTests().jobs as Record<string, unknown>)['test'] as Record<string, unknown>)
    const flakinessUploads = steps.filter(s => String(s.name ?? '').includes('Flakiness reports'))
    expect(flakinessUploads.length).toBe(2)
    for (const step of flakinessUploads) {
      expect(String(step.if ?? '')).toContain('always()')
    }
  })

  test('artifact names include run_id and run_attempt for unique delivery key', () => {
    const steps = getSteps((loadPrTests().jobs as Record<string, unknown>)['test'] as Record<string, unknown>)
    const flakinessUploads = steps.filter(s => String(s.name ?? '').includes('Flakiness reports'))
    for (const step of flakinessUploads) {
      const name = String((step.with as Record<string, unknown>)['name'])
      expect(name).toContain('run_id')
      expect(name).toContain('run_attempt')
    }
  })

  test('NO new Flakiness credentials or id-token in test job', () => {
    const job = (loadPrTests().jobs as Record<string, unknown>)['test'] as Record<string, unknown>
    const perms = job.permissions
    if (perms) expect(String(perms)).not.toContain('id-token')
    // env should not contain FLAKINESS_ACCESS_TOKEN
    const env = (job.env ?? {}) as Record<string, unknown>
    expect(env).not.toHaveProperty('FLAKINESS_ACCESS_TOKEN')
    // No FLAKINESS secrets in any step
    const steps = getSteps(job)
    const text = JSON.stringify(steps)
    expect(text).not.toContain('FLAKINESS_ACCESS_TOKEN')
  })
})
