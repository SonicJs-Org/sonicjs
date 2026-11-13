import { expect, test, describe } from 'vitest'
import { parse } from 'yaml'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const workflowPath = fileURLToPath(new URL('../../.github/workflows/reporting-contracts.yml', import.meta.url))

function loadWorkflow(): Record<string, unknown> {
  return parse(readFileSync(workflowPath, 'utf8')) as Record<string, unknown>
}

function withModification(modify: (w: Record<string, unknown>) => void): Record<string, unknown> {
  const w = loadWorkflow()
  modify(w)
  return w
}

function getJob(w: Record<string, unknown>) {
  const jobs = w.jobs as Record<string, unknown>
  return jobs['reporting-contracts'] as Record<string, unknown>
}

function getSteps(w: Record<string, unknown>): Array<Record<string, unknown>> {
  return getJob(w).steps as Array<Record<string, unknown>>
}

function getStepRuns(w: Record<string, unknown>): string[] {
  return getSteps(w).map(s => String(s.run ?? '')).filter(Boolean)
}

function findStep(w: Record<string, unknown>, pred: (s: Record<string, unknown>) => boolean) {
  return getSteps(w).find(pred)
}

// ─── Trigger tests ──────────────────────────────────────────────────────────
describe('triggers', () => {
  test('name is Reporting Contracts', () => {
    expect(loadWorkflow().name).toBe('Reporting Contracts')
  })

  test('pull_request trigger covers main branch', () => {
    const w = loadWorkflow()
    const on = w.on as Record<string, unknown>
    const pr = on.pull_request as Record<string, unknown>
    expect((pr.branches as string[]).includes('main')).toBe(true)
  })

  test('push trigger covers main and no stale rollout branch', () => {
    const w = loadWorkflow()
    const on = w.on as Record<string, unknown>
    const push = on.push as Record<string, unknown>
    expect((push.branches as string[]).includes('main')).toBe(true)
    expect((push.branches as string[]).includes('ci/flakiness-artifact-validation')).toBe(false)
  })

  test('NO pull_request_target trigger', () => {
    const w = loadWorkflow()
    const on = w.on as Record<string, unknown>
    expect(on).not.toHaveProperty('pull_request_target')
  })

  test('NO workflow_run trigger', () => {
    const w = loadWorkflow()
    const on = w.on as Record<string, unknown>
    expect(on).not.toHaveProperty('workflow_run')
  })

  test('NO schedule trigger', () => {
    const w = loadWorkflow()
    const on = w.on as Record<string, unknown>
    expect(on).not.toHaveProperty('schedule')
  })
})

// ─── Permissions tests ───────────────────────────────────────────────────────
describe('permissions', () => {
  test('global permissions is contents:read only', () => {
    const w = loadWorkflow()
    expect(w.permissions).toEqual({ contents: 'read' })
  })

  test('mutation guard: contents:write fails', () => {
    const w = withModification(w => { (w.permissions as Record<string, unknown>).contents = 'write' })
    expect((w.permissions as Record<string, unknown>).contents).not.toBe('read')
    // Prove the unmodified version has 'read'
    expect((loadWorkflow().permissions as Record<string, unknown>).contents).toBe('read')
  })

  test('NO write-all permissions', () => {
    expect(loadWorkflow().permissions).not.toBe('write-all')
  })

  test('job has NO id-token permission', () => {
    const job = getJob(loadWorkflow())
    const perms = (job.permissions ?? {}) as Record<string, unknown>
    expect(perms).not.toHaveProperty('id-token')
  })
})

// ─── Job structure tests ─────────────────────────────────────────────────────
describe('job structure', () => {
  test('single job key: reporting-contracts', () => {
    const jobs = loadWorkflow().jobs as Record<string, unknown>
    expect(Object.keys(jobs)).toEqual(['reporting-contracts'])
  })

  test('runs-on ubuntu-latest', () => {
    expect(getJob(loadWorkflow())['runs-on']).toBe('ubuntu-latest')
  })

  test('job has timeout-minutes', () => {
    expect(getJob(loadWorkflow())['timeout-minutes']).toBeGreaterThan(0)
  })

  test('NO secrets reference in job', () => {
    const job = getJob(loadWorkflow())
    expect(job).not.toHaveProperty('secrets')
    // env block must not contain known secret patterns
    const env = (job.env ?? {}) as Record<string, unknown>
    const secretPatterns = ['CLOUDFLARE_', 'CODECOV_', 'NPM_TOKEN', 'FLAKINESS_ACCESS_TOKEN', 'GITHUB_TOKEN']
    for (const key of Object.keys(env)) {
      expect(secretPatterns.some(p => key.startsWith(p))).toBe(false)
    }
  })

  test('NO services block', () => {
    expect(getJob(loadWorkflow())).not.toHaveProperty('services')
  })
})

// ─── Environment tests ───────────────────────────────────────────────────────
describe('environment variables', () => {
  test('CI is set to true', () => {
    const env = getJob(loadWorkflow()).env as Record<string, unknown>
    expect(String(env['CI'])).toBe('true')
  })

  test('SONICJS_TEST_UPLOAD is 0', () => {
    const env = getJob(loadWorkflow()).env as Record<string, unknown>
    expect(String(env['SONICJS_TEST_UPLOAD'])).toBe('0')
  })

  test('FLAKINESS_DISABLE_UPLOAD is 1', () => {
    const env = getJob(loadWorkflow()).env as Record<string, unknown>
    expect(String(env['FLAKINESS_DISABLE_UPLOAD'])).toBe('1')
  })
})

// ─── Step tests ──────────────────────────────────────────────────────────────
describe('steps', () => {
  test('checkout uses exact pinned SHA with persist-credentials:false', () => {
    const step = findStep(loadWorkflow(), s => String(s.uses ?? '').startsWith('actions/checkout@'))
    expect(step).toBeDefined()
    expect(step!.uses).toBe('actions/checkout@11d5960a326750d5838078e36cf38b85af677262')
    const withBlock = step!.with as Record<string, unknown>
    expect(withBlock?.['persist-credentials']).toBe(false)
    // Full history required so wiring tests can git-show stage1 commits
    expect(withBlock?.['fetch-depth']).toBe(0)
  })

  test('setup-node uses exact pinned SHA with node-version 22.23.1', () => {
    const step = findStep(loadWorkflow(), s => String(s.uses ?? '').startsWith('actions/setup-node@'))
    expect(step).toBeDefined()
    expect(step!.uses).toBe('actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020')
    const withBlock = step!.with as Record<string, unknown>
    expect(String(withBlock?.['node-version'])).toBe('22.23.1')
  })

  test('upload-artifact uses exact pinned SHA with if:always() and retention-days:7', () => {
    const step = findStep(loadWorkflow(), s => String(s.uses ?? '').startsWith('actions/upload-artifact@'))
    expect(step).toBeDefined()
    expect(step!.uses).toBe('actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02')
    expect(step!.if).toBe('always()')
    const withBlock = step!.with as Record<string, unknown>
    expect(Number(withBlock?.['retention-days'])).toBe(7)
  })

  test('npm run test:reporting step exists', () => {
    const runs = getStepRuns(loadWorkflow())
    expect(runs.some(r => r.includes('npm run test:reporting'))).toBe(true)
  })

  test('NO credential env vars in step run scripts or with blocks', () => {
    const steps = getSteps(loadWorkflow())
    const forbidden = [
      /CLOUDFLARE_[A-Z]/,
      /CODECOV_[A-Z]/,
      /NPM_TOKEN/,
      /FLAKINESS_ACCESS_TOKEN/,
      /ACTIONS_ID_TOKEN_/,
    ]
    for (const step of steps) {
      const text = JSON.stringify(step)
      for (const pattern of forbidden) {
        expect(pattern.test(text)).toBe(false)
      }
    }
  })

  test('mutation guard: adding a secret env var is detectable', () => {
    const w = withModification(w => {
      const job = getJob(w)
      const env = (job.env ?? {}) as Record<string, unknown>
      env['CLOUDFLARE_API_TOKEN'] = '${{ secrets.CLOUDFLARE_API_TOKEN }}'
    })
    const jobEnv = (getJob(w).env ?? {}) as Record<string, unknown>
    expect(jobEnv).toHaveProperty('CLOUDFLARE_API_TOKEN')
    // Prove the guard would catch this if we checked
    const forbidden = /CLOUDFLARE_[A-Z]/
    expect(forbidden.test(JSON.stringify(getJob(w)))).toBe(true)
    // And the original doesn't have it
    expect(forbidden.test(JSON.stringify(getJob(loadWorkflow())))).toBe(false)
  })
})
