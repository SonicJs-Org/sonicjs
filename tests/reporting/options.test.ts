import { execFileSync, spawnSync } from 'node:child_process'
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  createReportingOptions, repositoryRoot, assertUniqueTestNames,
  reportingSuites, reportingTargets, writeInvocationManifest,
} from './options'

const enabled = {
  SONICJS_TEST_UPLOAD: '1', FLAKINESS_ACCESS_TOKEN: 'fixture-secret',
  FLAKINESS_PROJECT: 'example/project',
}
const make = (env: Record<string, string | undefined> = {}) =>
  createReportingOptions({ suite: 'reporting-contracts', target: 'none', env })

describe('upload policy', () => {
  it.each([{}, { SONICJS_TEST_UPLOAD: '1' }, { ...enabled, SONICJS_TEST_UPLOAD: 'true' },
    { ...enabled, FLAKINESS_ACCESS_TOKEN: '' }, { ...enabled, FLAKINESS_PROJECT: ' ' },
    { ...enabled, FLAKINESS_ACCESS_TOKEN: undefined }])('defaults to offline: %j', env => {
    const result = make(env)
    expect(result.playwright[1].disableUpload).toBe(true)
    expect(result.vitest.reporters[1][1].disableUpload).toBe(true)
    expect(result.notice).toMatch(/upload disabled/i)
    expect(isAbsolute(result.outputFolder)).toBe(true)
  })
  it('requires explicit local opt-in, token, and project', () => {
    const result = make(enabled)
    expect(result.playwright[1].disableUpload).toBe(false)
    expect(result.vitest.reporters[1][1].disableUpload).toBe(false)
    expect(JSON.stringify(result)).not.toContain('fixture-secret')
  })
  it.each(['CI', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'GITHUB_REPOSITORY',
    'ACTIONS_ID_TOKEN_REQUEST_URL', 'GITLAB_CI', 'CI_JOB_URL', 'BUILD_URL', 'TF_BUILD',
    'BUILD_BUILDID', 'CIRCLECI', 'BUILDKITE', 'JENKINS_URL'])('forces offline in %s context', key => {
    const result = make({ ...enabled, [key]: '1', CI: key === 'CI' ? '1' : 'false' })
    expect(result.playwright[1].disableUpload).toBe(true)
    expect(result.environment.FK_ENV_SOURCE).toBe('ci')
  })
  it('does not read credentials from files or unrelated supplied keys', () => {
    expect(make({ DEV_VARS: 'FLAKINESS_ACCESS_TOKEN=fixture-secret', SONICJS_TEST_UPLOAD: '1',
      FLAKINESS_PROJECT: 'example/project' }).playwright[1].disableUpload).toBe(true)
    expect(make({ CI: 'false', GITHUB_ACTIONS: 'false' }).environment.FK_ENV_SOURCE).toBe('local')
  })
})

describe('invocation contract', () => {
  it('is rooted at repository regardless of child cwd', () => {
    const output = execFileSync(process.execPath, ['--import', 'tsx',
      join(repositoryRoot, 'tests/reporting/fixtures/from-cwd.ts')], {
      cwd: join(repositoryRoot, 'packages/core'), encoding: 'utf8',
    })
    expect(output.trim()).toMatch(new RegExp(`^${repositoryRoot}/flakiness-reports/core-unit/`))
  })
  it('keeps concurrent/repeated invocations distinct without cleaning shared root', async () => {
    const results = await Promise.all(Array.from({ length: 40 }, async () => make()))
    expect(new Set(results.map(r => r.outputFolder)).size).toBe(40)
    for (const r of results) {
      expect(r.outputFolder.startsWith(join(repositoryRoot, 'flakiness-reports/reporting-contracts/'))).toBe(true)
      expect(r.outputFolder).not.toContain('test-results')
    }
  })
  it('keeps changing metadata out of stable history and strips URL secrets', () => {
    const r = createReportingOptions({ suite: 'cms-e2e', target: 'preview-worker',
      targetURL: 'https://user:pass@example.com/path?token=secret#secret',
      env: { ...enabled, GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', GITHUB_JOB: 'e2e',
        SONICJS_TEST_SHARD: '1/3', GITHUB_SHA: 'incorrect', GITHUB_EVENT_NUMBER: '42' } })
    expect(r.environment).toEqual({ FK_ENV_SUITE: 'cms-e2e', FK_ENV_TARGET: 'preview-worker', FK_ENV_SOURCE: 'ci' })
    expect(r.outputFolder).toContain('e2e-1-3-2-')
    expect(r.manifest.commit).toBe(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot, encoding: 'utf8' }).trim())
    expect(r.manifest.targetURL).toBe('https://example.com/path')
    expect(r.manifest).toMatchObject({ runId: '123', attempt: '2', job: 'e2e', shard: '1/3', pullRequest: '42' })
    expect(JSON.stringify(r.manifest)).not.toMatch(/secret|pass|incorrect/)
    expect(existsSync(r.outputFolder)).toBe(false)
  })
  it('supports every inventoried suite and target, rejects unsafe values', () => {
    for (const suite of reportingSuites) for (const target of reportingTargets)
      expect(createReportingOptions({ suite, target, env: {} }).environment.FK_ENV_SUITE).toBe(suite)
    for (const suite of ['../escape', '', 'unknown'])
      expect(() => createReportingOptions({ suite: suite as 'core-unit', target: 'none', env: {} })).toThrow(/suite/i)
    expect(() => createReportingOptions({ suite: 'core-unit', target: 'remote' as 'none', env: {} })).toThrow(/target/i)
  })
  it('provides correct runner shapes without automatic renaming or browser opening', () => {
    const r = make()
    expect(r.playwright[0]).toBe('@flakiness/playwright')
    expect(r.playwright[1].open).toBe('never')
    expect(r.vitest.includeTaskLocation).toBe(true)
    expect(r.vitest.reporters[0]).toBe('default')
    expect(r.vitest.reporters[1][0]).toBe('@flakiness/vitest')
    expect(r.vitest.reporters[1][1].commitId).toBe(r.manifest.commit)
    expect(r.vitest.reporters[1][1]).not.toHaveProperty('autoRename')
    expect(r.vitest.reporters[1][1]).not.toHaveProperty('duplicates')
  })
  it('preflights duplicate full names within file/project, allowing distinct identities', () => {
    const entry = { project: 'unit', file: 'a.test.ts', fullName: 'suite case' }
    expect(() => assertUniqueTestNames([entry, { ...entry }])).toThrow(/duplicate.*suite case/i)
    expect(() => assertUniqueTestNames([entry, { ...entry, project: 'browser' }, { ...entry, file: 'b.test.ts' }])).not.toThrow()
  })
  it('writes start/end metadata without cleaning another invocation and propagates write errors', () => {
    const first = make()
    const second = make()
    writeInvocationManifest(first)
    writeFileSync(join(first.outputFolder, 'retained.txt'), 'keep')
    writeInvocationManifest(second, { outcome: 'failed' })
    expect(readFileSync(join(first.outputFolder, 'retained.txt'), 'utf8')).toBe('keep')
    const manifest = JSON.parse(readFileSync(join(second.outputFolder, 'invocation.json'), 'utf8'))
    expect(manifest).toMatchObject({ outcome: 'failed', commit: second.manifest.commit })
    expect(Date.parse(manifest.endedAt)).toBeGreaterThanOrEqual(Date.parse(manifest.startedAt))
    const blocked = make()
    mkdirSync(blocked.outputFolder, { recursive: true })
    writeFileSync(join(blocked.outputFolder, 'blocked'), 'file')
    expect(() => writeInvocationManifest({ ...blocked, outputFolder: join(blocked.outputFolder, 'blocked') })).toThrow()
  })
  it('pins reviewed reporters without changing runner pins', () => {
    const pkg = JSON.parse(readFileSync(join(repositoryRoot, 'package.json'), 'utf8'))
    expect(pkg.devDependencies['@flakiness/playwright']).toBe('2.0.3')
    expect(pkg.devDependencies['@flakiness/vitest']).toBe('1.12.0')
  })
})

// Real runner processes: no browser, app server, network, or inherited credentials.
describe('official reporter compatibility', () => {
  it.each(['vitest', 'playwright'] as const)('%s preserves reports and failure status', runner => {
    for (const fail of ['0', '1']) {
      const result = spawnSync(process.execPath, [
        join(repositoryRoot, runner === 'vitest' ? 'node_modules/vitest/vitest.mjs' : 'node_modules/@playwright/test/cli.js'),
        runner === 'vitest' ? 'run' : 'test', '--config',
        join(repositoryRoot, `tests/reporting/fixtures/vendor-${runner}.config.ts`),
      ], {
        cwd: repositoryRoot, encoding: 'utf8', timeout: 25_000,
        env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR,
          CI: '1', SONICJS_TEST_UPLOAD: '1', GITHUB_SHA: 'wrong-event-sha',
          FLAKINESS_COMMIT_ID: 'wrong-override', REPORTING_FIXTURE_FAIL: fail },
      })
      expect(result.error).toBeUndefined()
      expect(result.status, result.stdout + result.stderr).toBe(fail === '1' ? 1 : 0)
      const folder = result.stdout.match(/REPORT_FOLDER=(.+)/)?.[1]?.trim()
      expect(folder, result.stdout + result.stderr).toBeTruthy()
      const report = JSON.parse(readFileSync(join(folder!, 'report.json'), 'utf8'))
      expect(report.commitId).toBe(execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repositoryRoot, encoding: 'utf8' }).trim())
      expect(report.environments[0].metadata).toMatchObject({
        suite: runner === 'vitest' ? 'reporting-contracts' : 'runner-contracts', target: 'none', source: 'ci',
      })
    }
  })
})
