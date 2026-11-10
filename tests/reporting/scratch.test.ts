import { afterEach, expect, test, vi } from 'vitest'
import { statSync, symlinkSync, realpathSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { repositoryRoot } from './options'
import { reportingScratch, reportingScratchParent } from './scratch'

afterEach(() => vi.unstubAllEnvs())

test('absent or empty TMPDIR uses runner-owned scratch with unique directories', () => {
  const runnerTemp = reportingScratch('runner-temp-')
  vi.stubEnv('SONICJS_REPORTING_EVIDENCE', undefined)
  vi.stubEnv('RUNNER_TEMP', runnerTemp)
  for (const tmpdir of [undefined, '']) {
    vi.stubEnv('TMPDIR', tmpdir)
    const first = reportingScratch('fixture-')
    const second = reportingScratch('fixture-')
    expect(dirname(first)).toBe(runnerTemp)
    expect(dirname(second)).toBe(runnerTemp)
    expect(first).not.toBe(second)
    expect(statSync(first).isDirectory()).toBe(true)
  }
})

test('explicit evidence and TMPDIR take precedence over RUNNER_TEMP', () => {
  const parent = reportingScratch('precedence-')
  vi.stubEnv('SONICJS_REPORTING_EVIDENCE', join(parent, 'evidence'))
  vi.stubEnv('TMPDIR', join(parent, 'tmp'))
  vi.stubEnv('RUNNER_TEMP', join(parent, 'runner'))
  expect(dirname(reportingScratch('fixture-'))).toBe(join(parent, 'evidence'))
  vi.stubEnv('SONICJS_REPORTING_EVIDENCE', '')
  expect(dirname(reportingScratch('fixture-'))).toBe(join(parent, 'tmp'))
})

test('without environment hints scratch stays outside producer report tree in owned test cache', () => {
  for (const key of ['SONICJS_REPORTING_EVIDENCE', 'TMPDIR', 'RUNNER_TEMP']) vi.stubEnv(key, undefined)
  expect(reportingScratchParent()).toBe(join(repositoryRoot, '.cache/reporting-contracts'))
})

test('owned symlink scratch parent resolves ancestry while preserving environment precedence', () => {
  const owner = reportingScratch('symlink-parent-')
  const alias = join(owner, 'alias'); symlinkSync(owner, alias)
  for (const selected of ['SONICJS_REPORTING_EVIDENCE', 'TMPDIR', 'RUNNER_TEMP']) {
    for (const key of ['SONICJS_REPORTING_EVIDENCE', 'TMPDIR', 'RUNNER_TEMP']) vi.stubEnv(key, undefined)
    vi.stubEnv(selected, alias)
    const result = reportingScratch('fixture-')
    expect(dirname(result)).toBe(realpathSync(owner))
    expect(realpathSync(result)).toBe(result)
  }
})
