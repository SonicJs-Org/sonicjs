import { spawn, spawnSync } from 'node:child_process'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { expect, test } from 'vitest'
import { repositoryRoot } from './options'
const fixture = join(repositoryRoot, 'tests/reporting/fixtures')
export function runVitest(mode: string) {
  const result = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(fixture, 'vitest-semantics.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25_000,
    env: { PATH: process.env.PATH, CI: '1', CASE_MODE: mode, NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  expect(result.error).toBeUndefined()
  const folder = result.stdout.match(/\[flakiness\] Report: (.+)/)?.[1]?.trim()
  expect(folder, result.stdout + result.stderr).toBeTruthy()
  expect(folder).toMatch(/\/vendor$/)
  expect(existsSync(`${dirname(folder!)}-metadata`)).toBe(false)
  return { ...result, folder: folder!, manifest: JSON.parse(readFileSync(join(dirname(folder!), 'invocation.json'), 'utf8')) }
}
test.each(['pass', 'fail', 'retry', 'skip', 'import', 'setup', 'duplicate', 'empty'])('native Vitest: %s', mode => {
  const result = runVitest(mode)
  expect(result.status, result.stdout + result.stderr).toBe(['fail', 'import', 'setup', 'duplicate', 'empty'].includes(mode) ? 1 : 0)
  expect(result.manifest.outcome).toBe(['fail', 'import', 'setup', 'duplicate', 'empty'].includes(mode) ? 'failed' : 'passed')
  if (mode === 'duplicate') {
    expect(result.stdout + result.stderr).toMatch(/Duplicate full test name/)
    expect(result.stdout).toContain('DUPLICATE_UPLOAD_BEFORE=false')
    expect(result.stdout).toContain('DUPLICATE_UPLOAD_AFTER=true')
    return
  }
  if (mode === 'empty') return
  const report = JSON.parse(readFileSync(join(result.folder, 'report.json'), 'utf8'))
  expect(report.commitId).toBe(result.manifest.commit)
  expect(report.environments[0].metadata).toMatchObject({ suite: 'runner-contracts', target: 'none', source: 'ci' })
  if (mode === 'import' || mode === 'setup') expect(report.unattributedErrors.length).toBeGreaterThan(0)
  const tests = report.suites.flatMap((s: any) => s.tests ?? [])
  const statuses = tests.flatMap((t: any) => t.attempts.map((a: any) => a.status ?? 'passed'))
  if (mode === 'retry') expect(statuses).toEqual(['failed', 'passed'])
  if (mode === 'pass') expect(statuses).toEqual(['passed'])
  if (mode === 'fail') expect(statuses).toEqual(['failed'])
  if (mode === 'skip') expect(statuses).toEqual(['skipped'])
})

test('same title in different filenames remains distinct vendor identity', async () => {
  const { mkdtempSync, writeFileSync, mkdirSync } = await import('node:fs')
  const evidenceRoot = process.env.SONICJS_REPORTING_EVIDENCE ?? join(repositoryRoot, 'flakiness-reports/fixture-evidence')
  mkdirSync(evidenceRoot, { recursive: true })
  const folder = mkdtempSync(join(evidenceRoot, 'identities-'))
  for (const name of ['a', 'b']) writeFileSync(join(folder, `${name}.case.ts`), `import { test } from '${repositoryRoot}/node_modules/vitest/dist/index.js'; test('same title', () => {})`)
  // One explicit glob collects both real files; no synthetic report records.
  const result = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(fixture, 'vitest-semantics.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25_000,
    env: { PATH: process.env.PATH, CI: '1', WATCH_CASE_FILE: `${folder}/*.case.ts`, NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  expect(result.status, result.stdout + result.stderr).toBe(0)
  const output = result.stdout.match(/\[flakiness\] Report: (.+)/)![1].trim()
  const report = JSON.parse(readFileSync(join(output, 'report.json'), 'utf8'))
  expect(report.suites.flatMap((s: any) => s.tests).map((t: any) => t.title)).toEqual(['same title', 'same title'])
})


test('invalid vendor output directory fails visibly even when tests pass', () => {
  const result = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(fixture, 'vitest-semantics.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 25_000,
    env: { PATH: process.env.PATH, CI: '1', REPORT_COLLISION: '1', NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  expect(result.error).toBeUndefined()
  expect(result.status, result.stdout + result.stderr).toBe(1)
  expect(result.stdout + result.stderr).toMatch(/ENOTDIR/)
})

test('Vitest SIGINT completes interrupted manifest without masking exit', async () => {
  const child = spawn(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(fixture, 'vitest-semantics.config.ts')], {
    cwd: repositoryRoot,
    env: { PATH: process.env.PATH, CI: '1', CASE_MODE: 'interrupt', NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  let output = ''
  let errors = ''
  let sent = false
  child.stdout.on('data', chunk => {
    output += chunk
    if (!sent && output.includes('INTERRUPT_READY')) { sent = true; child.kill('SIGINT') }
  })
  child.stderr.on('data', chunk => { errors += chunk })
  const timer = setTimeout(() => child.kill('SIGKILL'), 15_000)
  const code = await new Promise<number | null>((resolve, reject) => { child.on('error', reject); child.on('close', resolve) })
  clearTimeout(timer)
  expect(code, output + errors).toBe(130)
  const folder = output.match(/\[flakiness\] Report: (.+)/)![1].trim()
  expect(existsSync(folder)).toBe(true)
  expect(JSON.parse(readFileSync(join(dirname(folder!), 'invocation.json'), 'utf8')).outcome).toBe('interrupted')
  // Pinned Vitest exits before the official reporter can finish. Preserve this blocker.
  expect(existsSync(join(folder, 'report.json'))).toBe(false)
})
