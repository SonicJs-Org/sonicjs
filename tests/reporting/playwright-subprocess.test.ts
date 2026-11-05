import { spawn, spawnSync } from 'node:child_process'
import { readFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { expect, test } from 'vitest'
import { repositoryRoot } from './options'

const fixture = join(repositoryRoot, 'tests/reporting/fixtures')
function run(mode: string) {
  const result = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/@playwright/test/cli.js'), 'test', '--config', join(fixture, 'semantics.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 20_000,
    env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR, CI: '1', CASE_MODE: mode,
      NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  expect(result.error).toBeUndefined()
  const folder = result.stdout.match(/REPORT_FOLDER=(.+)/)?.[1]?.trim()
  expect(folder, result.stdout + result.stderr).toBeTruthy()
  return { ...result, folder: folder!, report: JSON.parse(readFileSync(join(folder!, 'report.json'), 'utf8')) }
}
test.each(['pass', 'fail', 'retry', 'static-skip', 'runtime-skip', 'expected-failure', 'timeout', 'setup', 'import'])('actual vendor and native status: %s', mode => {
  const result = run(mode)
  expect(result.status, result.stdout + result.stderr).toBe(['fail', 'timeout', 'setup', 'import'].includes(mode) ? 1 : 0)
  if (!['setup', 'import'].includes(mode)) expect(result.report.environments[0].metadata).toMatchObject({ suite: 'runner-contracts', target: 'none' })
  if (['setup', 'import'].includes(mode)) expect(result.report.unattributedErrors.length).toBeGreaterThan(0)
  expect(existsSync(join(`${result.folder}-native`, 'native.json'))).toBe(true)
  expect(existsSync(join(`${result.folder}-native`, 'native.xml'))).toBe(true)
  expect(existsSync(join(`${result.folder}-native`, 'html/index.html'))).toBe(true)
  const tests = (result.report.suites ?? []).flatMap((s: any) => s.tests ?? [])
  const statuses = tests.flatMap((t: any) => t.attempts.map((a: any) => a.status ?? 'passed'))
  if (mode === 'retry') expect(statuses).toEqual(['failed', 'passed'])
  if (mode === 'fail' || mode === 'expected-failure') expect(statuses).toEqual(['failed'])
  if (mode === 'expected-failure') expect(tests[0].attempts[0].expectedStatus).toBe('failed')
  if (mode === 'fail') expect(tests[0].attempts[0].expectedStatus ?? 'passed').toBe('passed')
  if (mode === 'timeout') expect(statuses).toEqual(['timedOut'])
  if (mode.includes('skip')) expect(statuses).toEqual(['skipped'])
  if (mode === 'retry') expect(tests.flatMap((t: any) => t.attempts)).toHaveLength(2)
  if (mode === 'pass') expect(readdirSync(join(result.folder, 'attachments')).length).toBeGreaterThan(0)
})

test('two native output cleanups preserve actual Vitest and Playwright reports and attachments', () => {
  const vitest = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), 'run', '--config', join(fixture, 'vendor-vitest.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 20_000,
    env: { PATH: process.env.PATH, CI: '1', NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  expect(vitest.status, vitest.stdout + vitest.stderr).toBe(0)
  const folder = vitest.stdout.match(/REPORT_FOLDER=(.+)/)![1].trim()
  const before = readFileSync(join(folder, 'report.json'), 'utf8')
  const first = run('pass')
  const attachment = readdirSync(join(first.folder, 'attachments'))[0]
  const body = readFileSync(join(first.folder, 'attachments', attachment), 'utf8')
  const second = run('pass')
  expect(new Set([folder, first.folder, second.folder]).size).toBe(3)
  expect(readFileSync(join(folder, 'report.json'), 'utf8')).toBe(before)
  expect(readFileSync(join(first.folder, 'attachments', attachment), 'utf8')).toBe(body)
  expect(existsSync(join(second.folder, 'report.json'))).toBe(true)
})

function interruptOnReady(sendInterrupt: () => void) {
  let output = ''
  let sent = false
  return (chunk: string) => {
    output += chunk
    if (!sent && output.includes('INTERRUPT_READY')) {
      sent = true
      sendInterrupt()
    }
  }
}

test('SIGINT is sent exactly once across multiple stdout chunks', () => {
  const signals: string[] = []
  const onData = interruptOnReady(() => { signals.push('SIGINT') })
  onData('starting\nINTERRUPT_')
  expect(signals).toEqual([])
  onData('READY\n')
  expect(signals).toEqual(['SIGINT'])
  onData('flushing report\n')
  onData('INTERRUPT_READY\nreport flushed\n')
  expect(signals).toEqual(['SIGINT'])
})

test('SIGINT exits 130; pinned vendor drops interrupted attempts (cutover blocker)', async () => {
  const child = spawn(process.execPath, [join(repositoryRoot, 'node_modules/@playwright/test/cli.js'), 'test', '--config', join(fixture, 'semantics.config.ts')], {
    cwd: repositoryRoot, env: { PATH: process.env.PATH, CI: '1', CASE_MODE: 'interrupt', NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  let output = ''
  let errors = ''
  const onData = interruptOnReady(() => { child.kill('SIGINT') })
  child.stderr.on('data', chunk => { errors += chunk })
  child.stdout.on('data', chunk => {
    output += chunk
    onData(chunk.toString())
  })
  const watchdog = setTimeout(() => child.kill('SIGKILL'), 15_000)
  const code = await new Promise<number | null>((resolve, reject) => { child.on('error', reject); child.on('close', resolve) })
  clearTimeout(watchdog)
  expect(code, output + errors).toBe(130)
  const folder = output.match(/REPORT_FOLDER=(.+)/)![1].trim()
  const report = JSON.parse(readFileSync(join(folder, 'report.json'), 'utf8'))
  const native = JSON.parse(readFileSync(join(`${folder}-native`, 'native.json'), 'utf8'))
  expect(native.suites[0].specs[0].tests[0].results[0].status).toBe('interrupted')
  expect(report.suites[0].tests[0].attempts).toEqual([])
})

test('denial hook blocks fetch, HTTP, HTTPS and sockets', () => {
  const probe = spawnSync(process.execPath, ['--require', join(fixture, 'deny-network.cjs'), '-e', `
    for (const call of [() => fetch('https://example.invalid'),
      () => require('node:http').get('http://example.invalid'),
      () => require('node:https').request('https://example.invalid'),
      () => require('node:net').connect(443, 'example.invalid')]) {
      try { call(); process.exit(2) } catch (error) {
        if (error.message !== 'REPORTING_NETWORK_DENIED') throw error
      }
    }
  `], { encoding: 'utf8', timeout: 5_000 })
  expect(probe.status, probe.stderr).toBe(0)
})

test.each(['1', 'unwritable'])('report-directory error %s is bounded and cannot turn failing test green', collision => {
  const result = spawnSync(process.execPath, [join(repositoryRoot, 'node_modules/@playwright/test/cli.js'), 'test', '--config', join(fixture, 'semantics.config.ts')], {
    cwd: repositoryRoot, encoding: 'utf8', timeout: 15_000,
    env: { PATH: process.env.PATH, CI: '1', CASE_MODE: 'fail', REPORT_COLLISION: collision, NODE_OPTIONS: `--require=${join(fixture, 'deny-network.cjs')}` },
  })
  expect(result.error).toBeUndefined()
  expect(result.status, result.stdout + result.stderr).toBe(1)
  expect(result.stderr + result.stdout).toMatch(collision === '1' ? /ENOTDIR/ : /EACCES/)
})
