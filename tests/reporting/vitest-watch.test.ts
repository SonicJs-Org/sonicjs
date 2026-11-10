import { spawn } from 'node:child_process'
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { expect, test } from 'vitest'
import { repositoryRoot } from './options'
import { reportingScratch } from './scratch'

// Change a real imported test file. No replay of vendor callbacks or reports.
test.each(['vendor', 'integrated'])('real watch lifecycle: %s', async mode => {
  const evidence = reportingScratch('watch-')
  const work = mkdtempSync(join(repositoryRoot, 'tests/reporting/fixtures/watch-'))
  const file = join(work, 'watch.case.ts')
  const source = (pass: boolean) => `import { test, expect } from '${repositoryRoot}/node_modules/vitest/dist/index.js'; test('watch identity', () => expect(${pass}).toBe(true))\n`
  writeFileSync(file, source(true))
  const child = spawn(process.execPath, [join(repositoryRoot, 'node_modules/vitest/vitest.mjs'), '--watch', '--config', join(repositoryRoot, 'tests/reporting/fixtures/vitest-semantics.config.ts')], {
    cwd: repositoryRoot,
    env: { PATH: process.env.PATH, CI: '1', WATCH_CASE_FILE: file, RAW_VENDOR_WATCH: mode === 'vendor' ? '1' : '0', NODE_OPTIONS: `--require=${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}` },
  })
  let output = ''
  let errors = ''
  child.stdout.on('data', chunk => { output += chunk })
  child.stderr.on('data', chunk => { errors += chunk })
  const waitFor = async (condition: () => boolean) => {
    const start = Date.now()
    while (!condition()) {
      if (child.exitCode !== null || Date.now() - start > 12_000) throw new Error(output + errors)
      await new Promise(resolve => setTimeout(resolve, 50))
    }
  }
  try {
    await waitFor(() => output.includes('Waiting for file changes'))
    const first = output.match(/\[flakiness\] Report: (.+)/)![1].trim()
    const original = readFileSync(join(first, 'report.json'), 'utf8')
    const firstManifest = mode === 'integrated' ? readFileSync(join(dirname(first), 'invocation.json'), 'utf8') : undefined
    writeFileSync(file, source(false))
    await waitFor(() => (output.match(/(?:Waiting|Watching) for file changes/g) ?? []).length >= 2)
    const folders = [...output.matchAll(/\[flakiness\] Report: (.+)/g)].map(m => m[1].trim())
    if (mode === 'vendor') {
      expect(folders).toHaveLength(1)
      const rewritten = JSON.parse(readFileSync(join(first, 'report.json'), 'utf8'))
      expect(readFileSync(join(first, 'report.json'), 'utf8')).not.toBe(original)
      expect(rewritten.suites[0].tests[0].attempts).toHaveLength(1)
      expect(rewritten.suites[0].tests[0].attempts[0].status).toBe('failed')
      return
    }
    expect(folders).toHaveLength(2)
    expect(readFileSync(join(dirname(first), 'invocation.json'), 'utf8')).toBe(firstManifest)
    expect(folders[0]).not.toBe(folders[1])
    expect(readFileSync(join(first, 'report.json'), 'utf8')).toBe(original)
    for (const [index, folder] of folders.entries()) {
      expect(folder).toMatch(/\/vendor$/)
      const manifest = JSON.parse(readFileSync(join(dirname(folder), 'invocation.json'), 'utf8'))
      expect(manifest.outcome).toBe(index ? 'failed' : 'passed')
      const report = JSON.parse(readFileSync(join(folder, 'report.json'), 'utf8'))
      expect(report.suites[0].tests[0].attempts).toHaveLength(1)
      expect(report.suites[0].tests[0].attempts[0].status ?? 'passed').toBe(index ? 'failed' : 'passed')
    }
  } finally {
    writeFileSync(join(evidence, 'stdout.log'), output)
    writeFileSync(join(evidence, 'stderr.log'), errors)
    child.kill('SIGINT')
    const timer = setTimeout(() => child.kill('SIGKILL'), 2000)
    await new Promise(resolve => child.on('close', resolve))
    clearTimeout(timer)
    rmSync(work, { recursive: true, force: true })
  }
}, 30_000)
