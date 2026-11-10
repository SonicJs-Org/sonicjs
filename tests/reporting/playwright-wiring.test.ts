import { expect, test } from 'vitest'
import main from '../playwright.config'
import smoke from '../playwright.smoke.config'
import infra from '../playwright.infrastructure.config'
import www from '../playwright.www.config'
import noServer from '../playwright-no-server.config'

const names = (config: typeof main): string[] => typeof config.reporter === 'string' ? [config.reporter] : (config.reporter ?? []).map(r => r[0])
test.each([
  ['main', main, ['list', 'html', 'json', 'junit'], 'cms-e2e'],
  ['smoke', smoke, ['list', 'html', 'json', 'junit'], 'cms-smoke'],
  ['infra', infra, ['list'], 'runner-contracts'],
  ['www', www, ['html'], 'www-e2e'],
  ['no-server', noServer, ['list', 'html', 'json', 'junit'], 'cms-e2e'],
] as const)('retains native reporters and one vendor: %s', (_name, config, native, suite) => {
  expect(names(config).filter(n => n === '@flakiness/playwright')).toHaveLength(1)
  expect(names(config).filter(n => ['list', 'html', 'json', 'junit'].includes(n))).toEqual(native)
  expect(JSON.stringify(config.reporter)).toContain(`/flakiness-reports/${suite}/`)
})
test('inherits CMS reporter once; infrastructure owns no application lifecycle', () => {
  expect(noServer.reporter).toBe(main.reporter)
  expect(noServer.webServer).toBeUndefined()
  expect(names(main).some(n => n.endsWith('stats-live-reporter.ts'))).toBe(true)
  expect(infra.webServer).toBeUndefined()
  expect(infra.globalSetup).toBeUndefined()
  expect(infra.globalTeardown).toBeUndefined()
})

// PR #1170's merged main commit is reachable in a fresh full-history CI checkout.
const preservationBaseline = '1dea9731f87a869fd2a46170c20cf8ba5aec4048'

async function assertBaselineHistory(cwd: string, baseline = preservationBaseline) {
  const { execFileSync } = await import('node:child_process')
  expect(() => execFileSync('git', ['merge-base', '--is-ancestor', baseline, 'HEAD'], { cwd })).not.toThrow()
}

async function assertConfigurationBytes(cwd: string, baseline = preservationBaseline) {
  const { execFileSync } = await import('node:child_process')
  const { readFileSync } = await import('node:fs')
  const stripReporting = (s: string) => s
    .replace("import { cmsReportingTarget, playwrightReporting } from './reporting/options'\n", '')
    .replace("import { playwrightReporting } from './reporting/options'\n", '')
    .replace(/^    \.\.\.playwrightReporting\(.+\),\n/gm, '')
    .replace("reporter: [['list'], ...playwrightReporting('runner-contracts', 'none')],", "reporter: [['list']],")
    .replace("reporter: [['html'], ...playwrightReporting('www-e2e', 'www')],", "reporter: 'html',")
  for (const file of ['playwright.config.ts', 'playwright-no-server.config.ts', 'playwright.smoke.config.ts', 'playwright.www.config.ts', 'playwright.infrastructure.config.ts']) {
    const path = `tests/${file}`
    const original = stripReporting(execFileSync('git', ['show', `${baseline}:${path}`], { cwd, encoding: 'utf8' }))
    const current = stripReporting(readFileSync(`${cwd}/${path}`, 'utf8'))
    expect(current, path).toBe(original)
  }
}

test('preservation baseline belongs to recorded main history', async () => {
  const { repositoryRoot } = await import('./options')
  await assertBaselineHistory(repositoryRoot)
})

test('all non-reporting production configuration bytes match merged main baseline', async () => {
  const { repositoryRoot } = await import('./options')
  await assertConfigurationBytes(repositoryRoot)
})

test('full-history remote-less checkout preserves pinned history and configuration; invalid baselines fail', async () => {
  const { execFileSync } = await import('node:child_process')
  const { repositoryRoot } = await import('./options')
  const { reportingScratch } = await import('./scratch')
  const cwd = reportingScratch('remote-less-')
  execFileSync('git', ['clone', '--no-hardlinks', '--quiet', repositoryRoot, cwd])
  execFileSync('git', ['remote', 'remove', 'origin'], { cwd })
  expect(execFileSync('git', ['remote'], { cwd, encoding: 'utf8' })).toBe('')
  expect(execFileSync('git', ['for-each-ref', '--format=%(refname)', 'refs/remotes'], { cwd, encoding: 'utf8' })).toBe('')
  expect(execFileSync('git', ['rev-parse', '--is-shallow-repository'], { cwd, encoding: 'utf8' }).trim()).toBe('false')
  await assertBaselineHistory(cwd)
  await assertConfigurationBytes(cwd)
  await expect(assertBaselineHistory(cwd, '0'.repeat(40))).rejects.toThrow()
  const obsolete = execFileSync('git', ['rev-list', '--max-parents=0', 'HEAD'], { cwd, encoding: 'utf8' }).trim().split('\n')[0]!
  await expect(assertConfigurationBytes(cwd, obsolete)).rejects.toThrow()
})

test('list mode never registers vendor or changes environment', async () => {
  const { playwrightReporting } = await import('./options')
  const previous = process.env.FK_ENV_SUITE
  process.argv.push('--list')
  try {
    expect(playwrightReporting('cms-e2e', 'local-worker')).toEqual([])
    expect(process.env.FK_ENV_SUITE).toBe(previous)
  } finally { process.argv.pop() }
})
