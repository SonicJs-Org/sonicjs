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

test('all non-reporting production configuration bytes match Task2', async () => {
  const { execFileSync } = await import('node:child_process')
  const { readFileSync } = await import('node:fs')
  const { repositoryRoot } = await import('./options')
  for (const file of ['playwright.config.ts', 'playwright-no-server.config.ts', 'playwright.smoke.config.ts', 'playwright.www.config.ts', 'playwright.infrastructure.config.ts']) {
    const path = `tests/${file}`
    const original = execFileSync('git', ['show', `4498f0126:${path}`], { cwd: repositoryRoot, encoding: 'utf8' })
    const current = readFileSync(`${repositoryRoot}/${path}`, 'utf8')
      .replace("import { playwrightReporting } from './reporting/options'\n", '')
      .replace(/^    \.\.\.playwrightReporting\(.+\),\n/gm, '')
      .replace("reporter: [['list'], ...playwrightReporting('runner-contracts', 'none')],", "reporter: [['list']],")
      .replace("reporter: [['html'], ...playwrightReporting('www-e2e', 'www')],", "reporter: 'html',")
    expect(current, path).toBe(original)
  }
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
