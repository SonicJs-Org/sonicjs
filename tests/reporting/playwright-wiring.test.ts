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

const stripReporting = (s: string) => s
  .replace("import { cmsReportingTarget, playwrightReporting } from './reporting/options'\n", '')
  .replace("import { playwrightReporting } from './reporting/options'\n", '')
  .replace(/^    \.\.\.playwrightReporting\(.+\),\n/gm, '')
  .replace("reporter: [['list'], ...playwrightReporting('runner-contracts', 'none')],", "reporter: [['list']],")
  .replace("reporter: [['html'], ...playwrightReporting('www-e2e', 'www')],", "reporter: 'html',")

test.each([
  ['workers', 'workers: ci ? 2 : 1,', 'workers: ci ? 3 : 1,'],
  ['retries', 'retries: ci ? (remotePreview ? 3 : 1) : 0,', 'retries: ci ? (remotePreview ? 2 : 1) : 0,'],
  ['comments', '// Keep 2 workers for remote previews.', '// Keep 3 workers for remote previews.'],
  ['server commands', "command: 'npx wrangler dev --local --port 8787',", "command: 'npx wrangler dev --local --port 8788',"],
])('reporting normalization preserves non-reporting %s changes', (_name, original, changed) => {
  const reporting = "    ...playwrightReporting('cms-e2e', cmsReportingTarget(process.env)),\n"
  expect(stripReporting(`${original}\n${reporting}`)).toBe(`${original}\n`)
  expect(stripReporting(`${changed}\n${reporting}`)).toBe(`${changed}\n`)
  expect(stripReporting(`${changed}\n${reporting}`)).not.toBe(stripReporting(`${original}\n${reporting}`))
})

test('all non-reporting production configuration bytes match the consolidated main baseline', async () => {
  const { execFileSync } = await import('node:child_process')
  const { readFileSync } = await import('node:fs')
  const { repositoryRoot } = await import('./options')
  // Reachable from main after squash; includes consolidated configs and intentional workers/retries tuning.
  // Both sides include reporting wiring, so strip only reporting additions before comparing every other byte.
  const baseline = '1dea9731f87a869fd2a46170c20cf8ba5aec4048'
  for (const file of ['playwright.config.ts', 'playwright-no-server.config.ts', 'playwright.smoke.config.ts', 'playwright.www.config.ts', 'playwright.infrastructure.config.ts']) {
    const path = `tests/${file}`
    const original = stripReporting(execFileSync('git', ['show', `${baseline}:${path}`], { cwd: repositoryRoot, encoding: 'utf8' }))
    const current = stripReporting(readFileSync(`${repositoryRoot}/${path}`, 'utf8'))
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
