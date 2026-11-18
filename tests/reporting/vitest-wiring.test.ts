import { expect, test } from 'vitest'
import core from '../../packages/core/vitest.config'
import sdk from '../../packages/sdk/vitest.config'
import root from '../../vitest.config'

test.each([['core-unit', core], ['sdk-unit', sdk], ['root-unit', root]] as const)('native wiring %s', (suite, config) => {
  const reporters = config.test!.reporters as any[]
  expect(reporters[0]).toBe('default')
  expect(reporters.filter(r => Array.isArray(r) && r[0] === '@flakiness/vitest')).toHaveLength(1)
  expect(config.test!.includeTaskLocation).toBe(true)
  expect(reporters.find(r => Array.isArray(r) && r[0] === '@flakiness/vitest')[1].outputFolder).toContain(`/flakiness-reports/${suite}/`)
})

test('core and root discovery/excludes/coverage bytes unchanged', async () => {
  const { execFileSync } = await import('node:child_process')
  const { readFileSync } = await import('node:fs')
  const { repositoryRoot } = await import('./options')
  for (const file of ['packages/core/vitest.config.ts', 'packages/sdk/vitest.config.ts', 'vitest.config.ts']) {
    const before = execFileSync('git', ['show', `d931cb73c:${file}`], { cwd: repositoryRoot, encoding: 'utf8' })
    const current = readFileSync(`${repositoryRoot}/${file}`, 'utf8')
      .replace(/^import \{ vitestReporting \} from '.+'\n/m, '')
      .replace(/^    \.\.\.vitestReporting\('.+'\),\n/m, '')
    expect(current, file).toBe(before)
  }
})

test('sample inherits identical root discovery and reports genuine failures', async () => {
  const { default: sample } = await import('../../my-sonicjs-app/vitest.config')
  expect(sample.test!.include).toEqual(root.test!.include)
  expect(sample.test!.exclude).toEqual(root.test!.exclude)
  expect(sample.test!.coverage).toEqual(root.test!.coverage)
  expect(JSON.stringify(sample.test!.reporters)).toContain('/flakiness-reports/sample-unit/')
})

test('config evaluation from root/package cwd reserves independent absolute folders', async () => {
  const { spawnSync } = await import('node:child_process')
  const { join, isAbsolute } = await import('node:path')
  const { repositoryRoot } = await import('./options')
  for (const name of ['core', 'sdk']) {
    const paths = [repositoryRoot, join(repositoryRoot, `packages/${name}`)].map(cwd => {
      const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', `
        const { default: config } = await import(${JSON.stringify(join(repositoryRoot, `packages/${name}/vitest.config.ts`))});
        console.log(config.test.reporters.find(r => Array.isArray(r) && r[0] === '@flakiness/vitest')[1].outputFolder);
      `], { cwd, encoding: 'utf8', timeout: 10_000,
        env: { PATH: process.env.PATH, CI: '1', NODE_OPTIONS: `--require=${join(repositoryRoot, 'tests/reporting/fixtures/deny-network.cjs')}` } })
      expect(result.status, result.stdout + result.stderr).toBe(0)
      return result.stdout.trim()
    })
    expect(paths[0]).not.toBe(paths[1])
    for (const path of paths) {
      expect(isAbsolute(path)).toBe(true)
      expect(path).toContain(`${repositoryRoot}/flakiness-reports/${name}-unit/`)
    }
  }
})

test('Vitest list mode reserves no reporting lifecycle or environment', async () => {
  const { vitestReporting } = await import('./vitest-integration')
  const previous = process.env.FK_ENV_SUITE
  process.argv.splice(2, 0, 'list')
  try {
    expect(vitestReporting('core-unit')).toEqual({})
    expect(process.env.FK_ENV_SUITE).toBe(previous)
  } finally { process.argv.splice(2, 1) }
})
