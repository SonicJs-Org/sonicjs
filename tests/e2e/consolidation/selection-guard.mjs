import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { collectLeaves, compareMultisets, normalizeLeaf } from './coverage-guard.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../..')
const environment = { ...process.env }
for (const key of ['CI', 'BASE_URL', 'E2E_REUSE_SERVER', 'PLAYWRIGHT_STATS_API_KEY']) delete environment[key]
const baseline = JSON.parse(readFileSync(resolve(here, 'baseline-leaves.json'), 'utf8'))
const smokeBaseline = JSON.parse(readFileSync(resolve(here, 'baseline-smoke-leaves.json'), 'utf8'))
for (const [name, expected] of [
  ['smoke', smokeBaseline],
  ['infrastructure', baseline.filter(leaf => JSON.parse(leaf)[0] === '126-runner-contracts.spec.ts')],
]) {
  const raw = execFileSync(process.execPath, [resolve(root, 'node_modules/playwright/cli.js'),
    'test', `--config=tests/playwright.${name}.config.ts`, '--list', '--reporter=json',
  ], { cwd: root, env: environment, encoding: 'utf8', maxBuffer: 20_000_000 })
  const actual = collectLeaves(JSON.parse(raw))
  compareMultisets(expected.map(normalizeLeaf), actual.map(normalizeLeaf))
  console.log(`${name}: ${actual.length} original tests preserved`)
}
