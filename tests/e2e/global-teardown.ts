import { existsSync, readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'

const here = dirname(fileURLToPath(import.meta.url))

/** Read a key=value line from a .dev.vars / .env file. Returns undefined if not found. */
function readDevVar(file: string, key: string): string | undefined {
  if (!existsSync(file)) return undefined
  const line = readFileSync(file, 'utf8')
    .split('\n')
    .find(l => l.startsWith(`${key}=`))
  return line?.slice(key.length + 1).trim() || undefined
}

/** Cleanup is resource-owned in fixtures, not a title/email-pattern sweep.
 * Disposable CI deployments/databases are removed by the workflow that created them.
 * Failed local runs retain their isolated state for diagnosis. */
export default async function globalTeardown(): Promise<void> {
  console.log('E2E teardown: no broad database cleanup performed')

  // CI reporting is handled by the workflow step (runs even when tests fail).
  if (process.env.CI) return

  // Resolve the API key: env var first, then packages/stats/.dev.vars fallback.
  const devVarsFile = resolve(here, '../../packages/stats/.dev.vars')
  const apiKey =
    process.env.PLAYWRIGHT_STATS_API_KEY ||
    readDevVar(devVarsFile, 'PLAYWRIGHT_API_KEY')

  if (!apiKey) return  // no key anywhere — skip silently

  const resultsFile = resolve(here, '../../test-results/results.json')
  if (!existsSync(resultsFile)) {
    console.log('⚠ stats reporter: no test-results/results.json found, skipping')
    return
  }

  const script = resolve(here, '../../packages/stats/scripts/report-playwright.sh')
  try {
    execFileSync('bash', [script, resultsFile], {
      env: { ...process.env, PLAYWRIGHT_STATS_API_KEY: apiKey },
      stdio: 'pipe',
      timeout: 30_000,
    })
    console.log('✓ Playwright results reported to stats.sonicjs.com')
  } catch (err: unknown) {
    // Always non-fatal — a stats outage must never break local dev workflow.
    const msg = err instanceof Error ? err.message : String(err)
    console.warn('⚠ Could not report to stats (non-fatal):', msg)
  }
}
