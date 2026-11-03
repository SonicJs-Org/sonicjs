import { existsSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execFileSync } from 'node:child_process'

const here = dirname(fileURLToPath(import.meta.url))

/** Cleanup is resource-owned in fixtures, not a title/email-pattern sweep.
 * Disposable CI deployments/databases are removed by the workflow that created them.
 * Failed local runs retain their isolated state for diagnosis. */
export default async function globalTeardown(): Promise<void> {
  console.log('E2E teardown: no broad database cleanup performed')

  // Report results to stats.sonicjs.com when PLAYWRIGHT_STATS_API_KEY is set.
  // Skips silently when the key is absent (opt-in for local devs).
  // CI reporting is handled by the GitHub Actions workflow step instead
  // (it uses `if: always()` so it runs even when tests fail).
  const apiKey = process.env.PLAYWRIGHT_STATS_API_KEY
  if (!apiKey || process.env.CI) return

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
