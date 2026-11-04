/** Cleanup is resource-owned in fixtures, not a title/email-pattern sweep.
 * Disposable CI deployments/databases are removed by the workflow that created them.
 * Failed local runs retain their isolated state for diagnosis.
 * Stats reporting is handled by StatsLiveReporter (tests/e2e/stats-live-reporter.ts). */
export default async function globalTeardown(): Promise<void> {
  console.log('E2E teardown: no broad database cleanup performed')
}
