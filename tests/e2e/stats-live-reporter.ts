/**
 * StatsLiveReporter — Playwright custom reporter that streams results to
 * stats.sonicjs.com in real time, one file-batch at a time.
 *
 * Lifecycle:
 *   onBegin  → POST /v1/playwright-runs/start  (opens a "running" run)
 *   onTestEnd → buffer by file; flush via POST /v1/playwright-runs/:id/tests when file is done
  *   onEnd    → awaits all pending POSTs, then POST /v1/playwright-runs/:id/complete
 *
 * Self-disables when PLAYWRIGHT_STATS_API_KEY is not set (checks env + .dev.vars).
 * Never throws — all errors are logged as warnings and swallowed.
 */
import type { Reporter, FullConfig, Suite, TestCase, TestResult, FullResult } from '@playwright/test/reporter'
import { existsSync, readFileSync } from 'node:fs'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { execSync } from 'node:child_process'

const here = dirname(fileURLToPath(import.meta.url))

// ── Helpers ───────────────────────────────────────────────────────────────────

function readDevVar(file: string, key: string): string | undefined {
  if (!existsSync(file)) return undefined
  const line = readFileSync(file, 'utf8').split('\n').find(l => l.startsWith(`${key}=`))
  return line?.slice(key.length + 1).trim() || undefined
}

function getApiKey(): string | undefined {
  return (
    process.env.PLAYWRIGHT_STATS_API_KEY ||
    readDevVar(resolve(here, '../../packages/stats/.dev.vars'), 'PLAYWRIGHT_API_KEY')
  )
}

function getStatsUrl(): string {
  return process.env.PLAYWRIGHT_STATS_URL || 'https://stats.sonicjs.com'
}

function getGitValue(cmd: string, fallback: string): string {
  try { return execSync(cmd, { stdio: 'pipe' }).toString().trim() || fallback }
  catch { return fallback }
}

interface TestPayload {
  test_id: string
  test_title: string
  test_file: string
  project_name?: string
  status: 'passed' | 'failed' | 'skipped' | 'timedOut' | 'interrupted'
  duration_ms: number
  retry: number
  is_flaky: boolean
  error_message?: string
}

/** Normalise Playwright's result.status to the DB enum. All values are already camelCase. */
function normaliseStatus(s: string): TestPayload['status'] {
  if (['passed', 'failed', 'timedOut', 'skipped', 'interrupted'].includes(s)) return s as TestPayload['status']
  return 'failed'
}

// ── Reporter class ────────────────────────────────────────────────────────────

export default class StatsLiveReporter implements Reporter {
  private apiKey: string | undefined
  private statsUrl: string = ''
  private runId: string = ''

  /** Number of tests still expected per absolute file path. */
  private filePendingCount = new Map<string, number>()
  /** Buffered test results per absolute file path. */
  private fileBuffer = new Map<string, TestPayload[]>()
  /**
   * All in-flight POST promises. Awaited in onEnd before sending /complete so
   * the run is not sealed before all file batches have landed.
   */
  private pendingPosts: Promise<void>[] = []

  onBegin(_config: FullConfig, rootSuite: Suite): void {
    this.apiKey = getApiKey()
    if (!this.apiKey) return   // opt-out — no key configured

    this.statsUrl = getStatsUrl()

    // Build run_id: CI uses GITHUB_RUN_ID, local uses timestamp
    this.runId = process.env.GITHUB_ACTIONS === 'true'
      ? `${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT ?? '1'}`
      : `local-${Date.now()}`

    // Walk the full suite tree and count tests per file so we know when each file is done.
    const countTests = (suite: Suite): void => {
      for (const child of suite.suites) countTests(child)
      for (const test of suite.tests) {
        const file = test.location.file
        this.filePendingCount.set(file, (this.filePendingCount.get(file) ?? 0) + 1)
        this.fileBuffer.set(file, this.fileBuffer.get(file) ?? [])
      }
    }
    countTests(rootSuite)

    const isCI = process.env.GITHUB_ACTIONS === 'true'
    const branch = isCI
      ? (process.env.GITHUB_REF_NAME || 'unknown')
      : getGitValue('git rev-parse --abbrev-ref HEAD', 'unknown')
    const commitSha = isCI
      ? (process.env.GITHUB_SHA || 'unknown')
      : getGitValue('git rev-parse HEAD', 'unknown')
    const commitMessage = isCI
      ? ''
      : getGitValue('git log -1 --format=%s', '')

    const startPost = this.postJson('/v1/playwright-runs/start', {
      run_id: this.runId,
      project: 'sonicjs',
      branch,
      commit_sha: commitSha,
      commit_message: commitMessage,
      ci_provider: isCI ? 'github_actions' : 'local',
      ci_run_url: isCI && process.env.GITHUB_SERVER_URL && process.env.GITHUB_REPOSITORY && process.env.GITHUB_RUN_ID
        ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
        : '',
      triggered_by: process.env.GITHUB_EVENT_NAME || 'manual',
      source: isCI ? 'ci' : 'local',
      started_at: new Date().toISOString(),
    }).catch(err => console.warn('[stats-reporter] onBegin POST failed:', err))
    this.pendingPosts.push(startPost)
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    if (!this.apiKey || !this.runId) return

    const file = test.location.file

    const isFlaky = result.status === 'passed' && result.retry > 0

    const payload: TestPayload = {
      test_id: test.id,
      test_title: test.titlePath().filter(Boolean).join(' › '),
      test_file: file,
      // Use Playwright's project API — most reliable source of the project name.
      project_name: test.parent?.project()?.name ?? undefined,
      status: normaliseStatus(result.status),
      duration_ms: result.duration,
      retry: result.retry,
      is_flaky: isFlaky,
      error_message: result.error?.message
        ? result.error.message.slice(0, 500)
        : undefined,
    }

    // Always buffer the attempt (all retries are stored for history).
    const buf = this.fileBuffer.get(file) ?? []
    buf.push(payload)
    this.fileBuffer.set(file, buf)

    // Only decrement the pending counter on the FINAL attempt of this test.
    // A test is finished when it passed/skipped, or exhausted all retries.
    const isFinalAttempt =
      result.status === 'passed' ||
      result.status === 'skipped' ||
      result.retry >= test.retries

    if (!isFinalAttempt) return   // more retries coming — don't flush yet

    const pending = (this.filePendingCount.get(file) ?? 1) - 1
    this.filePendingCount.set(file, pending)

    if (pending === 0) {
      const flushPost = this.flushFile(file).catch(err =>
        console.warn(`[stats-reporter] flush failed for ${file}:`, err)
      )
      this.pendingPosts.push(flushPost)
    }
  }

  async onEnd(result: FullResult): Promise<void> {
    if (!this.apiKey || !this.runId) return

    // Flush any files that never reached zero (e.g. tests skipped at runtime)
    for (const [file, buf] of this.fileBuffer) {
      if (buf.length > 0) {
        const flushPost = this.flushFile(file).catch(err =>
          console.warn(`[stats-reporter] final flush failed for ${file}:`, err)
        )
        this.pendingPosts.push(flushPost)
      }
    }

    // Await all in-flight batches before sealing the run.
    await Promise.allSettled(this.pendingPosts)

    // Every non-passed outcome (failed, timedout, interrupted) is stored as 'failed'.
    const runStatus = result.status === 'passed' ? 'complete' : 'failed'

    try {
      await this.postJson(`/v1/playwright-runs/${encodeURIComponent(this.runId)}/complete`, {
        finished_at: new Date().toISOString(),
        duration_ms: result.duration ?? 0,
        run_status: runStatus,
      })
      console.log(`✓ Live stats complete (${this.runId})`)
    } catch (err) {
      console.warn('[stats-reporter] /complete failed (non-fatal):', err)
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async flushFile(file: string): Promise<void> {
    const buf = this.fileBuffer.get(file)
    if (!buf || buf.length === 0) return
    this.fileBuffer.delete(file)   // clear before await to avoid double-flush

    await this.postJson(`/v1/playwright-runs/${encodeURIComponent(this.runId)}/tests`, {
      tests: buf,
    })
  }

  private async postJson(path: string, body: unknown): Promise<void> {
    // 10-second abort so an unresponsive stats server never stalls the e2e run.
    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), 10_000)
    try {
      const res = await fetch(`${this.statsUrl}${path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      })
      if (!res.ok) {
        const text = await res.text().catch(() => '')
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`)
      }
    } finally {
      clearTimeout(timer)
    }
  }
}
