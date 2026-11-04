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
// Repository root — used to compute relative test file paths
const repoRoot = resolve(here, '../..')

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
  /** Whether /start actually created the run (vs returning an existing one) */
  private runCreated: boolean = false

  /** Number of tests still expected per absolute file path. */
  private filePendingCount = new Map<string, number>()
  /** Buffered test results per absolute file path. */
  private fileBuffer = new Map<string, TestPayload[]>()
  /**
   * All in-flight POST promises. Awaited in onEnd before sending /complete so
   * the run is not sealed before all file batches have landed.
   */
  private pendingPosts: Promise<unknown>[] = []

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

    // Calculate expected total tests
    let expectedTotal = 0
    for (const count of this.filePendingCount.values()) {
      expectedTotal += count
    }

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

    // Extract PR number from GITHUB_REF_NAME (e.g., "123/merge") or branch patterns like "fix/issue-123"
    let prNumber: number | null = null
    if (isCI && process.env.GITHUB_REF_NAME) {
      const prMatch = process.env.GITHUB_REF_NAME.match(/^(\d+)\/merge$/)
      if (prMatch) {
        prNumber = parseInt(prMatch[1], 10)
      }
    }
    if (!prNumber && branch) {
      // Try to extract from branch name patterns like fix/issue-123, feature/pr-456
      const branchMatch = branch.match(/(?:issue-|pr-|#)(\d+)/i)
      if (branchMatch) {
        prNumber = parseInt(branchMatch[1], 10)
      }
    }

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
      expected_total: expectedTotal,
      pr_number: prNumber,
      base_url: process.env.BASE_URL || null,
    }).then(res => {
      // Track whether /start actually created the run
      this.runCreated = res?.created === true
    }).catch(err => console.warn('[stats-reporter] onBegin POST failed:', err))
    this.pendingPosts.push(startPost)
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    if (!this.apiKey || !this.runId) return

    const file = test.location.file

    const isFlaky = result.status === 'passed' && result.retry > 0

    // Convert absolute path to repo-relative for portability across machines
    const relativeFile = file.startsWith(repoRoot)
      ? file.slice(repoRoot.length + 1)
      : file

    const payload: TestPayload = {
      test_id: test.id,
      test_title: test.titlePath().filter(Boolean).join(' › '),
      test_file: relativeFile,
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

    // FIRST: await all in-flight batches from onTestEnd before touching fileBuffer
    // This prevents duplicate flushes if a flushFile was in progress when onEnd started
    await Promise.allSettled(this.pendingPosts)
    this.pendingPosts = []

    // THEN: flush any files that never reached zero (e.g. tests skipped at runtime)
    const finalFlushes: Promise<unknown>[] = []
    for (const [file, buf] of this.fileBuffer) {
      if (buf.length > 0) {
        const flushPost = this.flushFile(file).catch(err =>
          console.warn(`[stats-reporter] final flush failed for ${file}:`, err)
        )
        finalFlushes.push(flushPost)
      }
    }

    // Await final flushes
    await Promise.allSettled(finalFlushes)

    // Every non-passed outcome (failed, timedout, interrupted) is stored as 'failed'.
    const runStatus = result.status === 'passed' ? 'complete' : 'failed'

    // Call /complete with bounded retry (3 attempts, exponential backoff)
    const completePayload = {
      finished_at: new Date().toISOString(),
      duration_ms: result.duration ?? 0,
      run_status: runStatus,
    }

    let lastError: unknown
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        await this.postJson(`/v1/playwright-runs/${encodeURIComponent(this.runId)}/complete`, completePayload)
        console.log(`✓ Live stats complete (${this.runId})${this.runCreated ? '' : ' [rejoined existing run]'}`)
        return
      } catch (err) {
        lastError = err
        if (attempt < 3) {
          // Exponential backoff: 1s, 2s
          await new Promise(r => setTimeout(r, 1000 * attempt))
        }
      }
    }
    console.warn('[stats-reporter] /complete failed after 3 attempts (non-fatal):', lastError)
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async flushFile(file: string): Promise<void> {
    const buf = this.fileBuffer.get(file)
    if (!buf || buf.length === 0) return

    await this.postJson(`/v1/playwright-runs/${encodeURIComponent(this.runId)}/tests`, {
      tests: buf,
    })
    // Delete only after successful POST — if timeout/error, onEnd will retry
    this.fileBuffer.delete(file)
  }

  private async postJson(path: string, body: unknown): Promise<Record<string, unknown> | undefined> {
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
      return await res.json().catch(() => ({})) as Record<string, unknown>
    } finally {
      clearTimeout(timer)
    }
  }
}
