import { Hono } from 'hono'
import type { Context } from 'hono'

// Type for the Hono app — match what's used in the existing codebase
const playwrightIngest = new Hono()

/**
 * Bearer token auth middleware.
 * Reads PLAYWRIGHT_API_KEY from Workers secret / .dev.vars.
 */
function requirePlaywrightAuth() {
  return async (c: Context, next: () => Promise<void>) => {
    const authHeader = c.req.header('Authorization')
    const token = authHeader?.replace('Bearer ', '')
    const expected = (c.env as any).PLAYWRIGHT_API_KEY as string | undefined
    if (!expected || !token || token !== expected) {
      return c.json({ error: 'Unauthorized' }, 401)
    }
    return next()
  }
}

/**
 * Truncate a string to maxLen chars, appending "…" if truncated.
 */
function truncate(s: string | undefined | null, maxLen: number): string | undefined {
  if (!s) return undefined
  return s.length > maxLen ? s.slice(0, maxLen - 1) + '…' : s
}

/**
 * Retry a D1 batch, backing off on "D1 DB is overloaded" errors.
 * Uses jittered exponential backoff: delay = base * 2^(attempt-1) + rand(base).
 * Non-overload errors and the final attempt re-throw unchanged.
 */
async function batchWithRetry(
  db: { batch: (stmts: D1PreparedStatement[]) => Promise<unknown> },
  stmts: D1PreparedStatement[],
  maxAttempts = 3,
  baseDelayMs = 1000,
): Promise<void> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      await db.batch(stmts)
      return
    } catch (err: unknown) {
      const msg = (err as { message?: string })?.message ?? ''
      const isOverloaded = msg.includes('D1 DB is overloaded')
      if (!isOverloaded || attempt === maxAttempts) throw err
      // Jitter spreads retries across concurrent ingest requests so they
      // don't all retry at the same instant and re-collide on D1.
      const delay = baseDelayMs * Math.pow(2, attempt - 1) + Math.random() * baseDelayMs
      // eslint-disable-next-line no-console
      console.warn(
        `[playwright] D1 overloaded — retrying batch (attempt ${attempt}/${maxAttempts}) in ${Math.round(delay)}ms`,
      )
      await new Promise<void>((r) => { (globalThis as any).setTimeout(r, delay) })
    }
  }
}

/**
 * Payload shape from the GitHub Actions script.
 * This matches what our `report-playwright.sh` script will send.
 */
interface IngestPayload {
  run: {
    run_id: string
    project: string
    branch: string
    commit_sha: string
    commit_message?: string
    ci_provider: string
    ci_run_url?: string
    triggered_by?: string
    started_at: string
    finished_at: string
    duration_ms: number
  }
  tests: Array<{
    test_id: string
    test_title: string
    test_file: string
    project_name?: string
    status: 'passed' | 'failed' | 'skipped' | 'timedOut' | 'interrupted'
    duration_ms: number
    retry: number
    is_flaky: boolean
    error_message?: string
    error_snippet?: string
  }>
}

playwrightIngest.post('/', requirePlaywrightAuth(), async (c) => {
  try {
    const body = await c.req.json<IngestPayload>()

    if (!body.run?.run_id || !Array.isArray(body.tests)) {
      return c.json({ error: 'Missing required fields: run.run_id, tests[]' }, 400)
    }

    const db = (c.env as any).DB as D1Database
    const now = Math.floor(Date.now() / 1000)

    // Compute aggregates from the test results.
    // For aggregate counts, only use the FINAL attempt of each test
    // (highest retry number per test_id+project_name combo).
    const finalResults = new Map<string, typeof body.tests[number]>()
    for (const t of body.tests) {
      const key = `${t.test_id}::${t.project_name ?? ''}`
      const existing = finalResults.get(key)
      if (!existing || t.retry > existing.retry) {
        finalResults.set(key, t)
      }
    }

    let passed = 0, failed = 0, skipped = 0, flaky = 0
    for (const t of finalResults.values()) {
      if (t.status === 'passed') passed++
      else if (t.status === 'failed' || t.status === 'timedOut' || t.status === 'interrupted') failed++
      else if (t.status === 'skipped') skipped++
      if (t.is_flaky) flaky++
    }
    const total = finalResults.size

    // Insert the run row
    const runId = crypto.randomUUID()
    const runData = {
      run_id: body.run.run_id,
      project: body.run.project || 'sonicjs',
      branch: body.run.branch,
      commit_sha: body.run.commit_sha,
      commit_message: truncate(body.run.commit_message, 200),
      ci_provider: body.run.ci_provider || 'github_actions',
      ci_run_url: body.run.ci_run_url,
      triggered_by: body.run.triggered_by,
      total, passed, failed, skipped, flaky,
      duration_ms: body.run.duration_ms,
      started_at: body.run.started_at,
      finished_at: body.run.finished_at,
    }

    const runTitle = `${runData.project} — ${runData.branch} — ${passed}/${total} passed`

    // Insert the run row (also retried on D1 overload so a dangling run-without-tests
    // is less likely when the DB is under burst pressure from concurrent CI shards).
    await batchWithRetry(db, [
      db.prepare(
        `INSERT INTO documents
           (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
         VALUES (?, ?, 'playwright_runs', 1, 'published', ?, ?, ?, ?, ?)`
      ).bind(runId, runId, runTitle, JSON.stringify(runData), now, now, now)
    ])

    // Insert test rows in small batches to stay within D1's per-10s resource budget.
    // The previous limit of 500 caused D1 overload when multiple CI shards ingested
    // in parallel (each ~750 tests × 2 batches = heavy concurrent write pressure).
    // 100 rows per batch + retry backoff keeps each batch well under the limit.
    const BATCH_SIZE = 100
    const stmts: D1PreparedStatement[] = []
    for (const t of body.tests) {
      const testDocId = crypto.randomUUID()
      const testData = {
        run_id: body.run.run_id,
        test_id: t.test_id,
        test_title: truncate(t.test_title, 500),
        test_file: truncate(t.test_file, 300),
        project_name: t.project_name,
        status: t.status,
        duration_ms: t.duration_ms,
        retry: t.retry ?? 0,
        is_flaky: t.is_flaky ?? false,
        error_message: truncate(t.error_message, 500),
        error_snippet: truncate(t.error_snippet, 300),
      }
      const testTitle = `${t.test_title} [${t.status}]`
      stmts.push(
        db.prepare(
          `INSERT INTO documents
             (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
           VALUES (?, ?, 'playwright_tests', 1, 'published', ?, ?, ?, ?, ?)`
        ).bind(testDocId, testDocId, testTitle, JSON.stringify(testData), now, now, now)
      )
    }

    for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
      await batchWithRetry(db, stmts.slice(i, i + BATCH_SIZE))
    }

    return c.json({
      success: true,
      run_id: body.run.run_id,
      tests_stored: body.tests.length,
      summary: { total, passed, failed, skipped, flaky },
    }, 201)
  } catch (err) {
    console.error('[playwright] /v1/playwright-runs insert failed:', err)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export { playwrightIngest }
