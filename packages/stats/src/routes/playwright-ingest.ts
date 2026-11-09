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

    await db.prepare(
      `INSERT INTO documents
         (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
       VALUES (?, ?, 'playwright_runs', 1, 'published', ?, ?, ?, ?, ?)`
    ).bind(runId, runId, runTitle, JSON.stringify(runData), now, now, now).run()

    // Insert test rows in batches (D1 batch API to avoid per-statement overhead)
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

    // D1 batch — up to 500 statements per batch
    const BATCH_SIZE = 500
    for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
      await db.batch(stmts.slice(i, i + BATCH_SIZE))
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
