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

/** Shared test row shape used by both batch-ingest and live-append endpoints. */
interface TestInput {
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
}

/**
 * Build D1 INSERT statements for a list of test inputs.
 * Extracted so it can be shared between the batch route and the live append route.
 */
function buildTestInserts(db: D1Database, runId: string, tests: TestInput[]): D1PreparedStatement[] {
  return tests.map(t => {
    const testDocId = crypto.randomUUID()
    const testData = {
      run_id: runId,
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
    return db.prepare(
      `INSERT INTO documents
         (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
       VALUES (?, ?, 'playwright_tests', 1, 'published', ?, ?, ?, ?, ?)`
    ).bind(testDocId, testDocId, testTitle, JSON.stringify(testData),
      Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000))
  })
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
    source?: 'local' | 'ci'
    started_at: string
    finished_at: string
    duration_ms: number
  }
  tests: TestInput[]
}

// ── Live reporter endpoints ────────────────────────────────────────────────────

/**
 * POST /start
 * Opens a "running" run record. Called by StatsLiveReporter.onBegin().
 */
playwrightIngest.post('/start', requirePlaywrightAuth(), async (c) => {
  let body: {
    run_id: string; project?: string; branch: string; commit_sha: string
    commit_message?: string; ci_provider: string; ci_run_url?: string
    triggered_by?: string; source?: 'local' | 'ci'; started_at: string
    expected_total?: number; pr_number?: number | null; base_url?: string | null
  }
  try { body = await c.req.json() } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  // Validate all required fields for a valid run start
  if (!body.run_id || !body.branch || !body.commit_sha || !body.ci_provider || !body.started_at) {
    return c.json({ error: 'Missing required fields: run_id, branch, commit_sha, ci_provider, started_at' }, 400)
  }

  try {
    const db = (c.env as any).DB as D1Database
    const now = Math.floor(Date.now() / 1000)
    const runDocId = crypto.randomUUID()

    const runData = {
      run_id: body.run_id,
      project: body.project || 'sonicjs',
      branch: body.branch,
      commit_sha: body.commit_sha,
      commit_message: truncate(body.commit_message, 200),
      ci_provider: body.ci_provider || 'local',
      ci_run_url: body.ci_run_url,
      triggered_by: body.triggered_by,
      source: body.source ?? (body.ci_provider === 'local' ? 'local' : 'ci'),
      run_status: 'running',
      total: 0, passed: 0, failed: 0, skipped: 0, flaky: 0,
      duration_ms: 0,
      started_at: body.started_at,
      finished_at: null,
      expected_total: body.expected_total ?? null,
      pr_number: body.pr_number ?? null,
      base_url: body.base_url ?? null,
    }

    const runTitle = `${runData.project} — ${runData.branch} — running`
    await db.prepare(
      `INSERT INTO documents
         (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
       VALUES (?, ?, 'playwright_runs', 1, 'published', ?, ?, ?, ?, ?)`
    ).bind(runDocId, runDocId, runTitle, JSON.stringify(runData), now, now, now).run()

    return c.json({ success: true, run_id: body.run_id }, 201)
  } catch (err) {
    console.error('[playwright] /start failed:', err)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * Update run aggregate counts in real-time after tests are stored.
 * Queries all tests for this run, computes passed/failed/flaky/total, updates run document.
 */
async function updateRunAggregates(db: D1Database, externalRunId: string): Promise<void> {
  // Query all tests for this run
  const testsR = await db.prepare(
    `SELECT json_extract(data, '$.test_id')       AS test_id,
            json_extract(data, '$.project_name')   AS project_name,
            CAST(json_extract(data, '$.retry') AS INTEGER) AS retry,
            json_extract(data, '$.status')         AS status,
            json_extract(data, '$.is_flaky')       AS is_flaky
     FROM documents
     WHERE type_id = 'playwright_tests'
       AND is_published = 1
       AND deleted_at IS NULL
       AND json_extract(data, '$.run_id') = ?`
  ).bind(externalRunId).all()

  type TestRow = { test_id: string; project_name: string; retry: number; status: string; is_flaky: number | boolean }
  const rows = (testsR?.results ?? []) as TestRow[]

  // Keep only the final attempt per (test_id, project_name)
  const finalByKey = new Map<string, TestRow>()
  for (const r of rows) {
    const key = `${r.test_id}::${r.project_name ?? ''}`
    const ex = finalByKey.get(key)
    if (!ex || r.retry > ex.retry) finalByKey.set(key, r)
  }

  let passed = 0, failed = 0, skipped = 0, flaky = 0
  for (const r of finalByKey.values()) {
    if (r.status === 'passed') passed++
    else if (r.status === 'failed' || r.status === 'timedOut' || r.status === 'interrupted') failed++
    else if (r.status === 'skipped') skipped++
    if (r.is_flaky === true || r.is_flaky === 1) flaky++
  }
  const total = passed + failed + skipped

  // Update the run document with new counts
  const now = Math.floor(Date.now() / 1000)
  await db.prepare(
    `UPDATE documents
     SET data = json_set(data,
       '$.total', ?,
       '$.passed', ?,
       '$.failed', ?,
       '$.skipped', ?,
       '$.flaky', ?
     ),
     updated_at = ?
     WHERE type_id = 'playwright_runs'
       AND is_published = 1
       AND deleted_at IS NULL
       AND json_extract(data, '$.run_id') = ?`
  ).bind(total, passed, failed, skipped, flaky, now, externalRunId).run()
}

/**
 * POST /:run_id/tests
 * Appends a batch of test results to an existing run. Called per-file by StatsLiveReporter.
 */
playwrightIngest.post('/:run_id/tests', requirePlaywrightAuth(), async (c) => {
  let body: { tests: TestInput[] }
  try { body = await c.req.json() } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  if (!Array.isArray(body.tests) || body.tests.length === 0) {
    return c.json({ error: 'Missing required field: tests[]' }, 400)
  }

  try {
    const externalRunId = c.req.param('run_id')
    const db = (c.env as any).DB as D1Database
    const stmts = buildTestInserts(db, externalRunId ?? '', body.tests)

    const BATCH_SIZE = 500
    for (let i = 0; i < stmts.length; i += BATCH_SIZE) {
      await db.batch(stmts.slice(i, i + BATCH_SIZE))
    }

    // Update run aggregates in real-time
    await updateRunAggregates(db, externalRunId ?? '')

    return c.json({ success: true, tests_stored: body.tests.length }, 201)
  } catch (err) {
    console.error('[playwright] /:run_id/tests failed:', err)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

/**
 * POST /:run_id/complete
 * Seals a run — recomputes aggregate counts from stored tests, writes finished_at,
 * and sets run_status to 'complete' or 'failed'. Called by StatsLiveReporter.onEnd().
 */
playwrightIngest.post('/:run_id/complete', requirePlaywrightAuth(), async (c) => {
  let body: { finished_at: string; duration_ms: number; run_status?: 'complete' | 'failed' }
  try { body = await c.req.json() } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  // Validate required completion fields
  if (!body.finished_at || typeof body.duration_ms !== 'number') {
    return c.json({ error: 'Missing required fields: finished_at (string), duration_ms (number)' }, 400)
  }

  try {
    const externalRunId = c.req.param('run_id')
    const db = (c.env as any).DB as D1Database

    // Recompute aggregate counts from the stored test rows (final attempt per test only)
    const testsR = await db.prepare(
      `SELECT json_extract(data, '$.test_id')       AS test_id,
              json_extract(data, '$.project_name')   AS project_name,
              CAST(json_extract(data, '$.retry') AS INTEGER) AS retry,
              json_extract(data, '$.status')         AS status,
              json_extract(data, '$.is_flaky')       AS is_flaky
       FROM documents
       WHERE type_id = 'playwright_tests'
         AND is_published = 1
         AND deleted_at IS NULL
         AND json_extract(data, '$.run_id') = ?`
    ).bind(externalRunId).all()

    type TestRow = { test_id: string; project_name: string; retry: number; status: string; is_flaky: number | boolean }
    const rows = (testsR?.results ?? []) as TestRow[]

    // Keep only the final attempt per (test_id, project_name)
    const finalByKey = new Map<string, TestRow>()
    for (const r of rows) {
      const key = `${r.test_id}::${r.project_name ?? ''}`
      const ex = finalByKey.get(key)
      if (!ex || r.retry > ex.retry) finalByKey.set(key, r)
    }

    let passed = 0, failed = 0, skipped = 0, flaky = 0
    for (const r of finalByKey.values()) {
      if (r.status === 'passed') passed++
      else if (r.status === 'failed' || r.status === 'timedOut' || r.status === 'interrupted') failed++
      else if (r.status === 'skipped') skipped++
      if (r.is_flaky === 1 || r.is_flaky === true) flaky++
    }
    const total = finalByKey.size

    // Fetch the existing run document to merge updated fields
    const runRow = await db.prepare(
      `SELECT id, data FROM documents
       WHERE type_id = 'playwright_runs'
         AND is_published = 1
         AND deleted_at IS NULL
         AND json_extract(data, '$.run_id') = ?
       ORDER BY created_at DESC LIMIT 1`
    ).bind(externalRunId).first<{ id: string; data: string }>()

    if (!runRow) {
      return c.json({ error: `Run not found: ${externalRunId}` }, 404)
    }

    const existingData = JSON.parse((runRow.data ?? '{}') as string)
    const updatedData = {
      ...existingData,
      run_status: body.run_status ?? (failed > 0 ? 'failed' : 'complete'),
      total, passed, failed, skipped, flaky,
      duration_ms: body.duration_ms,
      finished_at: body.finished_at,
    }
    const runTitle = `${updatedData.project} — ${updatedData.branch} — ${passed}/${total} passed`
    const now = Math.floor(Date.now() / 1000)

    await db.prepare(
      `UPDATE documents SET title = ?, data = ?, updated_at = ? WHERE id = ?`
    ).bind(runTitle, JSON.stringify(updatedData), now, runRow.id).run()

    return c.json({ success: true, summary: { total, passed, failed, skipped, flaky } }, 200)
  } catch (err) {
    console.error('[playwright] /:run_id/complete failed:', err)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

// ── Original batch ingest (kept for shell script / manual use) ─────────────────

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
    const finalResults = new Map<string, TestInput>()
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
      source: body.run.source ?? (body.run.ci_provider === 'local' ? 'local' : 'ci'),
      run_status: 'complete',
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
    const stmts = buildTestInserts(db, body.run.run_id, body.tests)

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
