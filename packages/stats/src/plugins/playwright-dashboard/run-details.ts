// Pure helpers for the Playwright run-details page.
//
// The page used to pick "final attempt per test" and count statuses with a correlated
// `NOT EXISTS` over every playwright_tests document, matched on json_extract(...) keys. That
// is O(attempts_in_run × all_tests) and on stats.sonicjs.com (~70k test rows, ~730 per run)
// it hit D1's CPU limit ("exceeded its CPU time limit and was reset"). Now the route fetches
// the run's attempts once (index-backed by idx_pw_tests_run_id) and these helpers reproduce
// the old SQL semantics in memory.

export type TestAttemptRow = Record<string, unknown> & {
  test_id?: unknown
  test_title?: unknown
  test_file?: unknown
  project_name?: unknown
  status?: unknown
  is_flaky?: unknown
  retry?: unknown
}

export type RunFilter = 'all' | 'passed' | 'failed' | 'flaky' | 'skipped'

const FAILED_STATUSES = new Set(['failed', 'timedOut', 'interrupted'])

/** SQLite `CAST(x AS INTEGER)` for the values json_extract can return. NULL stays null. */
function castInt(v: unknown): number | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'number') return Math.trunc(v)
  if (typeof v === 'boolean') return v ? 1 : 0
  const m = /^\s*[+-]?\d+/.exec(String(v))
  return m ? parseInt(m[0], 10) : 0
}

/** JSON true/false come back from json_extract as 1/0. */
function sqlNum(v: unknown): number | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'boolean') return v ? 1 : 0
  const n = Number(v)
  return Number.isNaN(n) ? null : n
}

/**
 * Keep only the final attempt of each (test_id, project_name). Mirrors the old SQL exactly:
 * a row is dropped only when another row with the same non-NULL keys has a strictly greater
 * non-NULL retry. Rows with NULL keys or NULL retry are never dropped; equal retries are all kept.
 */
export function finalAttempts<T extends TestAttemptRow>(rows: T[]): T[] {
  const maxRetry = new Map<string, number>()
  const keyOf = (r: T) =>
    r.test_id === null || r.test_id === undefined || r.project_name === null || r.project_name === undefined
      ? null
      : JSON.stringify([r.test_id, r.project_name])
  for (const r of rows) {
    const k = keyOf(r)
    const retry = castInt(r.retry)
    if (k === null || retry === null) continue
    const cur = maxRetry.get(k)
    if (cur === undefined || retry > cur) maxRetry.set(k, retry)
  }
  return rows.filter(r => {
    const k = keyOf(r)
    const retry = castInt(r.retry)
    if (k === null || retry === null) return true
    return retry >= (maxRetry.get(k) as number)
  })
}

// Status predicates — SQL three-valued logic: NULL comparisons are false.
const isPassed = (r: TestAttemptRow) => {
  const f = sqlNum(r.is_flaky)
  return r.status === 'passed' && f !== null && f !== 1
}
const isFailed = (r: TestAttemptRow) => typeof r.status === 'string' && FAILED_STATUSES.has(r.status)
const isFlaky = (r: TestAttemptRow) => sqlNum(r.is_flaky) === 1
const isSkipped = (r: TestAttemptRow) => r.status === 'skipped'

export function countByStatus(finals: TestAttemptRow[]) {
  let passed = 0, failed = 0, flaky = 0, skipped = 0
  for (const r of finals) {
    if (isPassed(r)) passed++
    if (isFailed(r)) failed++
    if (isFlaky(r)) flaky++
    if (isSkipped(r)) skipped++
  }
  return { passed_count: passed, failed_count: failed, flaky_count: flaky, skipped_count: skipped }
}

export function applyFilter<T extends TestAttemptRow>(finals: T[], filter: string): T[] {
  switch (filter) {
    case 'passed': return finals.filter(isPassed)
    case 'failed': return finals.filter(isFailed)
    case 'flaky': return finals.filter(isFlaky)
    case 'skipped': return finals.filter(isSkipped)
    default: return finals
  }
}

/** ORDER BY test_file, test_title — SQLite BINARY collation, NULLs first. */
function cmp(a: unknown, b: unknown): number {
  const an = a === null || a === undefined, bn = b === null || b === undefined
  if (an || bn) return an === bn ? 0 : an ? -1 : 1
  const as = String(a), bs = String(b)
  return as < bs ? -1 : as > bs ? 1 : 0
}

export function sortTests<T extends TestAttemptRow>(rows: T[]): T[] {
  return [...rows].sort((a, b) => cmp(a.test_file, b.test_file) || cmp(a.test_title, b.test_title))
}
