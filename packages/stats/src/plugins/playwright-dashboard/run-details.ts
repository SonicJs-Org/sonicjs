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

/**
 * SQLite comparison of a json_extract() value against the integer 1, per SQLite's type rules
 * (INTEGER/REAL compare numerically; TEXT and BLOB are never equal to a number, and a TEXT value
 * always sorts greater than one; NULL compares as NULL → false). JSON true/false arrive as 1/0.
 * A JS boolean is treated as the 1/0 json_extract would have produced.
 */
function sqlEqualsOne(v: unknown): boolean | null {
  if (v === null || v === undefined) return null
  if (typeof v === 'boolean') return v
  if (typeof v === 'number') return v === 1
  return false // TEXT (e.g. "1", "true") is never = 1 in SQLite
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
// `status = 'passed' AND is_flaky != 1` — NULL is_flaky makes the whole predicate NULL (excluded).
const isPassed = (r: TestAttemptRow) => {
  const eq = sqlEqualsOne(r.is_flaky)
  return r.status === 'passed' && eq === false
}
const isFailed = (r: TestAttemptRow) => typeof r.status === 'string' && FAILED_STATUSES.has(r.status)
const isFlaky = (r: TestAttemptRow) => sqlEqualsOne(r.is_flaky) === true
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

const utf8 = new TextEncoder()

/**
 * ORDER BY test_file, test_title — SQLite BINARY collation: NULLs first, then numbers, then text
 * compared as UTF-8 bytes (memcmp). JS string `<` compares UTF-16 code units, which orders some
 * astral-plane vs. high-BMP characters (e.g. emoji vs. fullwidth letters) differently.
 */
function cmp(a: unknown, b: unknown): number {
  const rank = (v: unknown) => (v === null || v === undefined ? 0 : typeof v === 'number' ? 1 : 2)
  const ra = rank(a), rb = rank(b)
  if (ra !== rb) return ra - rb
  if (ra === 0) return 0
  if (ra === 1) return (a as number) - (b as number)
  const ab = utf8.encode(String(a)), bb = utf8.encode(String(b))
  const n = Math.min(ab.length, bb.length)
  for (let i = 0; i < n; i++) {
    const d = ab[i]! - bb[i]!
    if (d !== 0) return d
  }
  return ab.length - bb.length
}

export function sortTests<T extends TestAttemptRow>(rows: T[]): T[] {
  return [...rows].sort((a, b) => cmp(a.test_file, b.test_file) || cmp(a.test_title, b.test_title))
}
