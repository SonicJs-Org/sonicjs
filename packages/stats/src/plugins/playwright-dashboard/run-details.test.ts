// Parity tests for the run-details helpers: the page used to compute "final attempt per test",
// the status counts, the filter tabs and the ordering in SQL. These tests run that ORIGINAL SQL in
// real SQLite against an edge-case fixture and require the in-memory helpers to match it exactly,
// so SQLite semantics (NULL logic, TEXT-vs-INTEGER comparison, CAST, BINARY collation) can't drift.
import Database from 'better-sqlite3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { applyFilter, countByStatus, finalAttempts, sortTests, type TestAttemptRow } from './run-details'

const COLS = ['test_id', 'test_title', 'test_file', 'project_name', 'status', 'is_flaky', 'retry'] as const

// Each entry is the JSON stored in documents.data for one attempt of run R1.
const FIXTURE: Record<string, unknown>[] = [
  // Plain retry chain: only retry 2 survives.
  { test_id: 't1', project_name: 'chromium', test_file: 'a.spec.ts', test_title: 'chain', status: 'failed', is_flaky: false, retry: 0 },
  { test_id: 't1', project_name: 'chromium', test_file: 'a.spec.ts', test_title: 'chain', status: 'failed', is_flaky: false, retry: 1 },
  { test_id: 't1', project_name: 'chromium', test_file: 'a.spec.ts', test_title: 'chain', status: 'passed', is_flaky: true, retry: 2 },
  // Same test, different project → independent.
  { test_id: 't1', project_name: 'firefox', test_file: 'a.spec.ts', test_title: 'chain', status: 'passed', is_flaky: false, retry: 0 },
  // Retry tie: both kept.
  { test_id: 't2', project_name: 'chromium', test_file: 'b.spec.ts', test_title: 'tie', status: 'timedOut', is_flaky: false, retry: 1 },
  { test_id: 't2', project_name: 'chromium', test_file: 'b.spec.ts', test_title: 'tie', status: 'interrupted', is_flaky: false, retry: 1 },
  // Retry stored as text — CAST(... AS INTEGER) semantics.
  { test_id: 't3', project_name: 'chromium', test_file: 'c.spec.ts', test_title: 'text retry', status: 'failed', is_flaky: false, retry: '1' },
  { test_id: 't3', project_name: 'chromium', test_file: 'c.spec.ts', test_title: 'text retry', status: 'passed', is_flaky: false, retry: ' 2abc' },
  { test_id: 't3', project_name: 'chromium', test_file: 'c.spec.ts', test_title: 'text retry', status: 'skipped', is_flaky: false, retry: 1.9 },
  // NULL retry: never superseded, never supersedes.
  { test_id: 't4', project_name: 'chromium', test_file: 'd.spec.ts', test_title: 'null retry', status: 'passed', is_flaky: false, retry: null },
  { test_id: 't4', project_name: 'chromium', test_file: 'd.spec.ts', test_title: 'null retry', status: 'failed', is_flaky: false, retry: 3 },
  // NULL keys: always kept.
  { test_id: null, project_name: 'chromium', test_file: 'e.spec.ts', test_title: 'no id', status: 'passed', is_flaky: false, retry: 0 },
  { test_id: null, project_name: 'chromium', test_file: 'e.spec.ts', test_title: 'no id', status: 'passed', is_flaky: false, retry: 5 },
  { test_id: 't5', test_file: 'e.spec.ts', test_title: 'no project', status: 'skipped', is_flaky: false, retry: 0 },
  // test_id type matters: integer 6 and text "6" are different keys in SQLite.
  { test_id: 6, project_name: 'chromium', test_file: 'f.spec.ts', test_title: 'int id', status: 'passed', is_flaky: false, retry: 0 },
  { test_id: '6', project_name: 'chromium', test_file: 'f.spec.ts', test_title: 'text id', status: 'failed', is_flaky: false, retry: 1 },
  // is_flaky variants: text "1"/"true"/"false" are TEXT (never = 1), missing → NULL, number 1 → flaky.
  { test_id: 'f1', project_name: 'chromium', test_file: 'g.spec.ts', test_title: 'flaky text 1', status: 'passed', is_flaky: '1', retry: 0 },
  { test_id: 'f2', project_name: 'chromium', test_file: 'g.spec.ts', test_title: 'flaky text true', status: 'passed', is_flaky: 'true', retry: 0 },
  { test_id: 'f3', project_name: 'chromium', test_file: 'g.spec.ts', test_title: 'flaky text false', status: 'passed', is_flaky: 'false', retry: 0 },
  { test_id: 'f4', project_name: 'chromium', test_file: 'g.spec.ts', test_title: 'flaky missing', status: 'passed', retry: 0 },
  { test_id: 'f5', project_name: 'chromium', test_file: 'g.spec.ts', test_title: 'flaky number', status: 'passed', is_flaky: 1, retry: 0 },
  { test_id: 'f6', project_name: 'chromium', test_file: 'g.spec.ts', test_title: 'flaky zero', status: 'passed', is_flaky: 0, retry: 0 },
  // Ordering: UTF-8 byte order differs from JS UTF-16 order for emoji vs. fullwidth letters;
  // NULL file sorts first; numeric title sorts before text.
  { test_id: 'u1', project_name: 'chromium', test_file: 'h.spec.ts', test_title: '😀 emoji', status: 'passed', is_flaky: false, retry: 0 },
  { test_id: 'u2', project_name: 'chromium', test_file: 'h.spec.ts', test_title: 'Ａ fullwidth', status: 'passed', is_flaky: false, retry: 0 },
  { test_id: 'u3', project_name: 'chromium', test_file: 'h.spec.ts', test_title: 'a lower', status: 'passed', is_flaky: false, retry: 0 },
  { test_id: 'u4', project_name: 'chromium', test_file: 'h.spec.ts', test_title: 'B upper', status: 'passed', is_flaky: false, retry: 0 },
  { test_id: 'u5', project_name: 'chromium', test_file: 'h.spec.ts', test_title: 42, status: 'passed', is_flaky: false, retry: 0 },
  { test_id: 'u6', project_name: 'chromium', test_title: 'no file', status: 'failed', is_flaky: false, retry: 0 },
]

// ── The original SQL from routes/admin.ts (before the in-memory rewrite) ──────────────────────
const NOT_EXISTS = `NOT EXISTS (
  SELECT 1 FROM documents t2
  WHERE t2.type_id = 'playwright_tests' AND t2.is_published = 1 AND t2.deleted_at IS NULL
    AND json_extract(t2.data, '$.run_id') = json_extract(t1.data, '$.run_id')
    AND json_extract(t2.data, '$.test_id') = json_extract(t1.data, '$.test_id')
    AND json_extract(t2.data, '$.project_name') = json_extract(t1.data, '$.project_name')
    AND CAST(json_extract(t2.data, '$.retry') AS INTEGER) > CAST(json_extract(t1.data, '$.retry') AS INTEGER))`
const BASE = `FROM documents t1
  WHERE t1.type_id = 'playwright_tests' AND t1.is_published = 1 AND t1.deleted_at IS NULL
    AND json_extract(t1.data, '$.run_id') = ?`
const STATUS_CLAUSE: Record<string, string> = {
  all: '',
  passed: `AND json_extract(data, '$.status') = 'passed' AND json_extract(data, '$.is_flaky') != 1`,
  failed: `AND json_extract(data, '$.status') IN ('failed', 'timedOut', 'interrupted')`,
  flaky: `AND json_extract(data, '$.is_flaky') = 1`,
  skipped: `AND json_extract(data, '$.status') = 'skipped'`,
}

let db: Database.Database
const select = COLS.map(c => `json_extract(t1.data, '$.${c}') AS ${c}`).join(', ')
const oldList = (filter: string) => db.prepare(
  `SELECT ${select} ${BASE} ${STATUS_CLAUSE[filter]} AND ${NOT_EXISTS}
   ORDER BY json_extract(t1.data, '$.test_file'), json_extract(t1.data, '$.test_title')`,
).all('R1') as TestAttemptRow[]
const oldCounts = () => db.prepare(
  `SELECT
     SUM(CASE WHEN json_extract(t1.data, '$.status') = 'passed' AND json_extract(t1.data, '$.is_flaky') != 1 THEN 1 ELSE 0 END) AS passed_count,
     SUM(CASE WHEN json_extract(t1.data, '$.status') IN ('failed', 'timedOut', 'interrupted') THEN 1 ELSE 0 END) AS failed_count,
     SUM(CASE WHEN json_extract(t1.data, '$.is_flaky') = 1 THEN 1 ELSE 0 END) AS flaky_count,
     SUM(CASE WHEN json_extract(t1.data, '$.status') = 'skipped' THEN 1 ELSE 0 END) AS skipped_count
   ${BASE} AND ${NOT_EXISTS}`,
).get('R1')
// What the new route fetches: every attempt for the run, unordered.
const attempts = () => db.prepare(`SELECT ${select} ${BASE}`).all('R1') as TestAttemptRow[]

const key = (r: TestAttemptRow) => JSON.stringify(COLS.map(c => r[c] ?? null))

beforeAll(() => {
  db = new Database(':memory:')
  db.exec(`CREATE TABLE documents (type_id TEXT, is_published INT, deleted_at INT, data TEXT)`)
  const ins = db.prepare(`INSERT INTO documents VALUES ('playwright_tests', 1, NULL, ?)`)
  // Shuffle-ish insertion order so nothing relies on rowid order.
  for (const d of [...FIXTURE].reverse()) ins.run(JSON.stringify({ run_id: 'R1', ...d }))
  ins.run(JSON.stringify({ run_id: 'R2', test_id: 't1', project_name: 'chromium', status: 'passed', retry: 9 })) // other run
})
afterAll(() => db.close())

describe('run-details helpers match the original SQL', () => {
  it('final attempts: same rows (retry chains, ties, text/NULL retry, NULL keys, typed ids)', () => {
    const got = finalAttempts(attempts()).map(key).sort()
    const want = oldList('all').map(key).sort()
    expect(got).toEqual(want)
    expect(got.length).toBeGreaterThan(0)
  })

  it('status counts match', () => {
    expect(countByStatus(finalAttempts(attempts()))).toEqual(oldCounts())
  })

  for (const filter of Object.keys(STATUS_CLAUSE)) {
    it(`filter=${filter}: same rows in the same order`, () => {
      const want = oldList(filter)
      const got = sortTests(applyFilter(finalAttempts(attempts()), filter))
      expect(got.map(key).sort()).toEqual(want.map(key).sort())
      // ORDER BY only constrains (test_file, test_title); compare those columns position by position.
      const ord = (rows: TestAttemptRow[]) => rows.map(r => JSON.stringify([r.test_file ?? null, r.test_title ?? null]))
      expect(ord(got)).toEqual(ord(want))
    })
  }
})

describe('run-details helper edge cases', () => {
  it('treats is_flaky like SQLite: TEXT "1" is not flaky (TEXT != 1), NULL is neither passed nor flaky', () => {
    const rows: TestAttemptRow[] = [
      { test_id: 'a', project_name: 'p', status: 'passed', is_flaky: '1', retry: 0 },
      { test_id: 'b', project_name: 'p', status: 'passed', is_flaky: null, retry: 0 },
      { test_id: 'c', project_name: 'p', status: 'passed', is_flaky: 1, retry: 0 },
    ]
    expect(countByStatus(rows)).toEqual({ passed_count: 1, failed_count: 0, flaky_count: 1, skipped_count: 0 })
  })

  it('orders text by UTF-8 bytes, not UTF-16 code units', () => {
    const rows = sortTests<TestAttemptRow>([{ test_title: '😀' }, { test_title: 'Ａ' }])
    // U+FF21 (EF BC A1) < U+1F600 (F0 9F 98 80) in UTF-8, though '😀' < 'Ａ' in UTF-16.
    expect(rows.map(r => r.test_title)).toEqual(['Ａ', '😀'])
  })
})
