// @ts-nocheck
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest'
import { drizzle } from 'drizzle-orm/d1'
import { sql as dsql } from 'drizzle-orm'
import { createTestD1 } from '../d1-sqlite'
import { RequestTrace, loadAsyncLocalStorage, runWithTrace } from '../../../utils/request-trace/trace-context'
import { getTracedD1, RAW } from '../../../utils/request-trace/traced-d1'

/** Minimal mock D1 returning realistic `meta`, and recording what batch() received. */
function mockD1() {
  const seen = { batch: [] as any[] }
  const stmt = (sql: string, args: any[] = []) => ({
    __sql: sql,
    __args: args,
    bind: (...a: any[]) => stmt(sql, a),
    all: async () => ({ results: [{ a: 1 }, { a: 2 }], success: true, meta: { duration: 3, rows_read: 5000, rows_written: 0, served_by_region: 'ENAM', served_by_primary: true } }),
    first: async () => ({ a: 1 }),
    run: async () => ({ success: true, meta: { duration: 2, changes: 1, rows_written: 1 } }),
    raw: async () => [[1], [2]],
  })
  const db = {
    prepare: (sql: string) => stmt(sql),
    batch: async (stmts: any[]) => {
      seen.batch = stmts
      await new Promise((r) => setTimeout(r, 15))
      return stmts.map((_s, i) => ({ results: [], success: true, meta: { duration: 1 + i * 0.1, changes: 1, rows_written: 1 } }))
    },
    exec: async () => ({ count: 1, duration: 1 }),
  }
  return { db, seen }
}

describe('getTracedD1', () => {
  beforeAll(async () => { await loadAsyncLocalStorage() })

  it('is idempotent and exposes RAW', () => {
    const { db } = mockD1()
    const p = getTracedD1(db)
    expect(getTracedD1(db)).toBe(p)
    expect(getTracedD1(p)).toBe(p)
    expect(p[RAW]).toBe(db)
    expect(getTracedD1(undefined)).toBeUndefined()
  })

  it('records query metadata and returns unchanged results', async () => {
    const { db } = mockD1()
    const p = getTracedD1(db)
    const trace = new RequestTrace('GET', '/admin/x')
    const res = await runWithTrace(trace, () => p.prepare("SELECT * FROM users WHERE email = 'x@y.com' AND id = ?").bind('abc').all())
    expect(res.results).toHaveLength(2)
    const e = trace.entries[0]
    expect(e).toMatchObject({
      kind: 'd1', op: 'SELECT all', tables: ['users'], params: ['string(3)'],
      rowsReturned: 2, rowsRead: 5000, rowsWritten: 0, d1DurationMs: 3, servedBy: 'ENAM (primary)', cache: null,
    })
    expect(e.label).toBe('SELECT * FROM users WHERE email = ? AND id = ?')
    expect(JSON.stringify(trace.toJSON())).not.toContain('x@y.com')
    expect(JSON.stringify(trace.toJSON())).not.toContain('abc')
    expect(trace.getIdentityKey(1)).toBeTruthy()
  })

  it('records first/run/raw and keeps first(col) semantics', async () => {
    const { db } = mockD1()
    const p = getTracedD1(db)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      expect(await p.prepare('select a from t').first()).toEqual({ a: 1 })
      await p.prepare('update t set a = 1').run()
      expect(await p.prepare('select a from t').raw()).toEqual([[1], [2]])
    })
    expect(trace.entries.map((e) => e.op)).toEqual(['SELECT first', 'UPDATE run', 'SELECT raw'])
    expect(trace.entries[0].rowsReturned).toBe(1)
    expect(trace.entries[1].rowsReturned).toBeUndefined() // run(): changes are rows written, not returned
    expect(trace.entries[1].rowsWritten).toBe(1)
  })

  it('records nothing and returns identical results with no trace', async () => {
    const { db } = mockD1()
    const p = getTracedD1(db)
    expect((await p.prepare('select a from t').all()).results).toHaveLength(2)
    expect(await p.prepare('select a from t').first()).toEqual({ a: 1 })
  })

  it('records errors and rethrows', async () => {
    const { db } = mockD1()
    db.prepare = () => ({ bind() { return this }, all: async () => { throw new Error('boom') } })
    const p = getTracedD1(db)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await expect(p.prepare('select 1').all()).rejects.toThrow('boom')
    })
    expect(trace.entries[0].error).toBe('boom')
  })

  it('redacts literals echoed in recorded errors but rethrows the original', async () => {
    const { db } = mockD1()
    db.prepare = () => ({ bind() { return this }, all: async () => { throw new Error("syntax error near 'alice@x.com' in SELECT 'tok123'") } })
    const p = getTracedD1(db)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await expect(p.prepare('select 1').all()).rejects.toThrow('alice@x.com')
    })
    expect(trace.entries[0].error).not.toContain('alice')
    expect(trace.entries[0].error).not.toContain('tok123')
  })

  it('same fingerprint, different inline literals => different identity', async () => {
    const { db } = mockD1()
    const p = getTracedD1(db)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await p.prepare('select a from t where id = 1').all()
      await p.prepare('select a from t where id = 2').all()
      await p.prepare('select a from t where id = 1').all()
    })
    expect(trace.getIdentityKey(1)).not.toBe(trace.getIdentityKey(2))
    expect(trace.getIdentityKey(1)).toBe(trace.getIdentityKey(3))
  })

  it('batch unwraps statements and records 1 parent + N members with own durations', async () => {
    const { db, seen } = mockD1()
    const p = getTracedD1(db)
    const trace = new RequestTrace('POST', '/')
    await runWithTrace(trace, async () => {
      const stmts = Array.from({ length: 10 }, (_v, i) => p.prepare('INSERT INTO t (a) VALUES (?)').bind(i))
      await p.batch(stmts)
    })
    // workerd type-checks batch members: they must be the raw statements
    expect(seen.batch.every((s) => s.__sql && !s[RAW])).toBe(true)
    const [parent, ...members] = trace.entries
    expect(parent).toMatchObject({ op: 'batch', label: 'batch(10)' })
    expect(parent.costMs).toBeUndefined()
    expect(parent.durationMs).toBeGreaterThanOrEqual(14)
    expect(members).toHaveLength(10)
    expect(members.every((m) => m.parentSeq === parent.seq)).toBe(true)
    expect(members.every((m) => m.durationMs !== parent.durationMs && m.durationMs < 3)).toBe(true)
    expect(parent.d1DurationMs).toBeCloseTo(members.reduce((a, m) => a + m.d1DurationMs, 0))
    // batch writes without RETURNING: results [] => rows written (changes), nothing returned
    expect(members.every((m) => m.rowsReturned === undefined && m.rowsWritten === 1)).toBe(true)
    // DB Σ over top-level entries counts the batch wall time once
    const top = trace.entries.filter((e) => e.parentSeq === undefined)
    expect(top).toHaveLength(1)
  })
})

describe('getTracedD1 with real SQLite + drizzle', () => {
  let raw
  beforeAll(async () => { await loadAsyncLocalStorage() })
  beforeEach(() => { raw = createTestD1(); raw.raw.exec('CREATE TABLE widgets (id integer primary key, name text)') })
  afterEach(() => raw.close())

  it('drizzle insert + select record correct op/tables', async () => {
    const p = getTracedD1(raw)
    const db = drizzle(p)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await db.run(dsql`insert into widgets (name) values (${'secret-name'})`)
      const rows = await db.all(dsql`select * from widgets where name = ${'secret-name'}`)
      expect(rows).toHaveLength(1)
    })
    expect(trace.entries.map((e) => e.op.split(' ')[0])).toEqual(['INSERT', 'SELECT'])
    expect(trace.entries.every((e) => e.tables.join() === 'widgets')).toBe(true)
    expect(JSON.stringify(trace.toJSON())).not.toContain('secret-name')
  })

  it('batch with wrappers succeeds against real sqlite', async () => {
    const p = getTracedD1(raw)
    const trace = new RequestTrace('POST', '/')
    await runWithTrace(trace, async () => {
      await p.batch([p.prepare('insert into widgets (name) values (?)').bind('a'), p.prepare('insert into widgets (name) values (?)').bind('b')])
    })
    expect(raw.raw.prepare('select count(*) c from widgets').get().c).toBe(2)
    expect(trace.entries[0].op).toBe('batch')
  })
})
