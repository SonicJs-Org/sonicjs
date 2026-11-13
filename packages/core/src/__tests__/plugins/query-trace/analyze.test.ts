import { describe, it, expect } from 'vitest'
import { RequestTrace, type TraceEntryInput } from '../../../utils/request-trace/trace-context'
import { analyze, groupByFingerprint, serverTimingValue, summarize } from '../../../plugins/core-plugins/query-trace-plugin/services/analyze'
import { DEFAULT_QUERY_TRACE_SETTINGS } from '../../../plugins/core-plugins/query-trace-plugin/constants'

const S = DEFAULT_QUERY_TRACE_SETTINGS
let t: RequestTrace
const q = (over: Partial<TraceEntryInput> & { id?: string } = {}): number => {
  const { id, ...rest } = over
  return t.record(
    {
      kind: 'd1', op: 'SELECT all', label: 'select * from t where id = ?', fingerprint: 'select * from t where id = ?',
      tables: ['t'], params: [], startMs: 0, durationMs: 5, cache: null, ...rest,
    },
    id
  )
}
const rules = (a = analyze(t, S, 1000)) => a.findings.map((f) => f.rule)

describe('analyze', () => {
  it('flags N+1 (≥3 same fingerprint)', () => {
    t = new RequestTrace('GET', '/')
    for (let i = 0; i < 3; i++) q({ startMs: i * 10 })
    const a = analyze(t, S, 1000)
    expect(a.findings.find((f) => f.rule === 'n-plus-one')?.message).toMatch(/ran 3×/)
    expect(a.groups[0]).toMatchObject({ count: 3, totalMs: 15, avgMs: 5, maxMs: 5 })
  })

  it('flags identical repeat only via identity key, not masked params', () => {
    t = new RequestTrace('GET', '/')
    q({ id: 'same', params: ['string(36)'] }); q({ id: 'same', params: ['string(36)'] })
    expect(rules()).toContain('identical-repeat')
    t = new RequestTrace('GET', '/')
    q({ id: 'a', params: ['string(36)'] }); q({ id: 'b', params: ['string(36)'] })
    expect(rules()).not.toContain('identical-repeat')
  })

  it('flags missing index suspect', () => {
    t = new RequestTrace('GET', '/')
    q({ rowsRead: 18400, rowsReturned: 20, tables: ['documents'] })
    expect(analyze(t, S, 1000).findings.find((f) => f.rule === 'missing-index')?.message).toMatch(/18,400 rows to return 20.*documents/)
    t = new RequestTrace('GET', '/')
    q({ rowsRead: 900, rowsReturned: 1 })
    expect(rules()).not.toContain('missing-index')
  })

  it('flags slow query and slow batch (batch parent, members not double-counted)', () => {
    t = new RequestTrace('GET', '/')
    q({ durationMs: 230 })
    expect(rules()).toContain('slow-query')
    t = new RequestTrace('POST', '/')
    const p = q({ op: 'batch', label: 'batch(2)', fingerprint: 'batch', durationMs: 230, d1DurationMs: 2 })
    q({ parentSeq: p, durationMs: 1, d1DurationMs: 1 }); q({ parentSeq: p, durationMs: 1, d1DurationMs: 1 })
    const a = analyze(t, S, 1000)
    expect(a.findings.find((f) => f.rule === 'slow-batch')?.message).toBe('Slow batch of 2 (230 ms).')
    expect(a.findings.some((f) => f.rule === 'slow-query')).toBe(false)
    // DB Σ counts batch wall time once; counts are statements only
    expect(a.summary).toMatchObject({ dbMs: 230, d1Count: 2 })
  })

  it('flags latency-bound (≥5 calls with wall ≫ d1)', () => {
    t = new RequestTrace('GET', '/')
    for (let i = 0; i < 5; i++) q({ startMs: i * 20, durationMs: 10, d1DurationMs: 1, fingerprint: `f${i}` })
    expect(rules()).toContain('latency-bound')
  })

  it('flags serial chain in the same span (hint)', () => {
    t = new RequestTrace('GET', '/')
    for (let i = 0; i < 3; i++) q({ startMs: i * 10, durationMs: 5, fingerprint: `f${i}` })
    const f = analyze(t, S, 1000).findings.find((x) => x.rule === 'serial-chain')
    expect(f?.severity).toBe('low')
    expect(f?.message).toMatch(/3 sequential queries in `handler`/)
  })

  it('flags cache miss → DB', () => {
    t = new RequestTrace('GET', '/')
    t.record({ kind: 'cache', op: 'get', label: 'content:list:<n>', fingerprint: 'get', tables: [], params: [], startMs: 0, durationMs: 1, cache: 'miss' })
    q({ startMs: 2 })
    expect(analyze(t, S, 1000).findings.find((f) => f.rule === 'cache-miss-db')?.message).toMatch(/Cache miss on `content:list:<n>` → 1 query/)
  })

  it('cache-miss-db: attributes queries per miss, stops at next cache op or span change', () => {
    t = new RequestTrace('GET', '/')
    const cache = (cacheOutcome: 'miss' | 'hit', label: string) =>
      t.record({ kind: 'cache', op: 'get', label, fingerprint: 'get', tables: [], params: [], startMs: 0, durationMs: 1, cache: cacheOutcome })
    cache('miss', 'k1'); q({ durationMs: 4 }); q({ durationMs: 6, fingerprint: 'x' })
    cache('miss', 'k2') // no queries before next cache op
    cache('hit', 'k3'); q({ fingerprint: 'y' }) // after a hit: not attributed
    cache('miss', 'k4'); t.spanStack.push('other'); q({ fingerprint: 'z' }) // span changed: not attributed
    const found = analyze(t, S, 1000).findings.filter((f) => f.rule === 'cache-miss-db')
    expect(found).toHaveLength(1)
    expect(found[0]!.message).toMatch(/`k1` → 2 queries/)
    expect(found[0]!.impactMs).toBe(10)
  })

  it('cache-miss-db analysis is linear (5000 misses)', () => {
    t = new RequestTrace('GET', '/', 5000)
    for (let i = 0; i < 2500; i++) {
      t.record({ kind: 'cache', op: 'get', label: `k${i}`, fingerprint: 'get', tables: [], params: [], startMs: i, durationMs: 1, cache: 'miss' })
      q({ startMs: i, fingerprint: `f${i}` })
    }
    const t0 = performance.now()
    analyze(t, S, 1000)
    expect(performance.now() - t0).toBeLessThan(500)
  })

  it('missing-index heuristic applies to reads only', () => {
    t = new RequestTrace('POST', '/')
    q({ op: 'UPDATE run', rowsRead: 18400, rowsWritten: 1, tables: ['documents'] })
    expect(rules()).not.toContain('missing-index')
  })

  it('cold-bootstrap uses bootstrap self time, not inclusive duration', () => {
    t = new RequestTrace('GET', '/')
    t.spans.push({ name: 'bootstrap', startMs: 0, durationMs: 900, selfMs: 20 }) // warm: slow downstream, cheap bootstrap
    const a = analyze(t, S, 1000)
    expect(a.findings.map((f) => f.rule)).not.toContain('cold-bootstrap')
    expect(a.summary.coldBootstrap).toBe(false)
    t = new RequestTrace('GET', '/')
    t.spans.push({ name: 'bootstrap', startMs: 0, durationMs: 900, selfMs: 600 })
    const b = analyze(t, S, 1000)
    expect(b.findings.find((f) => f.rule === 'cold-bootstrap')).toMatchObject({ impactMs: 600 })
    expect(b.summary.coldBootstrap).toBe(true)
  })

  it('flags write on GET only for GET', () => {
    t = new RequestTrace('GET', '/')
    q({ op: 'UPDATE run', rowsWritten: 3, tables: ['users'] })
    expect(rules()).toContain('write-on-get')
    t = new RequestTrace('POST', '/')
    q({ op: 'UPDATE run', rowsWritten: 3 })
    expect(rules()).not.toContain('write-on-get')
  })

  it('flags middleware-heavy and cold bootstrap', () => {
    t = new RequestTrace('GET', '/')
    t.spans.push({ name: 'bootstrap', startMs: 0, durationMs: 840, selfMs: 600 }, { name: 'requireRbac', startMs: 0, durationMs: 120, selfMs: 120 })
    const a = analyze(t, S, 1000)
    expect(a.findings.map((f) => f.rule)).toEqual(expect.arrayContaining(['middleware-heavy', 'cold-bootstrap']))
    expect(a.summary.coldBootstrap).toBe(true)
    expect(a.spans[0]!.name).toBe('bootstrap') // sorted by self desc
  })

  it('orders findings by severity then impact', () => {
    t = new RequestTrace('GET', '/')
    q({ durationMs: 300, fingerprint: 'a' })
    q({ durationMs: 150, fingerprint: 'b' })
    for (let i = 0; i < 3; i++) q({ startMs: 1000 + i * 10, durationMs: 1, fingerprint: 'c' })
    const f = analyze(t, S, 1000).findings
    const sev = f.map((x) => x.severity)
    expect(sev).toEqual([...sev].sort((a, b) => ['high', 'medium', 'low'].indexOf(a) - ['high', 'medium', 'low'].indexOf(b)))
    expect(f[0]!.impactMs).toBeGreaterThanOrEqual(f.filter((x) => x.severity === 'high')[1]!.impactMs)
  })

  it('summarizes and formats Server-Timing', () => {
    t = new RequestTrace('GET', '/')
    q({ durationMs: 10 }); q({ durationMs: 20, fingerprint: 'other' })
    t.record({ kind: 'cache', op: 'get', label: 'x', fingerprint: 'g', tables: [], params: [], startMs: 0, durationMs: 1, cache: 'hit:memory' })
    t.record({ kind: 'cache', op: 'get', label: 'y', fingerprint: 'g', tables: [], params: [], startMs: 0, durationMs: 1, cache: 'miss' })
    t.record({ kind: 'kv', op: 'get', label: 'z', fingerprint: 'g', tables: [], params: [], startMs: 0, durationMs: 1, cache: 'hit' })
    const s = summarize(t, 412)
    expect(s).toMatchObject({ totalMs: 412, badge: 'amber', d1Count: 2, d1Unique: 2, dupes: 0, dbMs: 30, cacheHit: 1, cacheMiss: 1, kvCount: 1, slowestMs: 20 })
    expect(summarize(t, 100).badge).toBe('green')
    expect(summarize(t, 600).badge).toBe('red')
    expect(serverTimingValue(analyze(t, S, 412))).toBe('total;dur=412, db;dur=30;desc="2 q", cache;desc="1 hit/1 miss", mw;dur=0')
    expect(groupByFingerprint(t.entries).map((g) => g.totalMs)).toEqual([20, 10])
  })
})
