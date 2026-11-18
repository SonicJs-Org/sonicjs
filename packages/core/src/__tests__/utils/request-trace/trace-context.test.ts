import { describe, it, expect, beforeAll } from 'vitest'
import {
  RequestTrace,
  getCurrentTrace,
  loadAsyncLocalStorage,
  runWithTrace,
  type TraceEntryInput,
} from '../../../utils/request-trace/trace-context'

const entry = (label = 'x'): TraceEntryInput => ({
  kind: 'd1', op: 'SELECT', label, fingerprint: label, tables: [], params: [],
  startMs: 0, durationMs: 1, cache: null,
})

describe('trace-context', () => {
  beforeAll(async () => { await loadAsyncLocalStorage() })

  it('getCurrentTrace is undefined outside a run', () => {
    expect(getCurrentTrace()).toBeUndefined()
  })

  it('isolates interleaved concurrent runs', async () => {
    const a = new RequestTrace('GET', '/a')
    const b = new RequestTrace('GET', '/b')
    const seen: string[] = []
    await Promise.all([
      runWithTrace(a, async () => {
        await new Promise((r) => setTimeout(r, 5))
        seen.push('a:' + getCurrentTrace()!.path)
      }),
      runWithTrace(b, async () => {
        seen.push('b:' + getCurrentTrace()!.path)
        await new Promise((r) => setTimeout(r, 10))
        seen.push('b2:' + getCurrentTrace()!.path)
      }),
    ])
    expect(seen.sort()).toEqual(['a:/a', 'b2:/b', 'b:/b'])
  })

  it('closed stops recording and hides the trace', () => {
    const t = new RequestTrace('GET', '/')
    t.record(entry())
    t.closed = true
    expect(t.record(entry())).toBe(0)
    expect(t.entries).toHaveLength(1)
    runWithTrace(t, () => expect(getCurrentTrace()).toBeUndefined())
  })

  it('maxEntries increments dropped', () => {
    const t = new RequestTrace('GET', '/', 2)
    t.record(entry('1')); t.record(entry('2')); t.record(entry('3'))
    expect(t.entries).toHaveLength(2)
    expect(t.dropped).toBe(1)
  })

  it('sets seq/span/costMs; batch parents have no costMs; identity keys stay private', () => {
    const t = new RequestTrace('GET', '/')
    const s1 = t.record(entry('a'), 'idkey')
    const s2 = t.record({ ...entry('batch(2)'), op: 'batch' })
    expect(s1).toBe(1)
    expect(t.entries[0]).toMatchObject({ seq: 1, span: 'handler', costMs: 1 })
    expect(t.entries[s2 - 1].costMs).toBeUndefined()
    expect(t.getIdentityKey(1)).toBe('idkey')
    expect(JSON.stringify(t.toJSON())).not.toContain('idkey')
  })
})
