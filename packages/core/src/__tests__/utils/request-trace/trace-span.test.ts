import { describe, it, expect, beforeAll } from 'vitest'
import { Hono } from 'hono'
import { RequestTrace, getCurrentTrace, loadAsyncLocalStorage, runWithTrace } from '../../../utils/request-trace/trace-context'
import { traceSpan } from '../../../utils/request-trace/trace-span'

const rec = (label: string) =>
  getCurrentTrace()?.record({ kind: 'd1', op: 'SELECT', label, fingerprint: label, tables: [], params: [], startMs: 0, durationMs: 0, cache: null })
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

describe('traceSpan', () => {
  beforeAll(async () => { await loadAsyncLocalStorage() })

  it('is a passthrough with no active trace', async () => {
    const app = new Hono()
    app.use('*', traceSpan('mw', async (_c, next) => { await next() }))
    app.get('/', (c) => c.text('ok'))
    const res = await app.request('/')
    expect(await res.text()).toBe('ok')
  })

  it('attributes entries to middleware vs downstream and computes selfMs', async () => {
    const app = new Hono()
    app.use('*', traceSpan('mw', async (_c, next) => {
      rec('in-mw-before')
      await sleep(10)
      await next()
      rec('in-mw-after')
    }))
    app.get('/', async (c) => { rec('in-handler'); await sleep(30); return c.text('ok') })
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, () => app.request('/'))
    const bySpan = Object.fromEntries(trace.entries.map((e) => [e.label, e.span]))
    expect(bySpan).toEqual({ 'in-mw-before': 'mw', 'in-handler': 'handler', 'in-mw-after': 'mw' })
    expect(trace.spans).toHaveLength(1)
    const s = trace.spans[0]
    expect(s.durationMs).toBeGreaterThanOrEqual(35)
    expect(s.selfMs).toBeLessThan(s.durationMs - 20)
    expect(trace.spanStack).toEqual([])
  })
})
