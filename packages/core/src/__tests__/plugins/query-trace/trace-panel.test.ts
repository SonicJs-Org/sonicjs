import { describe, it, expect } from 'vitest'
import { RequestTrace, type TraceEntryInput } from '../../../utils/request-trace/trace-context'
import { analyze } from '../../../plugins/core-plugins/query-trace-plugin/services/analyze'
import { renderTracePanel } from '../../../plugins/core-plugins/query-trace-plugin/components/trace-panel'
import { DEFAULT_QUERY_TRACE_SETTINGS } from '../../../plugins/core-plugins/query-trace-plugin/constants'

const S = DEFAULT_QUERY_TRACE_SETTINGS
const base: TraceEntryInput = { kind: 'd1', op: 'SELECT all', label: 'select 1', fingerprint: 'select 1', tables: [], params: [], startMs: 0, durationMs: 1, cache: null }
const render = (t: RequestTrace, s = S) => renderTracePanel(t, analyze(t, s, 100), s)

describe('renderTracePanel', () => {
  it('escapes SQL/labels', () => {
    const t = new RequestTrace('GET', '/admin')
    t.record({ ...base, label: 'select \'<script>alert(1)</script>\'', fingerprint: 'x' })
    const html = render(t)
    expect(html).not.toContain('<script>alert(1)')
    expect(html).toContain('&lt;script&gt;alert(1)')
  })

  it('escapes < in embedded JSON', () => {
    const t = new RequestTrace('GET', '/admin')
    t.record({ ...base, label: '</script><b>', fingerprint: 'x' })
    const html = render(t)
    const data = html.split('id="sjs-trace-data">')[1]!.split('</script>')[0]!
    expect(data).not.toContain('<')
    expect(data).toContain('\\u003c')
  })

  it('sorts rows by duration desc', () => {
    const t = new RequestTrace('GET', '/admin')
    t.record({ ...base, label: 'fast_q', fingerprint: 'a', durationMs: 1 })
    t.record({ ...base, label: 'slow_q', fingerprint: 'b', durationMs: 50 })
    const html = render(t)
    expect(html.indexOf('slow_q')).toBeLessThan(html.indexOf('fast_q'))
  })

  it('renders testids and empty state', () => {
    const html = render(new RequestTrace('GET', '/admin'))
    for (const id of ['trace-summary', 'trace-queries', 'trace-opportunities', 'trace-spans', 'trace-copy-json']) expect(html).toContain(`data-testid="${id}"`)
    expect(html).toContain('No queries or cache operations recorded')
    expect(html).toContain('No opportunities found')
  })

  it('shows dropped count', () => {
    const t = new RequestTrace('GET', '/admin', 1)
    t.record(base); t.record(base); t.record(base)
    expect(render(t)).toContain('2 entries dropped')
  })

  it('Hide for me only in opt-in mode', () => {
    const t = new RequestTrace('GET', '/admin')
    expect(render(t)).toContain('Hide for me')
    expect(render(t, { ...S, visibility: 'all-admins' })).not.toContain('Hide for me')
  })
})
