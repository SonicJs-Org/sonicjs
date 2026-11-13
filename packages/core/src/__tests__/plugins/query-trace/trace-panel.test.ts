import { describe, it, expect } from 'vitest'
import { RequestTrace, type TraceEntryInput } from '../../../utils/request-trace/trace-context'
import { analyze } from '../../../plugins/core-plugins/query-trace-plugin/services/analyze'
import { renderTracePanel, TRACE_SORT_SCRIPT } from '../../../plugins/core-plugins/query-trace-plugin/components/trace-panel'
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

/** Minimal fake DOM: just enough surface for TRACE_SORT_SCRIPT. */
function runSortScript(rows: Array<{ cells: string[]; parent?: string }>) {
  const tbody: any = { rows: [] as any[], appendChild(r: any) { this.rows = this.rows.filter((x: any) => x !== r); this.rows.push(r) } }
  tbody.rows = rows.map((r) => ({ cells: r.cells.map((t) => ({ textContent: t })), dataset: r.parent ? { parent: r.parent } : {}, label: r.cells[0] }))
  const table = { tBodies: [tbody] }
  const handlers: Array<() => void> = []
  const th: any = { cellIndex: 0, dataset: {}, attrs: {}, closest: () => table, setAttribute(k: string, v: string) { this.attrs[k] = v }, addEventListener: (_e: string, h: () => void) => handlers.push(h) }
  const panel = { querySelectorAll: () => [th], querySelector: () => null }
  new Function('document', TRACE_SORT_SCRIPT)({ getElementById: () => panel })
  return { click: (col = 0) => { th.cellIndex = col; handlers[0]!() }, order: () => tbody.rows.map((r: any) => r.label), th }
}

describe('sort script', () => {
  const rows = [
    { cells: ['5', '×2'] }, { cells: ['m1', ''], parent: '1' }, { cells: ['m2', ''], parent: '1' },
    { cells: ['20', '×10'] }, { cells: ['1', ''] },
  ]
  it('first click is ascending and actually ascending; second click descends', () => {
    const d = runSortScript([{ cells: ['5'] }, { cells: ['20'] }, { cells: ['1'] }])
    d.click()
    expect(d.th.dataset.dir).toBe('asc')
    expect(d.order()).toEqual(['1', '5', '20'])
    d.click()
    expect(d.th.dataset.dir).toBe('desc')
    expect(d.order()).toEqual(['20', '5', '1'])
  })
  it('keeps batch members attached to their parent, in original order', () => {
    const d = runSortScript(rows)
    d.click(0) // asc: 1, 5(+m1,m2), 20
    expect(d.order()).toEqual(['1', '5', 'm1', 'm2', '20'])
    d.click(0) // desc
    expect(d.order()).toEqual(['20', '5', 'm1', 'm2', '1'])
  })
  it('sorts ×N numerically (×10 after ×2), blanks last', () => {
    const d = runSortScript(rows)
    d.click(1)
    expect(d.order()).toEqual(['5', 'm1', 'm2', '20', '1'])
  })
  it('header cells are keyboard-focusable buttons', () => {
    const t = new RequestTrace('GET', '/admin')
    t.record(base)
    expect(render(t)).toMatch(/<th data-col="0"[^>]*><button type="button"/)
  })
  it('renders members after their parent via a single-pass index', () => {
    const t = new RequestTrace('POST', '/admin')
    const p = t.record({ ...base, op: 'batch', label: 'batch(2)', fingerprint: 'batch', durationMs: 9 })
    t.record({ ...base, label: 'member_a', fingerprint: 'ma', parentSeq: p, durationMs: 1 })
    t.record({ ...base, label: 'member_b', fingerprint: 'mb', parentSeq: p, durationMs: 2 })
    t.record({ ...base, label: 'other_q', fingerprint: 'o', durationMs: 3 })
    const html = render(t)
    expect(html).toContain(`data-parent="${p}"`)
    expect(html.indexOf('batch(2)')).toBeLessThan(html.indexOf('member_a'))
    expect(html.indexOf('member_b')).toBeLessThan(html.indexOf('other_q'))
  })
  it('renders 5000 entries quickly', () => {
    const t = new RequestTrace('GET', '/admin', 5000)
    const p = t.record({ ...base, op: 'batch', label: 'batch', fingerprint: 'batch' })
    for (let i = 1; i < 5000; i++) t.record({ ...base, label: `q${i}`, fingerprint: `f${i}`, parentSeq: i % 2 ? p : undefined })
    const t0 = performance.now()
    render(t)
    expect(performance.now() - t0).toBeLessThan(2000)
  })
})
