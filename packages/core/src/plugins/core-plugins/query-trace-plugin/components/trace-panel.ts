import { escapeHtml } from '../../../../utils/sanitize'
import type { RequestTrace, TraceEntry } from '../../../../utils/request-trace'
import type { QueryTraceSettings } from '../constants'
import type { Analysis } from '../services/analyze'

const BADGE: Record<string, string> = {
  green: 'bg-emerald-600 text-white',
  amber: 'bg-amber-500 text-zinc-900',
  red: 'bg-red-600 text-white',
}
const SEV: Record<string, string> = { high: 'text-red-400', medium: 'text-amber-400', low: 'text-zinc-400' }

const ms = (n: number | undefined) => (n === undefined ? '–' : String(Math.round(n * 10) / 10))
const e = (s: string | number | undefined) => escapeHtml(String(s ?? ''))

function msClass(v: number, s: QueryTraceSettings): string {
  return v >= s.slowQueryMs ? 'text-red-400' : v >= s.warnQueryMs ? 'text-amber-400' : 'text-zinc-300'
}

function entryRow(en: TraceEntry, total: number, dupes: number, child: boolean, s: QueryTraceSettings): string {
  const pct = total > 0 ? Math.min(100, (en.startMs / total) * 100) : 0
  const w = total > 0 ? Math.max(0.5, Math.min(100 - pct, (en.durationMs / total) * 100)) : 0.5
  const rows = en.kind === 'd1' ? `${en.rowsReturned ?? '–'}/${en.rowsRead ?? '–'}/${en.rowsWritten ?? '–'}` : ''
  const detail = [
    `<pre class="whitespace-pre-wrap break-all text-zinc-300">${e(en.label)}</pre>`,
    en.params.length ? `<div class="text-zinc-500">params: ${e(en.params.join(', '))}</div>` : '',
    en.caller ? `<div class="text-zinc-500">caller: ${e(en.caller)}</div>` : '',
    en.servedBy ? `<div class="text-zinc-500">served by: ${e(en.servedBy)}</div>` : '',
    en.error ? `<div class="text-red-400">error: ${e(en.error)}</div>` : '',
  ].join('')
  return `<tr class="border-t border-zinc-800 align-top" data-ms="${en.durationMs}">
<td class="px-2 py-1 text-right ${msClass(en.durationMs, s)}">${ms(en.durationMs)}</td>
<td class="px-2 py-1 text-right text-zinc-400">${ms(en.d1DurationMs)}</td>
<td class="px-2 py-1">${e(en.kind)}</td>
<td class="px-2 py-1">${e(en.op)}</td>
<td class="px-2 py-1 ${child ? 'pl-6' : ''}"><details><summary class="cursor-pointer truncate max-w-xl font-mono">${e(en.label.slice(0, 120))}</summary>${detail}</details></td>
<td class="px-2 py-1">${e(en.tables.join(', '))}</td>
<td class="px-2 py-1 text-right">${e(rows)}</td>
<td class="px-2 py-1">${e(en.cache ?? '')}</td>
<td class="px-2 py-1 text-right">${dupes > 1 ? `×${dupes}` : ''}</td>
<td class="px-2 py-1">${e(en.span)}</td>
<td class="px-2 py-1 w-48"><div class="relative h-2 bg-zinc-800 rounded"><div class="absolute h-2 bg-sky-500 rounded" style="left:${pct.toFixed(1)}%;width:${w.toFixed(1)}%"></div></div><span class="text-zinc-500">${ms(en.startMs)}</span></td>
</tr>`
}

const SORT_SCRIPT = `(function(){var p=document.getElementById('sjs-trace-panel');if(!p)return;p.querySelectorAll('[data-testid=trace-queries] th[data-col]').forEach(function(th){th.addEventListener('click',function(){var tb=th.closest('table').tBodies[0],i=th.cellIndex,d=th.dataset.dir==='asc'?-1:1;th.dataset.dir=d===1?'asc':'desc';Array.prototype.slice.call(tb.rows).sort(function(a,b){var x=a.cells[i].textContent,y=b.cells[i].textContent,nx=parseFloat(x),ny=parseFloat(y);return(isNaN(nx)||isNaN(ny)?x.localeCompare(y):nx-ny)*d*-1}).forEach(function(r){tb.appendChild(r)})})});var b=p.querySelector('[data-testid=trace-copy-json]');if(b)b.addEventListener('click',function(){navigator.clipboard.writeText(document.getElementById('sjs-trace-data').textContent)})})();`

export function renderTracePanel(trace: RequestTrace, analysis: Analysis, settings: QueryTraceSettings): string {
  const { summary: s } = analysis
  const entries = trace.entries
  const dupeCount = new Map<string, number>()
  for (const en of entries) if (en.kind === 'd1' && en.op !== 'batch') dupeCount.set(en.fingerprint, (dupeCount.get(en.fingerprint) ?? 0) + 1)

  // Top-level by duration desc; batch members follow their parent.
  const top = entries.filter((x) => x.parentSeq === undefined).sort((a, b) => b.durationMs - a.durationMs)
  const rowsHtml = top
    .flatMap((en) => [
      entryRow(en, s.totalMs, dupeCount.get(en.fingerprint) ?? 1, false, settings),
      ...entries.filter((m) => m.parentSeq === en.seq).map((m) => entryRow(m, s.totalMs, dupeCount.get(m.fingerprint) ?? 1, true, settings)),
    ])
    .join('')

  const opportunities = analysis.findings.length
    ? `<ul class="space-y-1">${analysis.findings
        .map((f) => `<li><span class="${SEV[f.severity]} font-semibold uppercase">${e(f.severity)}</span> <span class="text-zinc-500">${ms(f.impactMs)} ms</span> ${e(f.message)}</li>`)
        .join('')}</ul>`
    : '<p class="text-zinc-500">No opportunities found.</p>'

  const queries = entries.length
    ? `<table class="w-full text-xs"><thead class="text-zinc-400 text-left"><tr>${['ms', 'D1 ms', 'Type', 'Op', 'Query / key', 'Tables', 'Rows ret/read/wr', 'Cached', '×', 'Span', 'Start']
        .map((h, i) => `<th data-col="${i}" class="px-2 py-1 cursor-pointer select-none">${e(h)}</th>`)
        .join('')}</tr></thead><tbody>${rowsHtml}</tbody></table>`
    : '<p class="text-zinc-500">No queries or cache operations recorded.</p>'

  const groups = analysis.groups.length
    ? `<table class="w-full text-xs"><thead class="text-zinc-400 text-left"><tr><th class="px-2">Count</th><th class="px-2">Total ms</th><th class="px-2">Avg</th><th class="px-2">Max</th><th class="px-2">Rows read</th><th class="px-2">Fingerprint</th></tr></thead><tbody>${analysis.groups
        .map((g) => `<tr class="border-t border-zinc-800"><td class="px-2">${g.count}</td><td class="px-2">${g.totalMs}</td><td class="px-2">${g.avgMs}</td><td class="px-2">${g.maxMs}</td><td class="px-2">${g.totalRowsRead}</td><td class="px-2 font-mono truncate max-w-xl">${e(g.label.slice(0, 120))}</td></tr>`)
        .join('')}</tbody></table>`
    : ''

  const spans = analysis.spans.length
    ? `<table class="w-full text-xs"><thead class="text-zinc-400 text-left"><tr><th class="px-2">Span</th><th class="px-2">Start</th><th class="px-2">Total</th><th class="px-2">Self</th><th class="px-2">Queries</th><th class="px-2">DB ms</th></tr></thead><tbody>${analysis.spans
        .map((sp) => `<tr class="border-t border-zinc-800"><td class="px-2">${e(sp.name)}</td><td class="px-2">${sp.startMs}</td><td class="px-2">${sp.durationMs}</td><td class="px-2">${sp.selfMs}</td><td class="px-2">${sp.queries}</td><td class="px-2">${sp.dbMs}</td></tr>`)
        .join('')}</tbody></table>`
    : '<p class="text-zinc-500">No middleware spans.</p>'

  const json = JSON.stringify({ ...trace.toJSON(), totalMs: s.totalMs, analysis }).replace(/</g, '\\u003c')

  return `<details id="sjs-trace-panel" class="fixed bottom-0 inset-x-0 z-[99999] bg-zinc-950 text-zinc-200 text-xs border-t border-zinc-700 shadow-2xl max-h-[70vh] overflow-auto">
<summary data-testid="trace-summary" class="cursor-pointer px-3 py-2 flex flex-wrap gap-x-3 items-center">
<span class="px-2 py-0.5 rounded ${BADGE[s.badge]}">⚡ Trace · ${ms(s.totalMs)} ms server</span>
<span>${s.d1Count} D1 (${s.d1Unique} unique)</span><span>DB ${ms(s.dbMs)} ms Σ</span><span>${s.dupes} dupes</span>
<span>cache ${s.cacheHit} hit / ${s.cacheMiss} miss</span><span>KV ${s.kvCount}</span><span>slowest ${ms(s.slowestMs)} ms</span>
</summary>
<div class="p-3 space-y-4">
<section data-testid="trace-opportunities"><h3 class="font-semibold mb-1">Opportunities</h3>${opportunities}</section>
<section data-testid="trace-queries"><h3 class="font-semibold mb-1">Queries &amp; cache ops</h3>${queries}</section>
<section><h3 class="font-semibold mb-1">Grouped by fingerprint</h3>${groups}</section>
<section data-testid="trace-spans"><h3 class="font-semibold mb-1">Spans</h3>${spans}</section>
<footer class="flex flex-wrap gap-3 items-center text-zinc-400">
<button type="button" data-testid="trace-copy-json" class="px-2 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200">Copy JSON</button>
${settings.visibility === 'opt-in' ? '<a data-testid="trace-hide" href="?trace=0" class="underline">Hide for me</a>' : ''}
${s.coldBootstrap ? '<span>cold isolate: bootstrap ran its slow path</span>' : ''}
${s.dropped > 0 ? `<span data-testid="trace-dropped">${s.dropped} entries dropped (cap ${settings.maxEntries})</span>` : ''}
<a href="/admin/plugins/query-trace" class="underline">Trace settings</a>
</footer>
</div>
<script type="application/json" id="sjs-trace-data">${json}</script>
<script>${SORT_SCRIPT}</script>
</details>`
}
