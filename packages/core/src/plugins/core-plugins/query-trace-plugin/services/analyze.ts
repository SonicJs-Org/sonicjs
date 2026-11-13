/**
 * Pure analysis of a finished RequestTrace: summary numbers, fingerprint groups,
 * span table and "opportunities" (findings). No I/O, no rendering.
 *
 * Aggregation rules (plan §2.5):
 *  - DB Σ: durationMs over top-level D1 entries (standalone statements + batch parents).
 *  - Counts: statements only (batch members count, batch parents don't).
 *  - Groups / N+1 / identical / slow: costMs over statements.
 */
import type { RequestTrace, TraceEntry } from '../../../../utils/request-trace'
import type { QueryTraceSettings } from '../constants'

export type Severity = 'high' | 'medium' | 'low'
export type Badge = 'green' | 'amber' | 'red'

export interface Finding {
  rule: string
  severity: Severity
  impactMs: number
  message: string
}

export interface Summary {
  totalMs: number
  badge: Badge
  d1Count: number
  d1Unique: number
  dupes: number
  dbMs: number
  cacheHit: number
  cacheMiss: number
  kvCount: number
  slowestMs: number
  middlewareMs: number
  dropped: number
  coldBootstrap: boolean
}

export interface FingerprintGroup {
  fingerprint: string
  label: string
  count: number
  totalMs: number
  avgMs: number
  maxMs: number
  totalRowsRead: number
}

export interface SpanSummary {
  name: string
  startMs: number
  durationMs: number
  selfMs: number
  queries: number
  dbMs: number
}

export interface Analysis {
  summary: Summary
  findings: Finding[]
  groups: FingerprintGroup[]
  spans: SpanSummary[]
}

const COLD_BOOTSTRAP_MS = 200

const SEVERITY_ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 }

const r1 = (n: number) => Math.round(n * 10) / 10
const trunc = (s: string, n = 90) => (s.length > n ? s.slice(0, n - 1) + '…' : s)

const isD1 = (e: TraceEntry) => e.kind === 'd1'
const isBatchParent = (e: TraceEntry) => e.kind === 'd1' && e.op === 'batch'
const isStatement = (e: TraceEntry) => e.kind === 'd1' && e.op !== 'batch'
const isTopLevelD1 = (e: TraceEntry) => e.kind === 'd1' && e.parentSeq === undefined

export function groupByFingerprint(entries: TraceEntry[]): FingerprintGroup[] {
  const map = new Map<string, FingerprintGroup>()
  for (const e of entries.filter(isStatement)) {
    const cost = e.costMs ?? e.durationMs
    const g = map.get(e.fingerprint) ?? {
      fingerprint: e.fingerprint, label: e.label, count: 0, totalMs: 0, avgMs: 0, maxMs: 0, totalRowsRead: 0,
    }
    g.count++
    g.totalMs += cost
    g.maxMs = Math.max(g.maxMs, cost)
    g.totalRowsRead += e.rowsRead ?? 0
    map.set(e.fingerprint, g)
  }
  return [...map.values()]
    .map((g) => ({ ...g, totalMs: r1(g.totalMs), avgMs: r1(g.totalMs / g.count), maxMs: r1(g.maxMs) }))
    .sort((a, b) => b.totalMs - a.totalMs)
}

export function summarize(trace: RequestTrace, totalMs: number = trace.now()): Summary {
  const entries = trace.entries
  const statements = entries.filter(isStatement)
  const unique = new Set(statements.map((s) => s.fingerprint)).size
  const cacheOps = entries.filter((e) => e.kind === 'cache')
  const boot = trace.spans.find((s) => s.name === 'bootstrap')
  const nonHandlerSelf = trace.spans.reduce((a, s) => a + s.selfMs, 0)
  return {
    totalMs: r1(totalMs),
    badge: totalMs < 150 ? 'green' : totalMs < 500 ? 'amber' : 'red',
    d1Count: statements.length,
    d1Unique: unique,
    dupes: statements.length - unique,
    dbMs: r1(entries.filter(isTopLevelD1).reduce((a, e) => a + e.durationMs, 0)),
    cacheHit: cacheOps.filter((e) => e.cache?.startsWith('hit')).length,
    cacheMiss: cacheOps.filter((e) => e.cache === 'miss').length,
    kvCount: entries.filter((e) => e.kind === 'kv').length,
    slowestMs: r1(statements.reduce((m, e) => Math.max(m, e.costMs ?? e.durationMs), 0)),
    middlewareMs: r1(nonHandlerSelf),
    dropped: trace.dropped,
    // selfMs, not durationMs: bootstrap's duration includes everything downstream via next().
    coldBootstrap: !!boot && boot.selfMs > COLD_BOOTSTRAP_MS,
  }
}

export function findOpportunities(trace: RequestTrace, settings: QueryTraceSettings, totalMs: number = trace.now()): Finding[] {
  const entries = trace.entries
  const statements = entries.filter(isStatement)
  const out: Finding[] = []
  const add = (f: Finding) => out.push({ ...f, impactMs: r1(f.impactMs) })

  // N+1 / repeated fingerprint
  for (const g of groupByFingerprint(entries)) {
    if (g.count >= 3) {
      add({
        rule: 'n-plus-one',
        severity: g.totalMs >= settings.slowQueryMs ? 'high' : 'medium',
        impactMs: g.totalMs,
        message: `\`${trunc(g.label)}\` ran ${g.count}× (${g.totalMs} ms). Batch with \`IN (…)\` or memoize per request.`,
      })
    }
  }

  // Identical repeat (same fingerprint + same raw bound values; compared via private identity key)
  const byIdentity = new Map<string, TraceEntry[]>()
  for (const s of statements) {
    const k = trace.getIdentityKey(s.seq)
    if (!k) continue
    const list = byIdentity.get(k) ?? []
    list.push(s)
    byIdentity.set(k, list)
  }
  for (const list of byIdentity.values()) {
    if (list.length >= 2) {
      const wasted = list.slice(1).reduce((a, e) => a + (e.costMs ?? e.durationMs), 0)
      add({
        rule: 'identical-repeat',
        severity: 'medium',
        impactMs: wasted,
        message: `Identical query repeated ${list.length}×: \`${trunc(list[0]!.label)}\`. Cache it in request context.`,
      })
    }
  }

  // Missing index suspect (reads only: for writes rowsRead includes index maintenance and nothing is "returned")
  for (const s of statements) {
    if (!s.op.startsWith('SELECT')) continue
    const read = s.rowsRead ?? 0
    if (read >= 1000 && read / Math.max(s.rowsReturned ?? 0, 1) >= 20) {
      add({
        rule: 'missing-index',
        severity: 'high',
        impactMs: s.costMs ?? s.durationMs,
        message: `Read ${read.toLocaleString('en-US')} rows to return ${s.rowsReturned ?? 0}. Check the index on \`${s.tables.join(', ') || 'table'}\`.`,
      })
    }
  }

  // Slow query / slow batch
  for (const e of entries.filter(isD1)) {
    if (isBatchParent(e)) {
      if (e.durationMs >= settings.slowQueryMs) {
        const n = entries.filter((m) => m.parentSeq === e.seq).length
        add({ rule: 'slow-batch', severity: 'high', impactMs: e.durationMs, message: `Slow batch of ${n} (${r1(e.durationMs)} ms).` })
      }
    } else if ((e.costMs ?? e.durationMs) >= settings.slowQueryMs) {
      add({
        rule: 'slow-query',
        severity: 'high',
        impactMs: e.costMs ?? e.durationMs,
        message: `Slow query (${r1(e.costMs ?? e.durationMs)} ms): \`${trunc(e.label)}\`.`,
      })
    }
  }

  // Latency-bound: network/RPC overhead dominates DB time (top-level entries with server timing)
  const timed = entries.filter((e) => isTopLevelD1(e) && e.d1DurationMs !== undefined && e.durationMs > 0)
  const latencyBound = timed.filter((e) => (e.durationMs - (e.d1DurationMs ?? 0)) / e.durationMs > 0.8)
  if (latencyBound.length >= 5) {
    const wall = latencyBound.reduce((a, e) => a + e.durationMs, 0)
    const sql = latencyBound.reduce((a, e) => a + (e.d1DurationMs ?? 0), 0)
    add({
      rule: 'latency-bound',
      severity: 'medium',
      impactMs: wall - sql,
      message: `Network overhead is ${Math.round(((wall - sql) / wall) * 100)}% of DB time across ${latencyBound.length} calls. Batch with \`db.batch()\` or cache.`,
    })
  }

  // Serial chain: ≥3 consecutive non-overlapping top-level D1 calls in the same span
  const top = entries.filter(isTopLevelD1)
  let chain: TraceEntry[] = []
  const flush = () => {
    if (chain.length >= 3) {
      const ms = chain.reduce((a, e) => a + e.durationMs, 0)
      add({
        rule: 'serial-chain',
        severity: 'low',
        impactMs: ms,
        message: `${chain.length} sequential queries in \`${chain[0]!.span}\` (${r1(ms)} ms). \`Promise.all\`/\`batch\` if independent.`,
      })
    }
    chain = []
  }
  for (const e of top) {
    const prev = chain[chain.length - 1]
    if (prev && prev.span === e.span && e.startMs >= prev.startMs + prev.durationMs - 0.05) chain.push(e)
    else {
      flush()
      chain = [e]
    }
  }
  flush()

  // Cache miss → DB (same span, before the next cache op). Single linear pass.
  let miss: { entry: TraceEntry; n: number; ms: number } | null = null
  const flushMiss = () => {
    if (miss && miss.n > 0) {
      add({
        rule: 'cache-miss-db',
        severity: 'low',
        impactMs: miss.ms,
        message: `Cache miss on \`${trunc(miss.entry.label, 60)}\` → ${miss.n} ${miss.n === 1 ? 'query' : 'queries'}. Check TTL/warming.`,
      })
    }
    miss = null
  }
  for (const e of entries) {
    if (e.kind === 'cache') {
      flushMiss()
      if (e.cache === 'miss') miss = { entry: e, n: 0, ms: 0 }
    } else if (miss && e.span !== miss.entry.span) {
      flushMiss()
    } else if (miss && isTopLevelD1(e)) {
      miss.n++
      miss.ms += e.durationMs
    }
  }
  flushMiss()

  // Write on GET
  if (trace.method === 'GET') {
    const writers = statements.filter((s) => (s.rowsWritten ?? 0) > 0)
    if (writers.length) {
      const rows = writers.reduce((a, s) => a + (s.rowsWritten ?? 0), 0)
      const tables = [...new Set(writers.flatMap((s) => s.tables))].join(', ')
      add({ rule: 'write-on-get', severity: 'medium', impactMs: writers.reduce((a, s) => a + (s.costMs ?? s.durationMs), 0), message: `GET wrote ${rows} rows (\`${tables}\`).` })
    }
  }

  // Middleware-heavy (non-handler span self time > 50% of total)
  if (totalMs > 0) {
    const mw = trace.spans.filter((s) => s.name !== 'handler')
    const self = mw.reduce((a, s) => a + s.selfMs, 0)
    if (self / totalMs > 0.5) {
      const topSpan = [...mw].sort((a, b) => b.selfMs - a.selfMs)[0]!
      add({
        rule: 'middleware-heavy',
        severity: 'medium',
        impactMs: self,
        message: `Middleware is ${Math.round((self / totalMs) * 100)}% of server time; top: \`${topSpan.name}\` ${Math.round(topSpan.selfMs)} ms.`,
      })
    }
  }

  // Cold bootstrap
  const boot = trace.spans.find((s) => s.name === 'bootstrap')
  if (boot && boot.selfMs > COLD_BOOTSTRAP_MS) {
    add({
      rule: 'cold-bootstrap',
      severity: 'low',
      impactMs: boot.selfMs,
      message: `Cold-start bootstrap (${Math.round(boot.selfMs)} ms). Isolate warm-up, not page cost.`,
    })
  }

  return out.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.impactMs - a.impactMs)
}

export function summarizeSpans(trace: RequestTrace): SpanSummary[] {
  return trace.spans
    .map((s) => {
      const own = trace.entries.filter((e) => e.span === s.name)
      return {
        name: s.name,
        startMs: r1(s.startMs),
        durationMs: r1(s.durationMs),
        selfMs: r1(s.selfMs),
        queries: own.filter(isStatement).length,
        dbMs: r1(own.filter(isTopLevelD1).reduce((a, e) => a + e.durationMs, 0)),
      }
    })
    .sort((a, b) => b.selfMs - a.selfMs)
}

export function analyze(trace: RequestTrace, settings: QueryTraceSettings, totalMs: number = trace.now()): Analysis {
  return {
    summary: summarize(trace, totalMs),
    findings: findOpportunities(trace, settings, totalMs),
    groups: groupByFingerprint(trace.entries),
    spans: summarizeSpans(trace),
  }
}

/** `total;dur=412, db;dur=288;desc="37 q", cache;desc="4 hit/3 miss", mw;dur=130` */
export function serverTimingValue(a: Analysis): string {
  const s = a.summary
  return [
    `total;dur=${s.totalMs}`,
    `db;dur=${s.dbMs};desc="${s.d1Count} q"`,
    `cache;desc="${s.cacheHit} hit/${s.cacheMiss} miss"`,
    `mw;dur=${s.middlewareMs}`,
  ].join(', ')
}
