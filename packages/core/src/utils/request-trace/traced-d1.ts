/**
 * Passthrough D1 proxy that records every query on the active request trace.
 *
 * Proxies never hold a trace: they look it up through AsyncLocalStorage on each call, so a
 * singleton that captured `env.DB` on request 1 still records into request N's trace. With no
 * active trace a call is one ALS lookup and nothing else.
 */
import { getCurrentTrace, type RequestTrace } from './trace-context'
import { extractTables, fingerprintSql, identityKey, maskParams, redactErrorMessage, redactSql, sqlOp } from './sql-fingerprint'

/** Hidden symbol exposing the underlying (unwrapped) binding / statement. */
export const RAW = Symbol.for('sonicjs.request-trace.raw')

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any

const SKIP_FRAME = /request-trace|query-trace-plugin|node_modules|node:internal/

export function captureCaller(): string | undefined {
  const stack = new Error().stack
  if (!stack) return undefined
  for (const line of stack.split('\n').slice(1)) {
    if (SKIP_FRAME.test(line)) continue
    const m = /at (?:(.+?) \()?(.*?):(\d+):\d+\)?$/.exec(line.trim())
    if (!m) continue
    const file = m[2]!.split(/[\\/]/).slice(-2).join('/')
    return `${m[1] ?? '<anon>'} ${file}:${m[3]}`
  }
  return undefined
}

interface Meta {
  duration?: number
  rows_read?: number
  rows_written?: number
  changes?: number
  served_by_region?: string
  served_by_primary?: boolean
}

function servedBy(meta: Meta | undefined): string | undefined {
  if (!meta?.served_by_region) return undefined
  return `${meta.served_by_region}${meta.served_by_primary ? ' (primary)' : ''}`
}

function baseEntry(trace: RequestTrace, sql: string, args: readonly unknown[], op: string) {
  const fingerprint = fingerprintSql(sql)
  return {
    entry: {
      kind: 'd1' as const,
      op,
      label: redactSql(sql),
      fingerprint,
      tables: extractTables(sql),
      params: maskParams(args),
      cache: null,
      caller: trace.captureCallers ? captureCaller() : undefined,
    },
    identity: identityKey(fingerprint, args, trace.salt, sql),
  }
}

async function traceStatement<T>(
  stmt: TracedStatement,
  method: 'all' | 'first' | 'run' | 'raw',
  exec: () => Promise<T>,
  describe: (res: T) => { meta?: Meta; returned?: number }
): Promise<T> {
  const trace = getCurrentTrace()
  if (!trace) return exec()
  const startMs = trace.now()
  const { entry, identity } = baseEntry(trace, stmt.sql, stmt.args, `${sqlOp(stmt.sql)} ${method}`)
  try {
    const res = await exec()
    const { meta, returned } = describe(res)
    trace.record(
      {
        ...entry,
        startMs,
        durationMs: trace.now() - startMs,
        d1DurationMs: meta?.duration,
        rowsReturned: returned,
        rowsRead: meta?.rows_read,
        rowsWritten: meta?.rows_written ?? meta?.changes,
        servedBy: servedBy(meta),
      },
      identity
    )
    return res
  } catch (err) {
    trace.record(
      { ...entry, startMs, durationMs: trace.now() - startMs, error: redactErrorMessage(err) },
      identity
    )
    throw err
  }
}

class TracedStatement {
  constructor(
    private readonly stmt: Any,
    readonly sql: string,
    readonly args: readonly unknown[]
  ) {}

  get [RAW](): Any {
    return this.stmt
  }

  bind(...args: unknown[]): TracedStatement {
    return new TracedStatement(this.stmt.bind(...args), this.sql, args)
  }

  all(): Promise<Any> {
    return traceStatement(this, 'all', () => this.stmt.all(), (r: Any) => ({ meta: r?.meta, returned: r?.results?.length }))
  }

  first(colName?: string): Promise<Any> {
    return traceStatement(
      this,
      'first',
      () => (colName === undefined ? this.stmt.first() : this.stmt.first(colName)),
      (r: Any) => ({ returned: r == null ? 0 : 1 })
    )
  }

  run(): Promise<Any> {
    return traceStatement(this, 'run', () => this.stmt.run(), (r: Any) => ({ meta: r?.meta, returned: undefined }))
  }

  raw(options?: { columnNames?: boolean }): Promise<Any> {
    return traceStatement(
      this,
      'raw',
      () => (options === undefined ? this.stmt.raw() : this.stmt.raw(options)),
      (r: Any) => ({ returned: Array.isArray(r) ? Math.max(0, r.length - (options?.columnNames ? 1 : 0)) : undefined })
    )
  }
}

const proxies = new WeakMap<object, Any>()

function unwrapStatement(s: Any): Any {
  return s && s[RAW] ? s[RAW] : s
}

function makeProxy(rawDb: Any): Any {
  const wrapBatch = async (statements: Any[]) => {
    const trace = getCurrentTrace()
    const raws = statements.map(unwrapStatement)
    if (!trace) return rawDb.batch(raws)
    const startMs = trace.now()
    const caller = trace.captureCallers ? captureCaller() : undefined
    const parentBase = {
      kind: 'd1' as const,
      op: 'batch',
      label: `batch(${statements.length})`,
      fingerprint: 'batch',
      tables: [] as string[],
      params: [] as string[],
      cache: null,
      caller,
    }
    try {
      const results: Any[] = await rawDb.batch(raws)
      const durationMs = trace.now() - startMs
      const metas: Array<Meta | undefined> = results.map((r) => r?.meta)
      const d1Sum = metas.reduce((a, m) => a + (m?.duration ?? 0), 0)
      const parentSeq = trace.record({ ...parentBase, startMs, durationMs, d1DurationMs: d1Sum })
      statements.forEach((st: Any, i: number) => {
        if (!parentSeq) {
          trace.dropped++
          return
        }
        const sql: string = st?.sql ?? ''
        const args: readonly unknown[] = st?.args ?? []
        const { entry, identity } = baseEntry(trace, sql, args, `${sqlOp(sql)} batch`)
        const meta = metas[i]
        const res = results[i]
        trace.record(
          {
            ...entry,
            caller: undefined,
            parentSeq,
            startMs,
            durationMs: meta?.duration ?? 0,
            d1DurationMs: meta?.duration ?? 0,
            rowsReturned: res?.results?.length ? res.results.length : undefined,
            rowsRead: meta?.rows_read,
            rowsWritten: meta?.rows_written ?? meta?.changes,
            servedBy: servedBy(meta),
          },
          identity
        )
      })
      return results
    } catch (err) {
      trace.record({
        ...parentBase,
        startMs,
        durationMs: trace.now() - startMs,
        error: redactErrorMessage(err),
      })
      throw err
    }
  }

  const wrapExec = async (query: string) => {
    const trace = getCurrentTrace()
    if (!trace) return rawDb.exec(query)
    const startMs = trace.now()
    const { entry, identity } = baseEntry(trace, query, [], 'OTHER exec')
    try {
      const res: Any = await rawDb.exec(query)
      trace.record({ ...entry, startMs, durationMs: trace.now() - startMs, d1DurationMs: res?.duration }, identity)
      return res
    } catch (err) {
      trace.record(
        { ...entry, startMs, durationMs: trace.now() - startMs, error: redactErrorMessage(err) },
        identity
      )
      throw err
    }
  }

  return new Proxy(rawDb, {
    get(target, prop) {
      if (prop === RAW) return target
      switch (prop) {
        case 'prepare':
          return (sql: string) => new TracedStatement(target.prepare(sql), sql, [])
        case 'batch':
          return wrapBatch
        case 'exec':
          return wrapExec
        case 'withSession':
          return (...a: unknown[]) => getTracedD1(target.withSession(...a))
      }
      const v = Reflect.get(target, prop, target)
      return typeof v === 'function' ? v.bind(target) : v
    },
  })
}

/** Returns the (cached) tracing proxy for a D1 binding. Falsy bindings pass through. Idempotent. */
export function getTracedD1<T>(rawDb: T): T {
  if (!rawDb || typeof rawDb !== 'object') return rawDb
  if ((rawDb as Any)[RAW]) return rawDb
  let p = proxies.get(rawDb as object)
  if (!p) {
    p = makeProxy(rawDb)
    proxies.set(rawDb as object, p)
    proxies.set(p, p)
  }
  return p
}
