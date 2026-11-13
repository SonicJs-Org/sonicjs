/**
 * Request-scoped trace store (plugin-agnostic).
 *
 * Everything here is a passthrough no-op when no trace is active, so core can
 * call `getCurrentTrace()?.record(...)` unconditionally. The query-trace plugin
 * is what actually starts a trace (see plugins/core-plugins/query-trace-plugin).
 */

export type CacheOutcome = 'hit' | 'miss' | 'hit:memory' | 'hit:kv' | null

export interface TraceEntry {
  seq: number
  kind: 'd1' | 'kv' | 'cache'
  op: string
  /** Redacted SQL / key. Raw text is never stored. */
  label: string
  fingerprint: string
  tables: string[]
  /** Masked bound-parameter descriptors (`string(36)`, `number`, …). Never values. */
  params: string[]
  startMs: number
  durationMs: number
  /** Per-statement cost used by aggregations. Undefined for batch parents. */
  costMs?: number
  /** Set on statements recorded from a `batch()` call; points at the parent entry's seq. */
  parentSeq?: number
  d1DurationMs?: number
  rowsReturned?: number
  rowsRead?: number
  rowsWritten?: number
  servedBy?: string
  cache: CacheOutcome
  span: string
  caller?: string
  error?: string
}

export interface SpanRecord {
  name: string
  startMs: number
  durationMs: number
  selfMs: number
}

export type TraceEntryInput = Omit<TraceEntry, 'seq' | 'span' | 'costMs'> & { costMs?: number }

export class RequestTrace {
  readonly t0 = performance.now()
  entries: TraceEntry[] = []
  spans: SpanRecord[] = []
  spanStack: string[] = []
  dropped = 0
  closed = false
  /** Per-request random salt for identity keys. Never rendered or exported. */
  readonly salt: string = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2)
  /** seq → salted hash of fingerprint + raw bound values. Private: excluded from toJSON(). */
  private readonly identityKeys = new Map<number, string>()

  constructor(
    readonly method: string,
    readonly path: string,
    readonly maxEntries = 1000,
    readonly captureCallers = true
  ) {}

  now(): number {
    return performance.now() - this.t0
  }

  currentSpan(): string {
    return this.spanStack[this.spanStack.length - 1] ?? 'handler'
  }

  /** Records an entry. Returns its seq, or 0 if dropped/closed. */
  record(e: TraceEntryInput, identityKey?: string): number {
    if (this.closed) return 0
    if (this.entries.length >= this.maxEntries) {
      this.dropped++
      return 0
    }
    const seq = this.entries.length + 1
    const isBatchParent = e.kind === 'd1' && e.op === 'batch'
    const entry: TraceEntry = {
      ...e,
      costMs: isBatchParent ? undefined : (e.costMs ?? e.durationMs),
      seq,
      span: this.currentSpan(),
    }
    this.entries.push(entry)
    if (identityKey) this.identityKeys.set(seq, identityKey)
    return seq
  }

  /** Private accessor for analysis (identical-repeat detection). Not serialised. */
  getIdentityKey(seq: number): string | undefined {
    return this.identityKeys.get(seq)
  }

  toJSON() {
    return {
      method: this.method,
      path: this.path,
      totalMs: this.now(),
      dropped: this.dropped,
      entries: this.entries,
      spans: this.spans,
    }
  }
}

type ALS<T> = { run<R>(s: T, fn: () => R): R; getStore(): T | undefined }
let alsPromise: Promise<ALS<RequestTrace> | null> | null = null
let als: ALS<RequestTrace> | null = null

/** Better-Auth pattern: dynamic import so builds without nodejs_compat still bundle. */
export function loadAsyncLocalStorage(): Promise<ALS<RequestTrace> | null> {
  alsPromise ??= import(/* @vite-ignore */ /* webpackIgnore: true */ 'node:async_hooks')
    .then((m: any) => m.AsyncLocalStorage)
    .catch(() => (globalThis as any).AsyncLocalStorage ?? null)
    .then((alsCtor: any) => {
      als = alsCtor ? new alsCtor() : null
      if (!als) console.warn('[query-trace] AsyncLocalStorage unavailable (enable nodejs_compat); tracing disabled')
      return als
    })
  return alsPromise
}

/** True once ALS has been loaded successfully. */
export function isTraceAvailable(): boolean {
  return als !== null
}

export const runWithTrace = <R>(t: RequestTrace, fn: () => R): R => (als ? als.run(t, fn) : fn())

export function getCurrentTrace(): RequestTrace | undefined {
  const t = als?.getStore()
  return t && !t.closed ? t : undefined
}
