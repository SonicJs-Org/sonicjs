/**
 * Passthrough KV proxy: records get/getWithMetadata/put/delete/list on the active trace.
 * Keys are redacted (`redactKey`) before they reach the trace. No trace → straight call.
 */
import { getCurrentTrace } from './trace-context'
import { redactKey } from './sql-fingerprint'
import { RAW, captureCaller } from './traced-d1'

/* eslint-disable @typescript-eslint/no-explicit-any */
type Any = any

const proxies = new WeakMap<object, Any>()

function keyOf(arg: unknown): string {
  if (typeof arg === 'string') return arg
  if (Array.isArray(arg)) return arg.map((k) => redactKey(typeof k === 'string' ? k : '')).join(', ')
  if (arg && typeof arg === 'object' && typeof (arg as Any).prefix === 'string') return (arg as Any).prefix
  return ''
}

async function traceKv(
  op: 'get' | 'getWithMetadata' | 'put' | 'delete' | 'list',
  arg: unknown,
  exec: () => Promise<Any>,
  outcome?: (res: Any) => 'hit' | 'miss' | null
): Promise<Any> {
  const trace = getCurrentTrace()
  if (!trace) return exec()
  const startMs = trace.now()
  const bulk = Array.isArray(arg)
  // bulk labels are already per-key redacted + comma-joined; redactKey would mangle the separators
  const label = bulk ? `[${keyOf(arg)}]` : redactKey(keyOf(arg))
  const base = {
    kind: 'kv' as const,
    op: bulk && (op === 'get' || op === 'getWithMetadata') ? (`${op} (bulk)` as Any) : op,
    label,
    fingerprint: `${op}${bulk ? ' (bulk)' : ''} ${label}`,
    tables: [] as string[],
    params: [] as string[],
    caller: trace.captureCallers ? captureCaller() : undefined,
  }
  try {
    const res = await exec()
    trace.record({ ...base, startMs, durationMs: trace.now() - startMs, cache: outcome ? outcome(res) : null })
    return res
  } catch (err) {
    trace.record({
      ...base,
      startMs,
      durationMs: trace.now() - startMs,
      cache: null,
      error: err instanceof Error ? err.message : String(err),
    })
    throw err
  }
}

const hitMiss = (res: Any): 'hit' | 'miss' => (res === null || res === undefined ? 'miss' : 'hit')

/** Bulk read returns Map<key, value|{value,metadata}|null>. Hit only if every requested key has a non-null value. */
const bulkHitMiss = (keys: unknown[], res: Any, meta: boolean): 'hit' | 'miss' | null => {
  if (keys.length === 0) return null // nothing requested, nothing missed
  if (!(res instanceof Map)) return 'miss'
  for (const k of keys) {
    const v = res.get(k)
    if ((meta ? v?.value : v) === null || (meta ? v?.value : v) === undefined) return 'miss'
  }
  return 'hit'
}

function makeProxy(rawKv: Any): Any {
  return new Proxy(rawKv, {
    get(target, prop) {
      if (prop === RAW) return target
      switch (prop) {
        case 'get':
          return (key: string | string[], ...rest: unknown[]) => {
            // snapshot at dispatch: caller may mutate the array before the promise resolves
            const snap = Array.isArray(key) ? [...key] : key
            return traceKv('get', snap, () => target.get(key, ...rest), Array.isArray(snap) ? (r) => bulkHitMiss(snap, r, false) : hitMiss)
          }
        case 'getWithMetadata':
          return (key: string | string[], ...rest: unknown[]) => {
            const snap = Array.isArray(key) ? [...key] : key
            return traceKv(
              'getWithMetadata',
              snap,
              () => target.getWithMetadata(key, ...rest),
              Array.isArray(snap) ? (r) => bulkHitMiss(snap, r, true) : (r) => hitMiss(r?.value)
            )
          }
        case 'put':
          return (key: string, ...rest: unknown[]) => traceKv('put', key, () => target.put(key, ...rest))
        case 'delete':
          return (key: string) => traceKv('delete', key, () => target.delete(key))
        case 'list':
          return (opts?: unknown) => traceKv('list', opts, () => target.list(opts))
      }
      const v = Reflect.get(target, prop, target)
      return typeof v === 'function' ? v.bind(target) : v
    },
  })
}

/** Returns the (cached) tracing proxy for a KV binding. Falsy bindings pass through. Idempotent. */
export function getTracedKV<T>(rawKv: T): T {
  if (!rawKv || typeof rawKv !== 'object') return rawKv
  if ((rawKv as Any)[RAW]) return rawKv
  let p = proxies.get(rawKv as object)
  if (!p) {
    p = makeProxy(rawKv)
    proxies.set(rawKv as object, p)
  }
  return p
}
