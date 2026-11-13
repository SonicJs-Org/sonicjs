import { getTracedD1 } from './traced-d1'
import { getTracedKV } from './traced-kv'

/**
 * Returns env with DB / CACHE_KV replaced by passthrough tracing proxies. Idempotent
 * (proxies are recognised and returned as-is) and never mutates the input env.
 * Applied by the query-trace middleware on every request AND by app.boot() so that
 * singletons seeded on cron-first isolates hold proxies, not raw bindings.
 */
export function wrapTraceBindings<E extends object>(env: E): E {
  if (!env) return env
  const e = env as Record<string, unknown>
  const db = getTracedD1(e.DB)
  const kv = getTracedKV(e.CACHE_KV)
  if (db === e.DB && kv === e.CACHE_KV) return env
  return { ...env, DB: db, CACHE_KV: kv }
}
