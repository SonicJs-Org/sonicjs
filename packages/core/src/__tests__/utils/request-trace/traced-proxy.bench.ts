// @ts-nocheck
// Overhead budget (plan §6 risk 4): inactive-path ≤ 2 µs per D1/KV call, ≤ 20 µs per request env spread.
// Run: cd packages/core && npx vitest bench src/__tests__/utils/request-trace/traced-proxy.bench.ts
import { bench, describe } from 'vitest'
import { getTracedD1 } from '../../../utils/request-trace/traced-d1'
import { wrapTraceBindings } from '../../../utils/request-trace/wrap-bindings'

const stmt = (args = []) => ({ bind: (...a) => stmt(a), first: async () => ({ a: 1 }) })
const rawDb = { prepare: (_sql: string) => stmt() }
const proxied = getTracedD1(rawDb)
const env = { DB: rawDb, CACHE_KV: { get: async () => null }, A: 1, B: 2, C: 3 }

describe('prepare().bind().first() — no active trace', () => {
  bench('raw mock D1', async () => { await rawDb.prepare('select 1 from t where id = ?').bind(1).first() })
  bench('proxied mock D1', async () => { await proxied.prepare('select 1 from t where id = ?').bind(1).first() })
})

describe('per-request env wrap (already-proxied bindings)', () => {
  const wrapped = wrapTraceBindings(env)
  bench('wrapTraceBindings(first time per request: spread)', () => { wrapTraceBindings(env) })
  bench('wrapTraceBindings(already wrapped: identity)', () => { wrapTraceBindings(wrapped) })
})
