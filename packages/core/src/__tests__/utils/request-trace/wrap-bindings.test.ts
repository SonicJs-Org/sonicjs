// @ts-nocheck
import { describe, it, expect } from 'vitest'
import { wrapTraceBindings } from '../../../utils/request-trace/wrap-bindings'
import { RAW } from '../../../utils/request-trace/traced-d1'

describe('wrapTraceBindings', () => {
  const db = { prepare: () => ({}), batch: async () => [] }
  const kv = { get: async () => null }

  it('wraps DB and CACHE_KV, preserves other bindings, does not mutate input', () => {
    const env = { DB: db, CACHE_KV: kv, OTHER: 1 }
    const w = wrapTraceBindings(env)
    expect(w).not.toBe(env)
    expect(env.DB).toBe(db)
    expect(w.DB[RAW]).toBe(db)
    expect(w.CACHE_KV[RAW]).toBe(kv)
    expect(w.OTHER).toBe(1)
  })

  it('is idempotent: wrapping twice returns the same proxies', () => {
    const w1 = wrapTraceBindings({ DB: db, CACHE_KV: kv })
    const w2 = wrapTraceBindings(w1)
    expect(w2).toBe(w1)
    expect(wrapTraceBindings({ DB: db, CACHE_KV: kv }).DB).toBe(w1.DB)
  })

  it('tolerates missing bindings', () => {
    expect(wrapTraceBindings({})).toEqual({})
    expect(wrapTraceBindings({ DB: db }).CACHE_KV).toBeUndefined()
  })
})
