// @ts-nocheck
import { describe, it, expect, beforeAll } from 'vitest'
import { RequestTrace, loadAsyncLocalStorage, runWithTrace } from '../../../utils/request-trace/trace-context'
import { getTracedKV } from '../../../utils/request-trace/traced-kv'
import { RAW } from '../../../utils/request-trace/traced-d1'

function mockKv() {
  const store = new Map<string, string>([['rbac:perms:3f2b1c9a-1111-4222-8333-444455556666', '["a"]']])
  return {
    get: async (k: string, _t?: any) => store.get(k) ?? null,
    getWithMetadata: async (k: string) => ({ value: store.get(k) ?? null, metadata: null }),
    put: async (k: string, v: string) => { store.set(k, v) },
    delete: async (k: string) => { store.delete(k) },
    list: async (_o?: any) => ({ keys: [...store.keys()].map((name) => ({ name })) }),
  }
}

describe('getTracedKV', () => {
  beforeAll(async () => { await loadAsyncLocalStorage() })

  it('is idempotent and exposes RAW', () => {
    const kv = mockKv()
    const p = getTracedKV(kv)
    expect(getTracedKV(kv)).toBe(p)
    expect(getTracedKV(p)).toBe(p)
    expect(p[RAW]).toBe(kv)
    expect(getTracedKV(undefined)).toBeUndefined()
  })

  it('records hit/miss with redacted keys and unchanged results', async () => {
    const p = getTracedKV(mockKv())
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      expect(await p.get('rbac:perms:3f2b1c9a-1111-4222-8333-444455556666', 'json')).toBe('["a"]')
      expect(await p.get('session:secretToken')).toBeNull()
      await p.put('content:list:42', 'x')
      await p.delete('content:list:42')
      await p.list({ prefix: 'rbac:perms:' })
      expect((await p.getWithMetadata('nope')).value).toBeNull()
    })
    expect(trace.entries.map((e) => [e.op, e.cache])).toEqual([
      ['get', 'hit'], ['get', 'miss'], ['put', null], ['delete', null], ['list', null], ['getWithMetadata', 'miss'],
    ])
    expect(trace.entries[0].label).toBe('rbac:perms:<uuid>')
    expect(trace.entries[1].label).toBe('session:<redacted:11>')
    expect(JSON.stringify(trace.toJSON())).not.toContain('secretToken')
    expect(trace.entries.every((e) => e.kind === 'kv')).toBe(true)
  })

  it('records nothing without a trace, and errors are recorded + rethrown', async () => {
    const kv = mockKv()
    const p = getTracedKV(kv)
    expect(await p.get('x')).toBeNull()
    kv.get = async () => { throw new Error('kv down') }
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await expect(p.get('x')).rejects.toThrow('kv down')
    })
    expect(trace.entries[0].error).toBe('kv down')
  })
})
