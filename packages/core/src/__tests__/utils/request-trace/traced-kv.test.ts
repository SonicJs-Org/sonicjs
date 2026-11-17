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

  it('traces bulk reads: per-key redaction, hit/miss from Map contents', async () => {
    const raw = {
      get: async (keys: string[]) => new Map(keys.map((k) => [k, k === 'session:missingTok' ? null : 'v'])),
      getWithMetadata: async (keys: string[]) =>
        new Map(keys.map((k) => [k, { value: k === 'session:missingTok' ? null : 'v', metadata: null }])),
    }
    const p = getTracedKV(raw)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await p.get(['content:list:42', 'config:x'])
      await p.get(['session:missingTok'])
      await p.getWithMetadata(['content:list:42', 'config:x'])
      await p.getWithMetadata(['content:list:42', 'session:missingTok'])
    })
    expect(trace.entries.map((e) => [e.op, e.cache])).toEqual([
      ['get (bulk)', 'hit'], ['get (bulk)', 'miss'], ['getWithMetadata (bulk)', 'hit'], ['getWithMetadata (bulk)', 'miss'],
    ])
    expect(trace.entries[0].label).toBe('[content:list:<n>, config:<redacted:1>]')
    expect(JSON.stringify(trace.toJSON())).not.toContain('missingTok')
  })

  it('empty bulk read leaves cache outcome unset', async () => {
    const p = getTracedKV({ get: async () => new Map(), getWithMetadata: async () => new Map() })
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => { await p.get([]); await p.getWithMetadata([]) })
    expect(trace.entries.map((e) => e.cache ?? null)).toEqual([null, null])
  })

  it('bulk tracing snapshots keys at dispatch', async () => {
    const raw = {
      get: async (keys: string[]) => { const ks = [...keys]; await Promise.resolve(); return new Map(ks.map((k) => [k, 'v'])) },
      getWithMetadata: async (keys: string[]) => { const ks = [...keys]; await Promise.resolve(); return new Map(ks.map((k) => [k, { value: 'v', metadata: null }])) },
    }
    const p = getTracedKV(raw)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      const k1 = ['config:a']; const r1 = p.get(k1); k1.push('config:b'); k1[0] = 'config:z'; await r1
      const k2 = ['config:a']; const r2 = p.getWithMetadata(k2); k2.push('config:b'); k2[0] = 'config:z'; await r2
    })
    expect(trace.entries.map((e) => e.label)).toEqual(['[config:<redacted:1>]', '[config:<redacted:1>]'])
    expect(trace.entries.map((e) => e.cache)).toEqual(['hit', 'hit'])
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
