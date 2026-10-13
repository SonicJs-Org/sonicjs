import { describe, it, expect, vi, afterEach } from 'vitest'
import type { KVNamespace } from '@cloudflare/workers-types'
import { createSecondaryStorage } from '../../auth/secondary-storage'

/** Map-backed KV that records the options passed to `put`. */
function fakeKv() {
  const data = new Map<string, string>()
  const puts: { key: string; options?: { expirationTtl?: number } }[] = []
  const kv = {
    get: async (k: string) => data.get(k) ?? null,
    put: async (k: string, v: string, options?: { expirationTtl?: number }) => {
      puts.push({ key: k, options })
      data.set(k, v)
    },
    delete: async (k: string) => void data.delete(k),
  } as unknown as KVNamespace
  return { kv, data, puts }
}

afterEach(() => vi.restoreAllMocks())

describe('createSecondaryStorage', () => {
  it('returns undefined without a KV binding, so Better Auth keeps sessions in D1', () => {
    expect(createSecondaryStorage(undefined)).toBeUndefined()
  })

  it('round-trips get/set/delete', async () => {
    const { kv } = fakeKv()
    const s = createSecondaryStorage(kv)!
    await s.set('k', 'v')
    expect(await s.get('k')).toBe('v')
    await s.delete('k')
    expect(await s.get('k')).toBeNull()
  })

  it('clamps a sub-60s TTL to KV’s minimum instead of failing', async () => {
    const { kv, puts } = fakeKv()
    const s = createSecondaryStorage(kv)!
    await s.set('short', 'v', 10)
    await s.set('long', 'v', 600)
    await s.set('forever', 'v')
    expect(puts.map((p) => p.options?.expirationTtl)).toEqual([60, 600, undefined])
  })

  it('getAndDelete returns the value once and warns that KV cannot do it atomically', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const { kv } = fakeKv()
    const s = createSecondaryStorage(kv)!
    await s.set('t', 'once')
    expect(await s.getAndDelete!('t')).toBe('once')
    expect(await s.getAndDelete!('t')).toBeNull()
    expect(warn).toHaveBeenCalledTimes(1)
    expect(String(warn.mock.calls[0]![0])).toMatch(/storeInDatabase/)
  })

  it('increment throws with an actionable message rather than counting non-atomically', async () => {
    const { kv } = fakeKv()
    const s = createSecondaryStorage(kv)!
    await expect(s.increment!('rl', 60)).rejects.toThrow(/rateLimit\.storage/)
  })
})
