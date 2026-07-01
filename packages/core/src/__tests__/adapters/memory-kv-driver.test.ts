import { describe, it, expect, beforeEach } from 'vitest'
import { createMemoryKVDriver } from '../../adapters/kv/memory-kv-driver'
import type { KVDriver } from '../../adapters/kv/memory-kv-driver'

let kv: KVDriver

beforeEach(() => {
  kv = createMemoryKVDriver()
})

describe('memory KV driver — get / put', () => {
  it('stores and retrieves a string value', async () => {
    await kv.put('key1', 'hello')
    const val = await kv.get('key1')
    expect(val).toBe('hello')
  })

  it('returns null for missing key', async () => {
    const val = await kv.get('no-such-key')
    expect(val).toBeNull()
  })

  it('get with json type parses the value', async () => {
    await kv.put('obj', JSON.stringify({ x: 42 }))
    const val = await kv.get<{ x: number }>('obj', 'json')
    expect(val?.x).toBe(42)
  })

  it('overwrites existing value', async () => {
    await kv.put('k', 'first')
    await kv.put('k', 'second')
    const val = await kv.get('k')
    expect(val).toBe('second')
  })
})

describe('memory KV driver — TTL / expiry', () => {
  it('returns null after expirationTtl elapses', async () => {
    await kv.put('ttl-key', 'expires', { expirationTtl: 0.001 }) // 1 ms
    await new Promise(r => setTimeout(r, 10))
    const val = await kv.get('ttl-key')
    expect(val).toBeNull()
  })

  it('returns value before expirationTtl elapses', async () => {
    await kv.put('live-key', 'alive', { expirationTtl: 3600 })
    const val = await kv.get('live-key')
    expect(val).toBe('alive')
  })
})

describe('memory KV driver — delete', () => {
  it('removes a key', async () => {
    await kv.put('del-key', 'val')
    await kv.delete('del-key')
    const val = await kv.get('del-key')
    expect(val).toBeNull()
  })

  it('delete on missing key is a no-op', async () => {
    await expect(kv.delete('ghost')).resolves.toBeUndefined()
  })
})

describe('memory KV driver — list', () => {
  it('lists all keys without prefix filter', async () => {
    await kv.put('a:1', 'x')
    await kv.put('a:2', 'y')
    await kv.put('b:1', 'z')
    const result = await kv.list()
    const names = result.keys.map(k => k.name)
    expect(names).toContain('a:1')
    expect(names).toContain('a:2')
    expect(names).toContain('b:1')
  })

  it('filters keys by prefix', async () => {
    await kv.put('rbac:perms:user-1', 'p1')
    await kv.put('rbac:perms:user-2', 'p2')
    await kv.put('cache:something', 'c')
    const result = await kv.list({ prefix: 'rbac:perms:' })
    const names = result.keys.map(k => k.name)
    expect(names).toContain('rbac:perms:user-1')
    expect(names).toContain('rbac:perms:user-2')
    expect(names).not.toContain('cache:something')
  })

  it('does not list expired keys', async () => {
    await kv.put('exp-key', 'v', { expirationTtl: 0.001 })
    await new Promise(r => setTimeout(r, 10))
    const result = await kv.list()
    expect(result.keys.map(k => k.name)).not.toContain('exp-key')
  })
})

describe('memory KV driver — getWithMetadata', () => {
  it('returns value and null metadata', async () => {
    await kv.put('meta-key', JSON.stringify({ foo: 'bar' }))
    const result = await kv.getWithMetadata<{ foo: string }>('meta-key', 'json')
    expect(result.value?.foo).toBe('bar')
    expect(result.metadata).toBeNull()
  })
})
