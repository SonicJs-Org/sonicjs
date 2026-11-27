/**
 * Cache Service Tests
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { CacheService, CACHE_CONFIGS, getCacheService } from './cache'

describe('CacheService', () => {
  let cacheService: CacheService

  beforeEach(() => {
    cacheService = new CacheService({
      ttl: 60, // 60 seconds
      keyPrefix: 'test'
    })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('generateKey', () => {
    it('should generate key with prefix and type', () => {
      const key = cacheService.generateKey('users')
      // After #1254: delegates to plugin's generateKey which appends ':v1'
      expect(key).toBe('test:users::v1')
    })

    it('should generate key with prefix, type, and identifier', () => {
      const key = cacheService.generateKey('users', '123')
      expect(key).toBe('test:users:123:v1')
    })

    it('should generate key without identifier when undefined', () => {
      const key = cacheService.generateKey('settings', undefined)
      // empty string coercion via `identifier ?? ''`
      expect(key).toBe('test:settings::v1')
    })
  })

  describe('get and set', () => {
    it('should return null for non-existent key', async () => {
      const result = await cacheService.get('nonexistent')
      expect(result).toBeNull()
    })

    it('should set and get a value', async () => {
      await cacheService.set('mykey', { foo: 'bar' })
      const result = await cacheService.get('mykey')
      expect(result).toEqual({ foo: 'bar' })
    })

    it('should set and get string values', async () => {
      await cacheService.set('stringkey', 'hello world')
      const result = await cacheService.get<string>('stringkey')
      expect(result).toBe('hello world')
    })

    it('should set and get number values', async () => {
      await cacheService.set('numkey', 42)
      const result = await cacheService.get<number>('numkey')
      expect(result).toBe(42)
    })

    it('should set and get array values', async () => {
      const arr = [1, 2, 3, 'four']
      await cacheService.set('arrkey', arr)
      const result = await cacheService.get<any[]>('arrkey')
      expect(result).toEqual(arr)
    })

    it('should use default TTL when not specified', async () => {
      vi.useFakeTimers()
      const now = Date.now()
      vi.setSystemTime(now)

      await cacheService.set('ttlkey', 'value')

      // Should exist before TTL expires
      vi.setSystemTime(now + 59000) // 59 seconds later
      let result = await cacheService.get('ttlkey')
      expect(result).toBe('value')

      // Should be expired after TTL
      vi.setSystemTime(now + 61000) // 61 seconds later
      result = await cacheService.get('ttlkey')
      expect(result).toBeNull()
    })

    it('should use custom TTL when specified', async () => {
      vi.useFakeTimers()
      const now = Date.now()
      vi.setSystemTime(now)

      await cacheService.set('customttl', 'value', 5) // 5 second TTL

      // Should exist before custom TTL expires
      vi.setSystemTime(now + 4000)
      let result = await cacheService.get('customttl')
      expect(result).toBe('value')

      // Should be expired after custom TTL
      vi.setSystemTime(now + 6000)
      result = await cacheService.get('customttl')
      expect(result).toBeNull()
    })
  })

  describe('getWithSource', () => {
    it('should return hit false when key does not exist', async () => {
      const result = await cacheService.getWithSource('nonexistent')
      expect(result).toEqual({
        hit: false,
        data: null,
        source: 'none'
      })
    })

    it('should return hit true with data when key exists', async () => {
      await cacheService.set('sourcekey', { test: true })
      const result = await cacheService.getWithSource('sourcekey')

      expect(result.hit).toBe(true)
      expect(result.data).toEqual({ test: true })
      expect(result.source).toBe('memory')
      expect(typeof result.ttl).toBe('number')
      expect(result.ttl).toBeGreaterThan(0)
    })

    it('should return expired source when entry has expired', async () => {
      vi.useFakeTimers()
      const now = Date.now()
      vi.setSystemTime(now)

      await cacheService.set('expirekey', 'value', 10)

      // Advance past TTL
      vi.setSystemTime(now + 11000)

      const result = await cacheService.getWithSource('expirekey')
      expect(result).toEqual({
        hit: false,
        data: null,
        source: 'expired'
      })
    })

    it('should return correct remaining TTL', async () => {
      vi.useFakeTimers()
      const now = Date.now()
      vi.setSystemTime(now)

      await cacheService.set('ttlcheck', 'value', 100) // 100 second TTL

      // Advance 30 seconds
      vi.setSystemTime(now + 30000)

      const result = await cacheService.getWithSource('ttlcheck')
      expect(result.ttl).toBeCloseTo(70, 0) // ~70 seconds remaining
    })
  })

  describe('delete', () => {
    it('should delete an existing key', async () => {
      await cacheService.set('deletekey', 'value')
      expect(await cacheService.get('deletekey')).toBe('value')

      await cacheService.delete('deletekey')
      expect(await cacheService.get('deletekey')).toBeNull()
    })

    it('should not throw when deleting non-existent key', async () => {
      await expect(cacheService.delete('nonexistent')).resolves.not.toThrow()
    })
  })

  describe('invalidate', () => {
    it('should invalidate keys matching exact pattern', async () => {
      await cacheService.set('user:1', 'user1')
      await cacheService.set('user:2', 'user2')
      await cacheService.set('post:1', 'post1')

      await cacheService.invalidate('user:1')

      expect(await cacheService.get('user:1')).toBeNull()
      expect(await cacheService.get('user:2')).toBe('user2')
      expect(await cacheService.get('post:1')).toBe('post1')
    })

    it('should invalidate keys matching wildcard pattern', async () => {
      await cacheService.set('user:1', 'user1')
      await cacheService.set('user:2', 'user2')
      await cacheService.set('user:10', 'user10')
      await cacheService.set('post:1', 'post1')

      await cacheService.invalidate('user:*')

      expect(await cacheService.get('user:1')).toBeNull()
      expect(await cacheService.get('user:2')).toBeNull()
      expect(await cacheService.get('user:10')).toBeNull()
      expect(await cacheService.get('post:1')).toBe('post1')
    })

    it('should invalidate keys matching question mark pattern', async () => {
      await cacheService.set('user:1', 'user1')
      await cacheService.set('user:2', 'user2')
      await cacheService.set('user:10', 'user10')

      await cacheService.invalidate('user:?')

      expect(await cacheService.get('user:1')).toBeNull()
      expect(await cacheService.get('user:2')).toBeNull()
      expect(await cacheService.get('user:10')).toBe('user10') // Not matched (2 chars)
    })

    it('should handle complex patterns', async () => {
      await cacheService.set('api:users:list', 'list')
      await cacheService.set('api:users:123', 'user123')
      await cacheService.set('api:posts:list', 'posts')

      await cacheService.invalidate('api:users:*')

      expect(await cacheService.get('api:users:list')).toBeNull()
      expect(await cacheService.get('api:users:123')).toBeNull()
      expect(await cacheService.get('api:posts:list')).toBe('posts')
    })
  })

  describe('clear', () => {
    it('should clear all cached values', async () => {
      await cacheService.set('key1', 'value1')
      await cacheService.set('key2', 'value2')
      await cacheService.set('key3', 'value3')

      await cacheService.clear()

      expect(await cacheService.get('key1')).toBeNull()
      expect(await cacheService.get('key2')).toBeNull()
      expect(await cacheService.get('key3')).toBeNull()
    })

    it('should not throw when clearing empty cache', async () => {
      await expect(cacheService.clear()).resolves.not.toThrow()
    })
  })

  describe('getOrSet', () => {
    it('should return cached value if exists', async () => {
      await cacheService.set('orsetkey', 'cached')
      const callback = vi.fn().mockResolvedValue('fresh')

      const result = await cacheService.getOrSet('orsetkey', callback)

      expect(result).toBe('cached')
      expect(callback).not.toHaveBeenCalled()
    })

    it('should call callback and cache result if key does not exist', async () => {
      const callback = vi.fn().mockResolvedValue('fresh')

      const result = await cacheService.getOrSet('newkey', callback)

      expect(result).toBe('fresh')
      expect(callback).toHaveBeenCalledTimes(1)

      // Verify it was cached
      expect(await cacheService.get('newkey')).toBe('fresh')
    })

    it('should use custom TTL when provided', async () => {
      vi.useFakeTimers()
      const now = Date.now()
      vi.setSystemTime(now)

      const callback = vi.fn().mockResolvedValue('value')
      await cacheService.getOrSet('customttlkey', callback, 5)

      // Verify cached
      vi.setSystemTime(now + 3000)
      expect(await cacheService.get('customttlkey')).toBe('value')

      // Verify expired
      vi.setSystemTime(now + 6000)
      expect(await cacheService.get('customttlkey')).toBeNull()
    })

    it('should handle async callbacks correctly', async () => {
      const callback = vi.fn().mockImplementation(async () => {
        await new Promise(resolve => setTimeout(resolve, 10))
        return { data: 'async result' }
      })

      const result = await cacheService.getOrSet('asynckey', callback)
      expect(result).toEqual({ data: 'async result' })
    })

    it('should call callback again after cache expires', async () => {
      vi.useFakeTimers()
      const now = Date.now()
      vi.setSystemTime(now)

      let callCount = 0
      const callback = vi.fn().mockImplementation(async () => {
        callCount++
        return `value${callCount}`
      })

      // First call - sets cache
      const result1 = await cacheService.getOrSet('expirekey', callback, 5)
      expect(result1).toBe('value1')
      expect(callback).toHaveBeenCalledTimes(1)

      // Second call within TTL - uses cache
      vi.setSystemTime(now + 3000)
      const result2 = await cacheService.getOrSet('expirekey', callback, 5)
      expect(result2).toBe('value1')
      expect(callback).toHaveBeenCalledTimes(1)

      // Third call after TTL - calls callback again
      vi.setSystemTime(now + 6000)
      const result3 = await cacheService.getOrSet('expirekey', callback, 5)
      expect(result3).toBe('value2')
      expect(callback).toHaveBeenCalledTimes(2)
    })
  })
})

describe('CACHE_CONFIGS', () => {
  it('should have api config with correct values', () => {
    expect(CACHE_CONFIGS.api).toEqual({
      ttl: 300,
      keyPrefix: 'api'
    })
  })

  it('should have user config with correct values', () => {
    expect(CACHE_CONFIGS.user).toEqual({
      ttl: 600,
      keyPrefix: 'user'
    })
  })

  it('should have content config with correct values', () => {
    expect(CACHE_CONFIGS.content).toEqual({
      ttl: 300,
      keyPrefix: 'content'
    })
  })

  it('should have collection config with correct values', () => {
    expect(CACHE_CONFIGS.collection).toEqual({
      ttl: 600,
      keyPrefix: 'collection'
    })
  })
})

describe('getCacheService', () => {
  it('should return a new CacheService instance', () => {
    const service = getCacheService({ ttl: 120, keyPrefix: 'myprefix' })
    expect(service).toBeInstanceOf(CacheService)
  })

  it('should create service with provided config', () => {
    const service = getCacheService({ ttl: 120, keyPrefix: 'custom' })
    const key = service.generateKey('type', 'id')
    expect(key).toBe('custom:type:id:v1')
  })

  it('should create independent service instances', () => {
    const service1 = getCacheService({ ttl: 60, keyPrefix: 'svc1' })
    const service2 = getCacheService({ ttl: 60, keyPrefix: 'svc2' })

    expect(service1.generateKey('test')).toBe('svc1:test::v1')
    expect(service2.generateKey('test')).toBe('svc2:test::v1')
  })
})
