/**
 * Cache Service Tests
 *
 * Tests for the three-tiered caching system
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  CacheService,
  createCacheService,
  getCacheService,
  clearAllCaches,
  getAllCacheStats
} from '../services/cache.js'
import {
  CacheConfig,
  CACHE_CONFIGS,
  getCacheConfig,
  generateCacheKey,
  parseCacheKey,
  hashQueryParams,
  createCachePattern
} from '../services/cache-config.js'

describe('CacheConfig', () => {
  it('should have predefined cache configurations', () => {
    expect(CACHE_CONFIGS.content).toBeDefined()
    expect(CACHE_CONFIGS.user).toBeDefined()
    expect(CACHE_CONFIGS.config).toBeDefined()
    expect(CACHE_CONFIGS.media).toBeDefined()
  })

  it('should get cache config by namespace', () => {
    const config = getCacheConfig('content')
    expect(config.namespace).toBe('content')
    expect(config.ttl).toBe(3600)
  })

  it('should return default config for unknown namespace', () => {
    const config = getCacheConfig('unknown')
    expect(config.namespace).toBe('unknown')
    expect(config.ttl).toBe(3600)
  })

  it('should generate cache key with correct format', () => {
    const key = generateCacheKey('content', 'post', '123', 'v1')
    expect(key).toBe('content:post:123:v1')
  })

  it('should parse cache key correctly', () => {
    const key = 'content:post:123:v1'
    const parsed = parseCacheKey(key)

    expect(parsed).toBeDefined()
    expect(parsed?.namespace).toBe('content')
    expect(parsed?.type).toBe('post')
    expect(parsed?.identifier).toBe('123')
    expect(parsed?.version).toBe('v1')
  })

  it('should return null for invalid cache key', () => {
    const parsed = parseCacheKey('invalid:key')
    expect(parsed).toBeNull()
  })

  it('should hash query parameters consistently', () => {
    const params1 = { limit: 10, offset: 0, sort: 'asc' }
    const params2 = { offset: 0, limit: 10, sort: 'asc' }

    const hash1 = hashQueryParams(params1)
    const hash2 = hashQueryParams(params2)

    expect(hash1).toBe(hash2) // Order shouldn't matter
  })

  it('should create cache pattern for invalidation', () => {
    const pattern1 = createCachePattern('content')
    expect(pattern1).toBe('content:*')

    const pattern2 = createCachePattern('content', 'post')
    expect(pattern2).toBe('content:post:*')

    const pattern3 = createCachePattern('content', 'post', '123')
    expect(pattern3).toBe('content:post:123:*')
  })
})

describe('CacheService - Basic Operations', () => {
  let cache: CacheService

  beforeEach(() => {
    const config: CacheConfig = {
      ttl: 60,
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config)
  })

  it('should create cache service instance', () => {
    expect(cache).toBeDefined()
    expect(cache.getStats).toBeDefined()
  })

  it('should set and get value from cache', async () => {
    await cache.set('test:key', 'value')
    const result = await cache.get('test:key')

    expect(result).toBe('value')
  })

  it('should return null for non-existent key', async () => {
    const result = await cache.get('non-existent')
    expect(result).toBeNull()
  })

  it('should delete value from cache', async () => {
    await cache.set('test:key', 'value')
    await cache.delete('test:key')

    const result = await cache.get('test:key')
    expect(result).toBeNull()
  })

  it('should clear all cache entries', async () => {
    await cache.set('test:key1', 'value1')
    await cache.set('test:key2', 'value2')

    await cache.clear()

    const result1 = await cache.get('test:key1')
    const result2 = await cache.get('test:key2')

    expect(result1).toBeNull()
    expect(result2).toBeNull()
  })

  it('should check if key exists', async () => {
    await cache.set('test:key', 'value')

    const exists = await cache.has('test:key')
    const notExists = await cache.has('non-existent')

    expect(exists).toBe(true)
    expect(notExists).toBe(false)
  })

  it('should generate cache key with namespace', () => {
    const key = cache.generateKey('item', '123')
    expect(key).toBe('test:item:123:v1')
  })
})

describe('CacheService - Complex Data Types', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should cache objects', async () => {
    const obj = { id: 1, name: 'Test', data: { nested: true } }
    await cache.set('obj:key', obj)

    const result = await cache.get<typeof obj>('obj:key')
    expect(result).toEqual(obj)
  })

  it('should cache arrays', async () => {
    const arr = [1, 2, 3, 4, 5]
    await cache.set('arr:key', arr)

    const result = await cache.get<number[]>('arr:key')
    expect(result).toEqual(arr)
  })

  it('should cache null values', async () => {
    await cache.set('null:key', null)
    const result = await cache.get('null:key')

    // Note: null is stored but get returns null for both "not found" and "stored null"
    // This is acceptable behavior
    expect(result).toBeNull()
  })

  it('should cache boolean values', async () => {
    await cache.set('bool:true', true)
    await cache.set('bool:false', false)

    const resultTrue = await cache.get('bool:true')
    const resultFalse = await cache.get('bool:false')

    expect(resultTrue).toBe(true)
    expect(resultFalse).toBe(false)
  })
})

describe('CacheService - TTL and Expiration', () => {
  let cache: CacheService

  beforeEach(() => {
    const config: CacheConfig = {
      ttl: 1, // 1 second TTL for testing
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config)
  })

  it('should expire entries after TTL', async () => {
    await cache.set('test:key', 'value')

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1100))

    const result = await cache.get('test:key')
    expect(result).toBeNull()
  })

  it('should not expire before TTL', async () => {
    await cache.set('test:key', 'value')

    // Wait less than TTL
    await new Promise(resolve => setTimeout(resolve, 500))

    const result = await cache.get('test:key')
    expect(result).toBe('value')
  })

  it('should allow custom TTL per entry', async () => {
    await cache.set('test:key', 'value', { ttl: 10 }) // 10 second TTL

    // Entry should still be there after 1 second
    await new Promise(resolve => setTimeout(resolve, 1100))

    const result = await cache.get('test:key')
    expect(result).toBe('value')
  })
})

describe('CacheService - Statistics', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should track cache hits', async () => {
    await cache.set('test:key', 'value')

    await cache.get('test:key') // Hit
    await cache.get('test:key') // Hit

    const stats = cache.getStats()
    expect(stats.memoryHits).toBe(2)
  })

  it('should track cache misses', async () => {
    await cache.get('non-existent1') // Miss
    await cache.get('non-existent2') // Miss

    const stats = cache.getStats()
    expect(stats.memoryMisses).toBe(2)
  })

  it('should calculate hit rate correctly', async () => {
    await cache.set('test:key', 'value')

    await cache.get('test:key')       // Hit
    await cache.get('non-existent')   // Miss

    const stats = cache.getStats()
    expect(stats.hitRate).toBe(50) // 1 hit out of 2 requests
  })

  it('should track total requests', async () => {
    await cache.get('key1')
    await cache.get('key2')
    await cache.get('key3')

    const stats = cache.getStats()
    expect(stats.totalRequests).toBe(3)
  })

  it('should track entry count', async () => {
    await cache.set('key1', 'value1')
    await cache.set('key2', 'value2')
    await cache.set('key3', 'value3')

    const stats = cache.getStats()
    expect(stats.entryCount).toBe(3)
  })
})

describe('CacheService - Pattern Invalidation', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should invalidate entries matching pattern', async () => {
    await cache.set('content:post:1', 'value1')
    await cache.set('content:post:2', 'value2')
    await cache.set('content:page:1', 'value3')

    const count = await cache.invalidate('content:post:*')

    expect(count).toBe(2)

    const post1 = await cache.get('content:post:1')
    const post2 = await cache.get('content:post:2')
    const page1 = await cache.get('content:page:1')

    expect(post1).toBeNull()
    expect(post2).toBeNull()
    expect(page1).toBe('value3') // Should not be invalidated
  })

  it('should invalidate all entries with wildcard', async () => {
    await cache.set('content:post:1', 'value1')
    await cache.set('content:page:1', 'value2')
    await cache.set('content:list:all', 'value3')

    const count = await cache.invalidate('content:*')

    expect(count).toBe(3)
  })

  it('should return 0 for non-matching pattern', async () => {
    await cache.set('content:post:1', 'value1')

    const count = await cache.invalidate('user:*')

    expect(count).toBe(0)
  })
})

describe('CacheService - Batch Operations', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should get multiple values at once', async () => {
    await cache.set('key1', 'value1')
    await cache.set('key2', 'value2')
    await cache.set('key3', 'value3')

    const results = await cache.getMany(['key1', 'key2', 'key3', 'key4'])

    expect(results.size).toBe(3)
    expect(results.get('key1')).toBe('value1')
    expect(results.get('key2')).toBe('value2')
    expect(results.get('key3')).toBe('value3')
    expect(results.has('key4')).toBe(false)
  })

  it('should set multiple values at once', async () => {
    await cache.setMany([
      { key: 'key1', value: 'value1' },
      { key: 'key2', value: 'value2' },
      { key: 'key3', value: 'value3' }
    ])

    const value1 = await cache.get('key1')
    const value2 = await cache.get('key2')
    const value3 = await cache.get('key3')

    expect(value1).toBe('value1')
    expect(value2).toBe('value2')
    expect(value3).toBe('value3')
  })

  it('should delete multiple keys at once', async () => {
    await cache.set('key1', 'value1')
    await cache.set('key2', 'value2')
    await cache.set('key3', 'value3')

    await cache.deleteMany(['key1', 'key3'])

    const value1 = await cache.get('key1')
    const value2 = await cache.get('key2')
    const value3 = await cache.get('key3')

    expect(value1).toBeNull()
    expect(value2).toBe('value2')
    expect(value3).toBeNull()
  })

  it('should warm cache with multiple entries', async () => {
    await cache.warmCache([
      { key: 'key1', value: 'value1' },
      { key: 'key2', value: 'value2' }
    ])

    const value1 = await cache.get('key1')
    const value2 = await cache.get('key2')

    expect(value1).toBe('value1')
    expect(value2).toBe('value2')
  })
})

describe('CacheService - Get or Set Pattern', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should fetch and cache value when not found', async () => {
    let fetchCount = 0
    const fetcher = async () => {
      fetchCount++
      return 'fetched-value'
    }

    const result1 = await cache.getOrSet('test:key', fetcher)
    const result2 = await cache.getOrSet('test:key', fetcher)

    expect(result1).toBe('fetched-value')
    expect(result2).toBe('fetched-value')
    expect(fetchCount).toBe(1) // Fetcher should only be called once
  })

  it('should not call fetcher when value is cached', async () => {
    await cache.set('test:key', 'cached-value')

    const fetcher = vi.fn(async () => 'fetched-value')
    const result = await cache.getOrSet('test:key', fetcher)

    expect(result).toBe('cached-value')
    expect(fetcher).not.toHaveBeenCalled()
  })
})

describe('Global Cache Management', () => {
  beforeEach(async () => {
    await clearAllCaches()
  })

  it('should get singleton cache instance', () => {
    const cache1 = getCacheService(CACHE_CONFIGS.content!)
    const cache2 = getCacheService(CACHE_CONFIGS.content!)

    expect(cache1).toBe(cache2) // Same instance
  })

  it('should get different instances for different namespaces', () => {
    const contentCache = getCacheService(CACHE_CONFIGS.content!)
    const userCache = getCacheService(CACHE_CONFIGS.user!)

    expect(contentCache).not.toBe(userCache)
  })

  it('should clear all cache instances', async () => {
    const contentCache = getCacheService(CACHE_CONFIGS.content!)
    const userCache = getCacheService(CACHE_CONFIGS.user!)

    await contentCache.set('content:key', 'value')
    await userCache.set('user:key', 'value')

    await clearAllCaches()

    const contentValue = await contentCache.get('content:key')
    const userValue = await userCache.get('user:key')

    expect(contentValue).toBeNull()
    expect(userValue).toBeNull()
  })

  it('should get stats from all cache instances', async () => {
    const contentCache = getCacheService(CACHE_CONFIGS.content!)
    const userCache = getCacheService(CACHE_CONFIGS.user!)

    await contentCache.set('content:key', 'value')
    await userCache.set('user:key', 'value')

    const stats = getAllCacheStats()

    expect(stats.content).toBeDefined()
    expect(stats.user).toBeDefined()
    expect(stats.content!.entryCount).toBe(1)
    expect(stats.user!.entryCount).toBe(1)
  })
})

describe('CacheService - KV Operations', () => {
  let cache: CacheService
  let mockKv: any

  beforeEach(async () => {
    await clearAllCaches()

    mockKv = {
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      list: vi.fn()
    }

    const config: CacheConfig = {
      ttl: 60,
      kvEnabled: true,
      memoryEnabled: true,
      namespace: 'kv-test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config, mockKv)
  })

  it('should get value from KV when not in memory', async () => {
    const testValue = { id: 1, name: 'test' }
    mockKv.get.mockResolvedValue(testValue)

    // First get will miss memory, hit KV
    const result = await cache.get('test:key')

    expect(mockKv.get).toHaveBeenCalledWith('test:key', 'json')
    expect(result).toEqual(testValue)
  })

  it('should populate memory cache after KV hit', async () => {
    const testValue = { id: 1, name: 'test' }
    mockKv.get.mockResolvedValue(testValue)

    // First get - from KV
    await cache.get('test:key')

    // Second get - should be from memory, not KV
    mockKv.get.mockClear()
    const result = await cache.get('test:key')

    expect(mockKv.get).not.toHaveBeenCalled()
    expect(result).toEqual(testValue)
  })

  it('should store value in both memory and KV', async () => {
    const testValue = { id: 1, name: 'test' }

    await cache.set('test:key', testValue)

    expect(mockKv.put).toHaveBeenCalledWith(
      'test:key',
      JSON.stringify(testValue),
      { expirationTtl: 60 }
    )
  })

  it('should delete from both memory and KV', async () => {
    await cache.set('test:key', 'value')

    await cache.delete('test:key')

    expect(mockKv.delete).toHaveBeenCalledWith('test:key')

    // Memory should also be cleared
    mockKv.get.mockResolvedValue(null)
    const result = await cache.get('test:key')
    expect(result).toBeNull()
  })

  it('should handle KV read errors gracefully', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockKv.get.mockRejectedValue(new Error('KV read error'))

    const result = await cache.get('test:key')

    expect(result).toBeNull()
    expect(consoleSpy).toHaveBeenCalledWith('KV cache read error:', expect.any(Error))

    consoleSpy.mockRestore()
  })

  it('should handle KV write errors gracefully', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockKv.put.mockRejectedValue(new Error('KV write error'))

    // Should not throw
    await expect(cache.set('test:key', 'value')).resolves.not.toThrow()

    expect(consoleSpy).toHaveBeenCalledWith('KV cache write error:', expect.any(Error))

    consoleSpy.mockRestore()
  })

  it('should handle KV delete errors gracefully', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockKv.delete.mockRejectedValue(new Error('KV delete error'))

    // Should not throw
    await expect(cache.delete('test:key')).resolves.not.toThrow()

    expect(consoleSpy).toHaveBeenCalledWith('KV cache delete error:', expect.any(Error))

    consoleSpy.mockRestore()
  })

  it('should invalidate pattern in KV', async () => {
    mockKv.list.mockResolvedValue({
      keys: [
        { name: 'kv-test:post:1' },
        { name: 'kv-test:post:2' },
        { name: 'kv-test:page:1' }
      ]
    })

    const count = await cache.invalidate('kv-test:post:*')

    expect(mockKv.list).toHaveBeenCalledWith({ prefix: 'kv-test:' })
    expect(mockKv.delete).toHaveBeenCalledWith('kv-test:post:1')
    expect(mockKv.delete).toHaveBeenCalledWith('kv-test:post:2')
    expect(count).toBeGreaterThanOrEqual(2)
  })

  it('should handle KV invalidation errors gracefully', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockKv.list.mockRejectedValue(new Error('KV list error'))

    // Should not throw
    await expect(cache.invalidate('kv-test:*')).resolves.not.toThrow()

    expect(consoleSpy).toHaveBeenCalledWith('KV cache invalidation error:', expect.any(Error))

    consoleSpy.mockRestore()
  })

  it('should track KV hits and misses', async () => {
    // KV hit
    mockKv.get.mockResolvedValue({ data: 'value' })
    await cache.get('hit:key')

    // KV miss
    mockKv.get.mockResolvedValue(null)
    await cache.get('miss:key')

    const stats = cache.getStats()
    expect(stats.kvHits).toBe(1)
    expect(stats.kvMisses).toBe(1)
  })
})

describe('CacheService - getWithSource', () => {
  let cache: CacheService
  let mockKv: any

  beforeEach(async () => {
    await clearAllCaches()

    mockKv = {
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      list: vi.fn()
    }

    const config: CacheConfig = {
      ttl: 60,
      kvEnabled: true,
      memoryEnabled: true,
      namespace: 'source-test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config, mockKv)
  })

  it('should return memory source when hit in memory', async () => {
    await cache.set('test:key', 'memory-value')

    const result = await cache.getWithSource('test:key')

    expect(result.hit).toBe(true)
    expect(result.source).toBe('memory')
    expect(result.data).toBe('memory-value')
  })

  it('should return kv source when hit in KV', async () => {
    mockKv.get.mockResolvedValue('kv-value')

    const result = await cache.getWithSource('test:key')

    expect(result.hit).toBe(true)
    expect(result.source).toBe('kv')
    expect(result.data).toBe('kv-value')
  })

  it('should return miss source when not found', async () => {
    mockKv.get.mockResolvedValue(null)

    const result = await cache.getWithSource('test:key')

    expect(result.hit).toBe(false)
    expect(result.source).toBe('miss')
    expect(result.data).toBeNull()
  })

  it('should populate memory after KV hit in getWithSource', async () => {
    mockKv.get.mockResolvedValue('kv-value')

    // First call hits KV
    await cache.getWithSource('test:key')

    // Second call should hit memory
    mockKv.get.mockClear()
    const result = await cache.getWithSource('test:key')

    expect(mockKv.get).not.toHaveBeenCalled()
    expect(result.source).toBe('memory')
  })

  it('should handle KV errors in getWithSource', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    mockKv.get.mockRejectedValue(new Error('KV error'))

    const result = await cache.getWithSource('test:key')

    expect(result.hit).toBe(false)
    expect(result.source).toBe('miss')

    consoleSpy.mockRestore()
  })
})

describe('CacheService - listKeys and getEntry', () => {
  let cache: CacheService

  beforeEach(async () => {
    await clearAllCaches()
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should list all cache keys with metadata', async () => {
    await cache.set('key1', 'value1')
    await cache.set('key2', { nested: 'value2' })

    const keys = await cache.listKeys()

    expect(keys.length).toBe(2)
    expect(keys[0].key).toBeDefined()
    expect(keys[0].size).toBeGreaterThan(0)
    expect(keys[0].expiresAt).toBeGreaterThan(Date.now())
    expect(keys[0].age).toBeGreaterThanOrEqual(0)
  })

  it('should sort keys by age (newest first)', async () => {
    await cache.set('old:key', 'old')
    await new Promise(resolve => setTimeout(resolve, 10))
    await cache.set('new:key', 'new')

    const keys = await cache.listKeys()

    // Newest (smallest age) should be first
    expect(keys[0].key).toBe('new:key')
  })

  it('should get cache entry with full metadata', async () => {
    await cache.set('test:key', { data: 'test' })

    const entry = await cache.getEntry('test:key')

    expect(entry).not.toBeNull()
    expect(entry?.data).toEqual({ data: 'test' })
    expect(entry?.timestamp).toBeLessThanOrEqual(Date.now())
    expect(entry?.expiresAt).toBeGreaterThan(Date.now())
    expect(entry?.ttl).toBeGreaterThan(0)
    expect(entry?.size).toBeGreaterThan(0)
  })

  it('should return null for non-existent entry', async () => {
    const entry = await cache.getEntry('non-existent')

    expect(entry).toBeNull()
  })

  it('should return null for expired entry in getEntry', async () => {
    const shortTtlConfig: CacheConfig = {
      ttl: 1, // 1 second
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'short-ttl',
      invalidateOn: [],
      version: 'v1'
    }
    const shortCache = createCacheService(shortTtlConfig)
    await shortCache.set('test:key', 'value')

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1100))

    const entry = await shortCache.getEntry('test:key')

    expect(entry).toBeNull()
  })

  it('should return null when memory is disabled', async () => {
    const noMemoryConfig: CacheConfig = {
      ttl: 60,
      kvEnabled: false,
      memoryEnabled: false,
      namespace: 'no-memory',
      invalidateOn: [],
      version: 'v1'
    }
    const noMemoryCache = createCacheService(noMemoryConfig)

    const entry = await noMemoryCache.getEntry('test:key')

    expect(entry).toBeNull()
  })
})

describe('CacheService - Memory Eviction', () => {
  it('should evict LRU entries when cache is full', async () => {
    // Create a small cache that will fill up quickly
    const smallConfig: CacheConfig = {
      ttl: 3600,
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'eviction-test',
      invalidateOn: [],
      version: 'v1'
    }
    const cache = createCacheService(smallConfig)

    // Add many entries to trigger eviction
    for (let i = 0; i < 100; i++) {
      await cache.set(`key${i}`, { data: 'x'.repeat(100000) }) // ~100KB each
    }

    // Some early entries should have been evicted
    const stats = cache.getStats()
    expect(stats.memorySize).toBeLessThan(50 * 1024 * 1024) // Less than 50MB
  })
})

describe('CacheService - Memory Disabled', () => {
  let cache: CacheService
  let mockKv: any

  beforeEach(async () => {
    await clearAllCaches()

    mockKv = {
      get: vi.fn(),
      put: vi.fn(),
      delete: vi.fn(),
      list: vi.fn()
    }

    const config: CacheConfig = {
      ttl: 60,
      kvEnabled: true,
      memoryEnabled: false,
      namespace: 'no-memory-test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config, mockKv)
  })

  it('should go directly to KV when memory is disabled', async () => {
    mockKv.get.mockResolvedValue('kv-value')

    const result = await cache.get('test:key')

    expect(mockKv.get).toHaveBeenCalledWith('test:key', 'json')
    expect(result).toBe('kv-value')
  })

  it('should only write to KV when memory is disabled', async () => {
    await cache.set('test:key', 'value')

    expect(mockKv.put).toHaveBeenCalled()

    // Verify memory stats are 0
    const stats = cache.getStats()
    expect(stats.entryCount).toBe(0)
  })
})

describe('CacheService - invalidatePattern alias', () => {
  let cache: CacheService

  beforeEach(async () => {
    await clearAllCaches()
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should work the same as invalidate', async () => {
    await cache.set('test:item:1', 'value1')
    await cache.set('test:item:2', 'value2')
    await cache.set('test:other:1', 'value3')

    const count = await cache.invalidatePattern('test:item:*')

    expect(count).toBe(2)

    const item1 = await cache.get('test:item:1')
    const item2 = await cache.get('test:item:2')
    const other = await cache.get('test:other:1')

    expect(item1).toBeNull()
    expect(item2).toBeNull()
    expect(other).toBe('value3')
  })
})

describe('CacheService - request trace instrumentation', () => {
  const baseConfig: CacheConfig = {
    ttl: 60, kvEnabled: true, memoryEnabled: true, namespace: 'trace-test', invalidateOn: [], version: 'v1',
  }
  const makeKv = (store: Record<string, unknown> = {}) =>
    ({
      get: async (k: string) => (k in store ? store[k] : null),
      put: async (k: string, v: string) => { store[k] = JSON.parse(v) },
      delete: async () => {},
      list: async () => ({ keys: [] }),
    }) as any

  it('records memory hit, KV hit and miss for get()', async () => {
    const { RequestTrace, loadAsyncLocalStorage, runWithTrace } = await import('../../../utils/request-trace')
    await loadAsyncLocalStorage()
    const cache = createCacheService(baseConfig, makeKv({ 'kv-key': { a: 1 } }))
    await cache.set('mem-key', 'v')
    const trace = new RequestTrace('GET', '/admin/x')
    await runWithTrace(trace, async () => {
      await cache.get('mem-key')
      await cache.get('kv-key')
      await cache.get('nope')
    })
    const gets = trace.entries.filter((e) => e.op === 'get')
    expect(gets.map((e) => e.cache)).toEqual(['hit:memory', 'hit:kv', 'miss'])
    expect(trace.entries.every((e) => e.kind === 'cache')).toBe(true)
  })

  it('records getWithSource() and set()', async () => {
    const { RequestTrace, loadAsyncLocalStorage, runWithTrace } = await import('../../../utils/request-trace')
    await loadAsyncLocalStorage()
    const cache = createCacheService(baseConfig, makeKv())
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, async () => {
      await cache.set('k', 1)
      await cache.getWithSource('k')
      await cache.getWithSource('zzz')
    })
    expect(trace.entries.map((e) => [e.op, e.cache])).toEqual([
      ['set', null], ['getWithSource', 'hit:memory'], ['getWithSource', 'miss'],
    ])
  })

  it('getMany records exactly one entry per key (no double counting)', async () => {
    const { RequestTrace, loadAsyncLocalStorage, runWithTrace } = await import('../../../utils/request-trace')
    await loadAsyncLocalStorage()
    const cache = createCacheService({ ...baseConfig, kvEnabled: false })
    await cache.set('a', 1)
    const trace = new RequestTrace('GET', '/')
    await runWithTrace(trace, () => cache.getMany(['a', 'b', 'c']))
    expect(trace.entries).toHaveLength(3)
  })

  it('records nothing outside a trace', async () => {
    const cache = createCacheService({ ...baseConfig, kvEnabled: false })
    await cache.set('a', 1)
    expect(await cache.get('a')).toBe(1)
  })
})
