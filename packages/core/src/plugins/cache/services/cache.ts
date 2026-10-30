/**
 * Cache Service
 *
 * Three-tiered caching implementation:
 * 1. In-Memory Cache (fastest, region-specific)
 * 2. Cloudflare KV Cache (fast, global)
 * 3. Database (fallback, source of truth)
 */

import { CacheConfig, CacheStats, generateCacheKey } from './cache-config.js'

/**
 * Cache entry with metadata
 */
interface CacheEntry<T> {
  data: T
  timestamp: number
  expiresAt: number
  version: string
}

/**
 * In-memory cache store
 */
class MemoryCache {
  private cache: Map<string, CacheEntry<any>> = new Map()
  private maxSize: number = 50 * 1024 * 1024 // 50MB
  private currentSize: number = 0

  /**
   * Get item from memory cache
   */
  get<T>(key: string): T | null {
    const entry = this.cache.get(key)

    if (!entry) {
      return null
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      this.delete(key)
      return null
    }

    return entry.data as T
  }

  /**
   * Set item in memory cache
   */
  set<T>(key: string, value: T, ttl: number, version: string = 'v1'): void {
    const now = Date.now()
    const entry: CacheEntry<T> = {
      data: value,
      timestamp: now,
      expiresAt: now + (ttl * 1000),
      version
    }

    // Estimate size (rough approximation)
    const entrySize = JSON.stringify(entry).length * 2 // UTF-16

    // Check if we need to evict
    if (this.currentSize + entrySize > this.maxSize) {
      this.evictLRU(entrySize)
    }

    // Delete old entry if exists
    if (this.cache.has(key)) {
      this.delete(key)
    }

    this.cache.set(key, entry)
    this.currentSize += entrySize
  }

  /**
   * Delete item from memory cache
   */
  delete(key: string): boolean {
    const entry = this.cache.get(key)
    if (entry) {
      const entrySize = JSON.stringify(entry).length * 2
      this.currentSize -= entrySize
      return this.cache.delete(key)
    }
    return false
  }

  /**
   * Clear all items from memory cache
   */
  clear(): void {
    this.cache.clear()
    this.currentSize = 0
  }

  /**
   * Get cache statistics
   */
  getStats(): { size: number; count: number } {
    return {
      size: this.currentSize,
      count: this.cache.size
    }
  }

  /**
   * Evict least recently used items to make space
   */
  private evictLRU(neededSpace: number): void {
    // Sort by timestamp (oldest first)
    const entries = Array.from(this.cache.entries()).sort(
      (a, b) => a[1].timestamp - b[1].timestamp
    )

    let freedSpace = 0
    for (const [key, entry] of entries) {
      if (freedSpace >= neededSpace) break

      const entrySize = JSON.stringify(entry).length * 2
      this.delete(key)
      freedSpace += entrySize
    }
  }

  /**
   * Delete items matching a pattern
   */
  invalidatePattern(pattern: string): number {
    const regex = new RegExp(
      '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
    )

    let count = 0
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.delete(key)
        count++
      }
    }

    return count
  }
}

/**
 * Cache result with source information
 */
export interface CacheResult<T> {
  data: T | null
  source: 'memory' | 'kv' | 'miss'
  hit: boolean
  timestamp?: number
  ttl?: number
}

/**
 * Main cache service with multi-tier support
 */
export class CacheService {
  private memoryCache: MemoryCache
  private config: CacheConfig
  private stats: CacheStats
  private kvNamespace?: KVNamespace

  constructor(config: CacheConfig, kvNamespace?: KVNamespace) {
    this.memoryCache = new MemoryCache()
    this.config = config
    this.kvNamespace = kvNamespace
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      kvHits: 0,
      kvMisses: 0,
      dbHits: 0,
      totalRequests: 0,
      hitRate: 0,
      memorySize: 0,
      entryCount: 0
    }
  }

  /**
   * Get value from cache (tries memory first, then KV)
   */
  async get<T>(key: string): Promise<T | null> {
    this.stats.totalRequests++

    // Try memory cache first (Tier 1)
    if (this.config.memoryEnabled) {
      const memoryValue = this.memoryCache.get<T>(key)
      if (memoryValue !== null) {
        this.stats.memoryHits++
        this.updateHitRate()
        return memoryValue
      }
      this.stats.memoryMisses++
    }

    // Try KV cache (Tier 2)
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        const kvValue = await this.kvNamespace.get(key, 'json')
        if (kvValue !== null) {
          this.stats.kvHits++

          // Populate memory cache for faster subsequent access
          if (this.config.memoryEnabled) {
            this.memoryCache.set(key, kvValue as T, this.config.ttl, this.config.version)
          }

          this.updateHitRate()
          return kvValue as T
        }
        this.stats.kvMisses++
      } catch (error) {
        console.error('KV cache read error:', error)
        this.stats.kvMisses++
      }
    }

    this.updateHitRate()
    return null
  }

  /**
   * Get value from cache with source information
   */
  async getWithSource<T>(key: string): Promise<CacheResult<T>> {
    this.stats.totalRequests++

    // Try memory cache first (Tier 1)
    if (this.config.memoryEnabled) {
      const memoryValue = this.memoryCache.get<T>(key)
      if (memoryValue !== null) {
        this.stats.memoryHits++
        this.updateHitRate()

        const entry = await this.getEntry<T>(key)
        return {
          data: memoryValue,
          source: 'memory',
          hit: true,
          timestamp: entry?.timestamp,
          ttl: entry?.ttl
        }
      }
      this.stats.memoryMisses++
    }

    // Try KV cache (Tier 2)
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        const kvValue = await this.kvNamespace.get(key, 'json')
        if (kvValue !== null) {
          this.stats.kvHits++

          // Populate memory cache for faster subsequent access
          if (this.config.memoryEnabled) {
            this.memoryCache.set(key, kvValue as T, this.config.ttl, this.config.version)
          }

          this.updateHitRate()
          return {
            data: kvValue as T,
            source: 'kv',
            hit: true
          }
        }
        this.stats.kvMisses++
      } catch (error) {
        console.error('KV cache read error:', error)
        this.stats.kvMisses++
      }
    }

    this.updateHitRate()
    return {
      data: null,
      source: 'miss',
      hit: false
    }
  }

  /**
   * Set value in cache (stores in both memory and KV)
   */
  async set<T>(
    key: string,
    value: T,
    customConfig?: Partial<CacheConfig>
  ): Promise<void> {
    const config = { ...this.config, ...customConfig }

    // Store in memory cache (Tier 1)
    if (config.memoryEnabled) {
      this.memoryCache.set(key, value, config.ttl, config.version)
    }

    // Store in KV cache (Tier 2)
    if (config.kvEnabled && this.kvNamespace) {
      try {
        await this.kvNamespace.put(key, JSON.stringify(value), {
          // Cloudflare KV requires minimum 60s TTL in production; clamp silently.
          expirationTtl: Math.max(config.ttl, 60)
        })
      } catch (error) {
        console.error('KV cache write error:', error)
      }
    }
  }

  /**
   * Delete value from cache (removes from both memory and KV)
   */
  async delete(key: string): Promise<void> {
    // Delete from memory (Tier 1)
    if (this.config.memoryEnabled) {
      this.memoryCache.delete(key)
    }

    // Delete from KV (Tier 2)
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        await this.kvNamespace.delete(key)
      } catch (error) {
        console.error('KV cache delete error:', error)
      }
    }
  }

  /**
   * Clear all cache entries for this namespace
   */
  async clear(): Promise<void> {
    if (this.config.memoryEnabled) {
      this.memoryCache.clear()
    }

    // Reset stats
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      kvHits: 0,
      kvMisses: 0,
      dbHits: 0,
      totalRequests: 0,
      hitRate: 0,
      memorySize: 0,
      entryCount: 0
    }
  }

  /**
   * Invalidate cache entries matching a pattern
   */
  async invalidate(pattern: string): Promise<number> {
    let count = 0

    // Invalidate from memory (Tier 1)
    if (this.config.memoryEnabled) {
      count += this.memoryCache.invalidatePattern(pattern)
    }

    // Invalidate from KV (Tier 2)
    // Note: KV doesn't support pattern matching, so we need to list all keys
    // This is expensive and should be used sparingly
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        const regex = new RegExp(
          '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
        )

        // List all keys with the namespace prefix
        const prefix = this.config.namespace + ':'
        const list = await this.kvNamespace.list({ prefix })

        for (const key of list.keys) {
          if (regex.test(key.name)) {
            await this.kvNamespace.delete(key.name)
            count++
          }
        }
      } catch (error) {
        console.error('KV cache invalidation error:', error)
      }
    }

    return count
  }

  /**
   * Invalidate cache entries matching a pattern (alias for invalidate)
   */
  async invalidatePattern(pattern: string): Promise<number> {
    return this.invalidate(pattern)
  }

  /**
   * Get cache statistics
   */
  getStats(): CacheStats {
    const memStats = this.memoryCache.getStats()

    return {
      ...this.stats,
      memorySize: memStats.size,
      entryCount: memStats.count
    }
  }

  /**
   * Update hit rate calculation
   */
  private updateHitRate(): void {
    const totalHits = this.stats.memoryHits + this.stats.kvHits + this.stats.dbHits
    this.stats.hitRate = this.stats.totalRequests > 0
      ? (totalHits / this.stats.totalRequests) * 100
      : 0
  }

  /**
   * Generate a cache key using the configured namespace
   */
  generateKey(type: string, identifier: string): string {
    return generateCacheKey(
      this.config.namespace,
      type,
      identifier,
      this.config.version
    )
  }

  /**
   * Warm cache with multiple entries
   */
  async warmCache<T>(entries: Array<{ key: string; value: T }>): Promise<void> {
    for (const entry of entries) {
      await this.set(entry.key, entry.value)
    }
  }

  /**
   * Check if a key exists in cache
   */
  async has(key: string): Promise<boolean> {
    const value = await this.get(key)
    return value !== null
  }

  /**
   * Get multiple values at once
   */
  async getMany<T>(keys: string[]): Promise<Map<string, T>> {
    const results = new Map<string, T>()

    for (const key of keys) {
      const value = await this.get<T>(key)
      if (value !== null) {
        results.set(key, value)
      }
    }

    return results
  }

  /**
   * Set multiple values at once
   */
  async setMany<T>(
    entries: Array<{ key: string; value: T }>,
    customConfig?: Partial<CacheConfig>
  ): Promise<void> {
    for (const entry of entries) {
      await this.set(entry.key, entry.value, customConfig)
    }
  }

  /**
   * Delete multiple keys at once
   */
  async deleteMany(keys: string[]): Promise<void> {
    for (const key of keys) {
      await this.delete(key)
    }
  }

  /**
   * Get or set pattern - fetch from cache or compute if not found
   */
  async getOrSet<T>(
    key: string,
    fetcher: () => Promise<T>,
    customConfig?: Partial<CacheConfig>
  ): Promise<T> {
    // Try to get from cache
    const cached = await this.get<T>(key)
    if (cached !== null) {
      return cached
    }

    // Fetch from source
    const value = await fetcher()

    // Store in cache
    await this.set(key, value, customConfig)

    return value
  }

  /**
   * List all cache keys with metadata
   */
  async listKeys(): Promise<Array<{ key: string; size: number; expiresAt: number; age: number }>> {
    const keys: Array<{ key: string; size: number; expiresAt: number; age: number }> = []

    // Get keys from memory cache
    if (this.config.memoryEnabled) {
      const cache = (this.memoryCache as any).cache as Map<string, CacheEntry<any>>
      for (const [key, entry] of cache.entries()) {
        const size = JSON.stringify(entry).length * 2
        const age = Date.now() - entry.timestamp
        keys.push({
          key,
          size,
          expiresAt: entry.expiresAt,
          age
        })
      }
    }

    // Sort by age (newest first)
    return keys.sort((a, b) => a.age - b.age)
  }

  /**
   * Get cache entry with full metadata
   */
  async getEntry<T>(key: string): Promise<{
    data: T
    timestamp: number
    expiresAt: number
    ttl: number
    size: number
  } | null> {
    if (!this.config.memoryEnabled) {
      return null
    }

    const cache = (this.memoryCache as any).cache as Map<string, CacheEntry<any>>
    const entry = cache.get(key)

    if (!entry) {
      return null
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      await this.delete(key)
      return null
    }

    const size = JSON.stringify(entry).length * 2
    const ttl = Math.max(0, entry.expiresAt - Date.now()) / 1000

    return {
      data: entry.data as T,
      timestamp: entry.timestamp,
      expiresAt: entry.expiresAt,
      ttl,
      size
    }
  }
}

/**
 * Create a cache service instance with configuration
 */
export function createCacheService(config: CacheConfig, kvNamespace?: KVNamespace): CacheService {
  return new CacheService(config, kvNamespace)
}

/**
 * Global cache instances by namespace (singleton pattern)
 */
const cacheInstances = new Map<string, CacheService>()
let globalKVNamespace: KVNamespace | undefined

/**
 * Set global KV namespace for all cache instances
 */
export function setGlobalKVNamespace(kvNamespace: KVNamespace): void {
  globalKVNamespace = kvNamespace
}

/**
 * Get or create a cache service for a namespace
 */
export function getCacheService(config: CacheConfig, kvNamespace?: KVNamespace): CacheService {
  const key = config.namespace

  if (!cacheInstances.has(key)) {
    // Use provided KV namespace or global one
    const kv = kvNamespace || globalKVNamespace
    cacheInstances.set(key, new CacheService(config, kv))
  }

  return cacheInstances.get(key)!
}

/**
 * Clear all cache instances
 */
export async function clearAllCaches(): Promise<void> {
  for (const cache of cacheInstances.values()) {
    await cache.clear()
  }
}

/**
 * Get stats from all cache instances
 */
export function getAllCacheStats(): Record<string, CacheStats> {
  const stats: Record<string, CacheStats> = {}

  for (const [namespace, cache] of cacheInstances.entries()) {
    stats[namespace] = cache.getStats()
  }

  return stats
}
