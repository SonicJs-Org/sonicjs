/**
 * Cache Service Adapter
 *
 * Thin facade over the cache plugin's `CacheService` so route code can keep its
 * legacy `{ ttl, keyPrefix }` contract while writes land in the plugin's
 * singleton — that's the same registry the admin dashboard at /admin/cache reads
 * via `getAllCacheStats()`. Without this adapter the two caches would be split:
 * routes would write to one, the dashboard would read from another, and the UI
 * would always show zero entries.
 */

import {
  getCacheService as getPluginCacheService,
  type CacheService as PluginCacheService,
} from '../plugins/cache/services/cache'
import type { CacheConfig as PluginCacheConfig } from '../plugins/cache/services/cache-config'

export interface CacheConfig {
  ttl: number // Time to live in seconds
  keyPrefix: string
}

function toPluginConfig(config: CacheConfig): PluginCacheConfig {
  return {
    ttl: config.ttl,
    namespace: config.keyPrefix,
    // KV survives isolate evictions — required for the dashboard to show non-zero
    // counts across requests in production. Falls back to memory-only when the
    // CACHE_KV binding is missing (cache plugin handles the null case).
    kvEnabled: true,
    memoryEnabled: true,
    invalidateOn: [],
    version: 'v1',
  }
}

export class CacheService {
  private config: CacheConfig
  private inner: PluginCacheService
  // Tracks expiry times so getWithSource can distinguish 'none' vs 'expired'.
  // The plugin returns source:'miss' for both cases; we differentiate here.
  private keyExpiry = new Map<string, number>()

  constructor(config: CacheConfig) {
    this.config = config
    this.inner = getPluginCacheService(toPluginConfig(config))
  }

  generateKey(type: string, identifier?: string): string {
    const parts = [this.config.keyPrefix, type]
    if (identifier !== undefined && identifier !== '') parts.push(identifier)
    return parts.join(':')
  }

  async get<T>(key: string): Promise<T | null> {
    return this.inner.get<T>(key)
  }

  async getWithSource<T>(key: string): Promise<{
    hit: boolean
    data: T | null
    source: string
    ttl?: number
  }> {
    const result = await this.inner.getWithSource<T>(key)
    if (result.hit) {
      const out: { hit: boolean; data: T | null; source: string; ttl?: number } = {
        hit: true,
        data: result.data,
        source: result.source,
      }
      if (result.ttl !== undefined) out.ttl = result.ttl
      return out
    }
    // Plugin returns source:'miss' for both "never set" and "expired". Distinguish
    // by checking if we ever recorded an expiry for this key.
    const expiry = this.keyExpiry.get(key)
    if (expiry !== undefined) {
      this.keyExpiry.delete(key)
      return { hit: false, data: null, source: 'expired' }
    }
    return { hit: false, data: null, source: 'none' }
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const effectiveTtl = ttl ?? this.config.ttl
    this.keyExpiry.set(key, Date.now() + effectiveTtl * 1000)
    await this.inner.set(key, value, ttl !== undefined ? { ttl } : undefined)
  }

  async delete(key: string): Promise<void> {
    this.keyExpiry.delete(key)
    await this.inner.delete(key)
  }

  async invalidate(pattern: string): Promise<void> {
    // Clear expiry tracking for invalidated keys
    if (pattern.includes('*') || pattern.includes('?')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$')
      for (const k of this.keyExpiry.keys()) {
        if (regex.test(k)) this.keyExpiry.delete(k)
      }
    } else {
      this.keyExpiry.delete(pattern)
    }
    await this.inner.invalidate(pattern)
  }

  async clear(): Promise<void> {
    this.keyExpiry.clear()
    await this.inner.clear()
  }

  async getOrSet<T>(key: string, callback: () => Promise<T>, ttl?: number): Promise<T> {
    const cached = await this.get<T>(key)
    if (cached !== null) return cached
    const value = await callback()
    await this.set(key, value, ttl)
    return value
  }
}

/**
 * Default cache configurations for different data types.
 */
export const CACHE_CONFIGS = {
  api: {
    ttl: 300, // 5 minutes
    keyPrefix: 'api',
  },
  user: {
    ttl: 600, // 10 minutes
    keyPrefix: 'user',
  },
  content: {
    ttl: 300, // 5 minutes
    keyPrefix: 'content',
  },
  collection: {
    ttl: 600, // 10 minutes
    keyPrefix: 'collection',
  },
}

/**
 * Resolve a cache service for a config. Wraps the plugin's singleton so admin
 * dashboard stats and route-side writes share the same store.
 */
export function getCacheService(config: CacheConfig): CacheService {
  return new CacheService(config)
}

/** Clear every cached value across all plugin singletons. Test/admin use only. */
export async function clearAllCacheInstances(): Promise<void> {
  const { clearAllCaches } = await import('../plugins/cache/services/cache')
  await clearAllCaches()
}
