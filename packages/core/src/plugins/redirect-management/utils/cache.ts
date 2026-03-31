/**
 * LRU Cache Wrapper for Redirect Lookups
 *
 * Provides sub-millisecond redirect lookups via in-memory caching with LRU eviction.
 * Cache keys are ALREADY normalized URLs (caller is responsible for normalization).
 *
 * Uses tiny-lru library for automatic LRU eviction when cache reaches max capacity.
 */

import { lru } from 'tiny-lru'

/**
 * Cache entry for a redirect
 *
 * Stores all redirect metadata needed to execute redirect without database lookup.
 * Note: Cache keys are normalized source URLs (lowercase, no trailing slash).
 */
export interface CacheEntry {
  /** Unique redirect identifier */
  id: string
  /** Destination URL to redirect to */
  destination: string
  /** HTTP status code (301, 302, 307, 308, 410) */
  statusCode: number
  /** Whether redirect is currently active */
  isActive: boolean
  /** Match type: 0=exact, 1=wildcard, 2=regex */
  matchType: number
  /** Whether to preserve query string in destination (Cloudflare: preserve_query_string) */
  preserveQueryString: boolean
  /** Whether to include subdomains in matching (Cloudflare: include_subdomains) */
  includeSubdomains: boolean
  /** Whether to enable subpath matching (Cloudflare: subpath_matching) */
  subpathMatching: boolean
  /** Whether to preserve path suffix when redirecting (Cloudflare: preserve_path_suffix) */
  preservePathSuffix: boolean
}

/**
 * LRU cache for redirect lookups
 *
 * Provides O(1) lookups with automatic LRU eviction at max capacity.
 * Entire cache is invalidated on any redirect change for consistency.
 *
 * Default capacity: 1000 entries (based on research recommendation)
 *
 * Usage:
 * ```typescript
 * const cache = new RedirectCache()
 * cache.set('/blog', { id: '123', destination: '/new-blog', ... })
 * const entry = cache.get('/blog')
 * cache.clear() // Invalidate on any redirect change
 * ```
 */
export class RedirectCache {
  private cache: ReturnType<typeof lru<CacheEntry>>

  /**
   * Create redirect cache with optional max size
   *
   * @param maxSize - Maximum number of entries (default 1000)
   */
  constructor(maxSize: number = 1000) {
    this.cache = lru<CacheEntry>(maxSize)
  }

  /**
   * Get redirect entry from cache
   *
   * @param normalizedSource - Already normalized source URL
   * @returns Cache entry if found, undefined otherwise
   */
  get(normalizedSource: string): CacheEntry | undefined {
    return this.cache.get(normalizedSource)
  }

  /**
   * Store redirect entry in cache
   *
   * @param normalizedSource - Already normalized source URL
   * @param entry - Cache entry to store
   */
  set(normalizedSource: string, entry: CacheEntry): void {
    this.cache.set(normalizedSource, entry)
  }

  /**
   * Check if redirect entry exists in cache
   *
   * @param normalizedSource - Already normalized source URL
   * @returns true if entry exists, false otherwise
   */
  has(normalizedSource: string): boolean {
    return this.cache.has(normalizedSource)
  }

  /**
   * Delete redirect entry from cache
   *
   * @param normalizedSource - Already normalized source URL
   */
  delete(normalizedSource: string): void {
    this.cache.delete(normalizedSource)
  }

  /**
   * Clear entire cache
   *
   * Called on any redirect change (create, update, delete) to ensure consistency.
   * Simple invalidation strategy: clear all on any change.
   */
  clear(): void {
    this.cache.clear()
  }

  /**
   * Get current cache size
   *
   * @returns Number of entries currently in cache
   */
  size(): number {
    return this.cache.size
  }
}
