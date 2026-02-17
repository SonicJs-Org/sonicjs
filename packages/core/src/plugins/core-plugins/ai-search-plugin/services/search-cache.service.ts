/**
 * Search Result Cache Service
 *
 * KV-backed caching for search results. Wraps Cloudflare KV get/put with
 * SHA-256 key hashing. Returns cached results on hit, stores on miss.
 * Content CRUD hooks call invalidateAll() to clear stale entries.
 */

import type { SearchQuery, SearchResponse } from '../types'

export class SearchCacheService {
  private static readonly PREFIX = 'search-cache:v1:'

  constructor(private kv: any) {} // KVNamespace

  /**
   * Build a deterministic cache key from post-rule query params.
   * Returns null if caching should be skipped.
   */
  async buildKey(query: SearchQuery): Promise<string | null> {
    if (query.cache === false || !query.query?.trim()) {
      return null
    }

    const canonical = JSON.stringify({
      q: query.query.toLowerCase().trim(),
      m: query.mode,
      l: query.limit ?? null,
      o: query.offset ?? null,
      f: this.normalizeFilters(query.filters),
      fct: query.facets ?? false,
    })

    const hash = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(canonical)
    )
    const hex = Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')

    return `${SearchCacheService.PREFIX}${hex.slice(0, 16)}`
  }

  /**
   * Get cached search response. Returns null on miss or error.
   */
  async get(key: string): Promise<SearchResponse | null> {
    try {
      return await this.kv.get(key, 'json')
    } catch (error) {
      console.warn('[SearchCache] Get error:', error)
      return null
    }
  }

  /**
   * Store search response in cache. Fire-and-forget — never blocks the response.
   * Strips search_id before caching (must be fresh per search for click tracking).
   */
  async put(key: string, response: SearchResponse, ttlSeconds: number): Promise<void> {
    try {
      const toCache = { ...response }
      delete toCache.search_id // Must be unique per search for click tracking
      delete toCache.cached    // Don't store the cached flag itself

      // KV minimum TTL is 60 seconds
      const ttl = Math.max(60, ttlSeconds)
      await this.kv.put(key, JSON.stringify(toCache), { expirationTtl: ttl })
    } catch (error) {
      console.warn('[SearchCache] Put error:', error)
    }
  }

  /**
   * Invalidate all cached search results by listing and deleting keys with our prefix.
   * Returns the number of keys deleted.
   */
  async invalidateAll(): Promise<number> {
    let deleted = 0
    let cursor: string | undefined

    try {
      do {
        const listOptions: any = { prefix: SearchCacheService.PREFIX, limit: 1000 }
        if (cursor) listOptions.cursor = cursor

        const list = await this.kv.list(listOptions)
        const keys = list.keys || []

        for (const key of keys) {
          await this.kv.delete(key.name)
          deleted++
        }

        cursor = list.list_complete ? undefined : list.cursor
      } while (cursor)
    } catch (error) {
      console.warn('[SearchCache] Invalidation error:', error)
    }

    if (deleted > 0) {
      console.log(`[SearchCache] Invalidated ${deleted} cached entries`)
    }
    return deleted
  }

  /**
   * Normalize filters for deterministic hashing.
   * Sorts collections, status, and custom keys/values.
   */
  private normalizeFilters(filters?: SearchQuery['filters']): any {
    if (!filters) return null

    const normalized: any = {}

    if (filters.collections?.length) {
      normalized.collections = [...filters.collections].sort()
    }
    if (filters.status?.length) {
      normalized.status = [...filters.status].sort()
    }
    if (filters.tags?.length) {
      normalized.tags = [...filters.tags].sort()
    }
    if (filters.author) {
      normalized.author = filters.author
    }
    if (filters.dateRange) {
      normalized.dateRange = filters.dateRange
    }
    if (filters.custom && Object.keys(filters.custom).length > 0) {
      const sortedCustom: Record<string, any> = {}
      for (const key of Object.keys(filters.custom).sort()) {
        const val = filters.custom[key]
        sortedCustom[key] = Array.isArray(val) ? [...val].sort() : val
      }
      normalized.custom = sortedCustom
    }

    return Object.keys(normalized).length > 0 ? normalized : null
  }
}
