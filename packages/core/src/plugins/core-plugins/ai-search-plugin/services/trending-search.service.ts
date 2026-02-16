import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import type { TrendingSearch, TrendingSearchResult } from '../types'

/**
 * Trending Search Service
 *
 * Computes trending search queries using time-decay bucket scoring.
 * Results are KV-cached with a 15-minute TTL.
 *
 * Scoring buckets (5-tier time decay):
 *   Last 1h: 4x | Last 6h: 2x | Last 24h: 1x | Last 7d: 0.5x | Older: 0.25x
 */
export class TrendingSearchService {
  constructor(private db: D1Database, private kv?: KVNamespace) {}

  /**
   * Get trending searches — returns from KV cache if available, otherwise computes.
   */
  async getTrending(limit = 10, periodDays = 7): Promise<TrendingSearchResult> {
    const cacheKey = `trending:${periodDays}d:${limit}`

    // Try KV cache first
    if (this.kv) {
      try {
        const cached = await this.kv.get(cacheKey, 'json')
        if (cached) {
          return { items: cached as TrendingSearch[], cached: true }
        }
      } catch {
        // KV read failed — compute fresh
      }
    }

    const items = await this.computeTrending(limit, periodDays)

    // Store in KV with 15-minute TTL
    if (this.kv) {
      try {
        await this.kv.put(cacheKey, JSON.stringify(items), { expirationTtl: 900 })
      } catch {
        // KV write failed — still return results
      }
    }

    return { items, cached: false }
  }

  /**
   * Compute trending searches using time-decay bucket scoring.
   * Precomputes all thresholds in TypeScript for clean parameter binding.
   */
  private async computeTrending(limit: number, periodDays: number): Promise<TrendingSearch[]> {
    const now = Date.now()
    const t1h = now - 3_600_000           // 1 hour ago
    const t6h = now - 21_600_000          // 6 hours ago
    const t24h = now - 86_400_000         // 24 hours ago
    const t7d = now - 604_800_000         // 7 days ago
    const lookback = now - (periodDays * 86_400_000) // period start

    try {
      const sql = `
        SELECT
          LOWER(query) as q,
          SUM(
            CASE
              WHEN created_at > ?1 THEN 4.0
              WHEN created_at > ?2 THEN 2.0
              WHEN created_at > ?3 THEN 1.0
              WHEN created_at > ?4 THEN 0.5
              ELSE 0.25
            END
          ) as trend_score,
          COUNT(*) as raw_count
        FROM ai_search_history
        WHERE created_at > ?5
          AND results_count > 0
          AND query IS NOT NULL
          AND LENGTH(TRIM(query)) >= 2
        GROUP BY LOWER(query)
        HAVING COUNT(*) >= 3
        ORDER BY trend_score DESC
        LIMIT ?6
      `
      // ?1=t1h, ?2=t6h, ?3=t24h, ?4=t7d, ?5=lookback, ?6=limit (fetch extra for post-filter)
      const fetchLimit = Math.min(limit * 2, 40)
      const { results } = await this.db
        .prepare(sql)
        .bind(t1h, t6h, t24h, t7d, lookback, fetchLimit)
        .all<{ q: string; trend_score: number; raw_count: number }>()

      if (!results || results.length === 0) return []

      // Post-filter garbage queries
      return results
        .filter((r) => this.isValidQuery(r.q))
        .slice(0, limit)
        .map((r) => ({
          query: r.q,
          trend_score: Math.round(r.trend_score * 100) / 100,
          search_count: r.raw_count,
        }))
    } catch (error) {
      console.log('[TrendingSearchService] Query failed:', error)
      return []
    }
  }

  /**
   * Post-filter: reject garbage queries that slip through SQL filters.
   */
  private isValidQuery(q: string): boolean {
    if (q.length < 3) return false
    if (q.length > 100) return false
    if (/^\d+$/.test(q)) return false
    if (/^[0-9a-f-]{8,}$/i.test(q)) return false
    return true
  }

  /**
   * Invalidate all trending KV cache keys.
   */
  async invalidateCache(): Promise<void> {
    if (!this.kv) return
    // KV doesn't support prefix deletion — invalidate common combinations
    const periods = [1, 7, 14, 30]
    const limits = [5, 10, 15, 20]
    const deletes = periods.flatMap((p) =>
      limits.map((l) => this.kv!.delete(`trending:${p}d:${l}`))
    )
    await Promise.allSettled(deletes)
  }
}
