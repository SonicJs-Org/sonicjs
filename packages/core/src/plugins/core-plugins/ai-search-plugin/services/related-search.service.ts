import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import type { RelatedSearch, RelatedSearchResult } from '../types'

/**
 * Related Search Service
 *
 * Manages related search suggestions from three sources:
 * 1. Manual (admin-curated, highest priority)
 * 2. Agent (approved from Quality Agent recommendations)
 * 3. Auto (computed from click overlap + session co-occurrence, cached in KV)
 */
export class RelatedSearchService {
  constructor(private db: D1Database, private kv?: KVNamespace) {}

  // =============================================
  // Main Entry Point
  // =============================================

  /**
   * Get related searches for a query — merges manual + agent (D1) + auto (KV/compute).
   * Returns deduplicated results with manual first, then agent, then auto, up to limit.
   */
  async getRelatedSearches(query: string, limit = 5): Promise<RelatedSearchResult[]> {
    const normalized = this.normalize(query)
    if (!normalized) return []

    // 1. Get stored entries (manual + agent) from D1
    const stored = await this.getStoredRelated(normalized)
    const results: RelatedSearchResult[] = stored.map(r => ({
      query: r.related_query,
      source: r.source,
    }))

    // If we already have enough from stored entries, return early
    if (results.length >= limit) {
      return results.slice(0, limit)
    }

    // 2. Get auto-generated from KV cache or compute
    const remaining = limit - results.length
    const autoResults = await this.getAutoRelated(normalized, remaining, results)
    results.push(...autoResults)

    return results.slice(0, limit)
  }

  // =============================================
  // Stored Entries (Manual + Agent)
  // =============================================

  async getStoredRelated(normalizedQuery: string): Promise<RelatedSearch[]> {
    try {
      const { results } = await this.db
        .prepare(`
          SELECT * FROM ai_search_related
          WHERE source_query = ? AND enabled = 1
          ORDER BY
            CASE source WHEN 'manual' THEN 0 WHEN 'agent' THEN 1 END,
            position ASC
        `)
        .bind(normalizedQuery)
        .all()

      return (results || []).map(row => this.mapRow(row))
    } catch {
      return []
    }
  }

  // =============================================
  // Auto-Generated (Click Overlap + Session Co-occurrence)
  // =============================================

  private async getAutoRelated(
    normalizedQuery: string,
    limit: number,
    existingResults: RelatedSearchResult[]
  ): Promise<RelatedSearchResult[]> {
    if (!this.kv || limit <= 0) return []

    const cacheKey = `related:auto:${normalizedQuery}`

    // Check KV cache first
    try {
      const cached = await this.kv.get<RelatedSearchResult[]>(cacheKey, 'json')
      if (cached) {
        const existingQueries = new Set(existingResults.map(r => r.query.toLowerCase()))
        return cached
          .filter(r => !existingQueries.has(r.query.toLowerCase()))
          .slice(0, limit)
      }
    } catch {
      // Cache miss or error — compute fresh
    }

    // Check minimum data threshold
    const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000)
    try {
      const countRow = await this.db
        .prepare('SELECT COUNT(*) as cnt FROM ai_search_history WHERE created_at >= ?')
        .bind(thirtyDaysAgo)
        .first<{ cnt: number }>()

      if (!countRow || countRow.cnt < 100) return []
    } catch {
      return []
    }

    // Compute from click overlap and session co-occurrence
    const existingQueries = new Set(existingResults.map(r => r.query.toLowerCase()))
    const scoreMap = new Map<string, number>()

    // Signal A: Click overlap — queries that led to clicks on the same content
    try {
      const { results: clickRows } = await this.db
        .prepare(`
          WITH target_clicks AS (
            SELECT DISTINCT c.clicked_content_id
            FROM ai_search_clicks c
            JOIN ai_search_history h ON c.search_id = CAST(h.id AS TEXT)
            WHERE LOWER(h.query) = ?
              AND h.created_at >= ?
          ),
          related AS (
            SELECT LOWER(h.query) as related_query,
                   COUNT(DISTINCT c.clicked_content_id) as shared_clicks
            FROM ai_search_clicks c
            JOIN ai_search_history h ON c.search_id = CAST(h.id AS TEXT)
            JOIN target_clicks t ON c.clicked_content_id = t.clicked_content_id
            WHERE LOWER(h.query) != ?
              AND LENGTH(TRIM(h.query)) >= 2
              AND h.results_count > 0
            GROUP BY LOWER(h.query)
            HAVING shared_clicks >= 2
          )
          SELECT related_query, shared_clicks
          FROM related
          ORDER BY shared_clicks DESC
          LIMIT 20
        `)
        .bind(normalizedQuery, thirtyDaysAgo, normalizedQuery)
        .all<{ related_query: string; shared_clicks: number }>()

      for (const row of clickRows || []) {
        if (!existingQueries.has(row.related_query)) {
          scoreMap.set(row.related_query, (scoreMap.get(row.related_query) || 0) + row.shared_clicks)
        }
      }
    } catch (error) {
      console.warn('[RelatedSearchService] Click overlap query failed:', error)
    }

    // Signal B: Session co-occurrence (authenticated users only)
    try {
      const { results: sessionRows } = await this.db
        .prepare(`
          WITH target_searches AS (
            SELECT user_id, created_at
            FROM ai_search_history
            WHERE LOWER(query) = ?
              AND created_at >= ?
              AND results_count > 0
              AND user_id IS NOT NULL
          ),
          co_occurring AS (
            SELECT LOWER(h.query) as related_query, COUNT(*) as co_count
            FROM ai_search_history h
            JOIN target_searches t ON h.user_id = t.user_id
              AND ABS(h.created_at - t.created_at) <= 1800000
            WHERE LOWER(h.query) != ?
              AND h.results_count > 0
              AND h.user_id IS NOT NULL
              AND LENGTH(TRIM(h.query)) >= 2
            GROUP BY LOWER(h.query)
            HAVING co_count >= 2
          )
          SELECT related_query, co_count
          FROM co_occurring
          ORDER BY co_count DESC
          LIMIT 20
        `)
        .bind(normalizedQuery, thirtyDaysAgo, normalizedQuery)
        .all<{ related_query: string; co_count: number }>()

      for (const row of sessionRows || []) {
        if (!existingQueries.has(row.related_query)) {
          scoreMap.set(row.related_query, (scoreMap.get(row.related_query) || 0) + row.co_count)
        }
      }
    } catch (error) {
      console.warn('[RelatedSearchService] Session co-occurrence query failed:', error)
    }

    // Sort by combined score and build results
    const autoResults: RelatedSearchResult[] = Array.from(scoreMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit + 5) // Fetch extra in case of dedup
      .map(([query]) => ({ query, source: 'auto' as const }))

    // Cache in KV with 1-hour TTL
    try {
      await this.kv.put(cacheKey, JSON.stringify(autoResults), { expirationTtl: 3600 })
    } catch {
      // Non-critical cache write failure
    }

    return autoResults.slice(0, limit)
  }

  // =============================================
  // CRUD
  // =============================================

  async create(
    sourceQuery: string,
    relatedQuery: string,
    opts?: { source?: 'manual' | 'agent'; position?: number; bidirectional?: boolean }
  ): Promise<RelatedSearch> {
    const source = opts?.source || 'manual'
    const position = opts?.position ?? 0
    const bidirectional = opts?.bidirectional ? 1 : 0
    const normalizedSource = this.normalize(sourceQuery)
    const normalizedRelated = this.normalize(relatedQuery)

    const id = crypto.randomUUID().replace(/-/g, '')
    await this.db
      .prepare(`
        INSERT INTO ai_search_related (id, source_query, related_query, source, position, bidirectional, enabled)
        VALUES (?, ?, ?, ?, ?, ?, 1)
      `)
      .bind(id, normalizedSource, normalizedRelated, source, position, bidirectional)
      .run()

    // If bidirectional, create the reverse pair
    if (opts?.bidirectional) {
      const reverseId = crypto.randomUUID().replace(/-/g, '')
      try {
        await this.db
          .prepare(`
            INSERT INTO ai_search_related (id, source_query, related_query, source, position, bidirectional, enabled)
            VALUES (?, ?, ?, ?, ?, ?, 1)
          `)
          .bind(reverseId, normalizedRelated, normalizedSource, source, position, bidirectional)
          .run()
      } catch {
        // Reverse pair may already exist (UNIQUE constraint) — that's fine
      }
    }

    return {
      id,
      source_query: normalizedSource,
      related_query: normalizedRelated,
      source,
      position,
      bidirectional: !!opts?.bidirectional,
      enabled: true,
      created_at: Math.floor(Date.now() / 1000),
      updated_at: Math.floor(Date.now() / 1000),
    }
  }

  async update(id: string, fields: Partial<Pick<RelatedSearch, 'related_query' | 'position' | 'enabled'>>): Promise<RelatedSearch | null> {
    const setClauses: string[] = ['updated_at = unixepoch()']
    const params: any[] = []

    if (fields.related_query !== undefined) {
      setClauses.push('related_query = ?')
      params.push(this.normalize(fields.related_query))
    }
    if (fields.position !== undefined) {
      setClauses.push('position = ?')
      params.push(fields.position)
    }
    if (fields.enabled !== undefined) {
      setClauses.push('enabled = ?')
      params.push(fields.enabled ? 1 : 0)
    }

    params.push(id)
    await this.db
      .prepare(`UPDATE ai_search_related SET ${setClauses.join(', ')} WHERE id = ?`)
      .bind(...params)
      .run()

    return this.getById(id)
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.db
      .prepare('DELETE FROM ai_search_related WHERE id = ?')
      .bind(id)
      .run()

    return (result?.meta?.changes ?? 0) > 0
  }

  async getById(id: string): Promise<RelatedSearch | null> {
    try {
      const row = await this.db
        .prepare('SELECT * FROM ai_search_related WHERE id = ?')
        .bind(id)
        .first()

      return row ? this.mapRow(row) : null
    } catch {
      return null
    }
  }

  async getAll(opts?: {
    source_query?: string
    source?: 'manual' | 'agent'
    enabled?: boolean
    limit?: number
    offset?: number
  }): Promise<RelatedSearch[]> {
    const conditions: string[] = []
    const params: any[] = []

    if (opts?.source_query) {
      conditions.push('source_query = ?')
      params.push(this.normalize(opts.source_query))
    }
    if (opts?.source) {
      conditions.push('source = ?')
      params.push(opts.source)
    }
    if (opts?.enabled !== undefined) {
      conditions.push('enabled = ?')
      params.push(opts.enabled ? 1 : 0)
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
    const limit = opts?.limit || 100
    const offset = opts?.offset || 0

    try {
      const { results } = await this.db
        .prepare(`SELECT * FROM ai_search_related ${where} ORDER BY source_query ASC, position ASC LIMIT ? OFFSET ?`)
        .bind(...params, limit, offset)
        .all()

      return (results || []).map(row => this.mapRow(row))
    } catch {
      return []
    }
  }

  async bulkCreate(
    entries: Array<{ source_query: string; related_query: string; source?: 'manual' | 'agent'; position?: number; bidirectional?: boolean }>
  ): Promise<number> {
    let count = 0
    for (const entry of entries) {
      try {
        await this.create(entry.source_query, entry.related_query, {
          source: entry.source,
          position: entry.position,
          bidirectional: entry.bidirectional,
        })
        count++
      } catch {
        // Skip duplicates (UNIQUE constraint)
      }
    }
    return count
  }

  async invalidateCache(query?: string): Promise<void> {
    if (!this.kv) return

    if (query) {
      await this.kv.delete(`related:auto:${this.normalize(query)}`)
    } else {
      // KV doesn't support prefix deletion — list and delete
      try {
        const list = await this.kv.list({ prefix: 'related:auto:' })
        for (const key of list.keys) {
          await this.kv.delete(key.name)
        }
      } catch {
        // Best-effort cache clear
      }
    }
  }

  // =============================================
  // Helpers
  // =============================================

  private normalize(query: string): string {
    return query.toLowerCase().trim()
  }

  private mapRow(row: Record<string, unknown>): RelatedSearch {
    return {
      id: row.id as string,
      source_query: row.source_query as string,
      related_query: row.related_query as string,
      source: row.source as 'manual' | 'agent',
      position: row.position as number,
      bidirectional: (row.bidirectional as number) === 1,
      enabled: (row.enabled as number) === 1,
      created_at: row.created_at as number,
      updated_at: row.updated_at as number,
    }
  }
}
