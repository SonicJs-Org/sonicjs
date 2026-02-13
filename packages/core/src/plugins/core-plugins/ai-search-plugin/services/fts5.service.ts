/**
 * FTS5 Full-Text Search Service
 *
 * Provides BM25-ranked full-text search with:
 * - Porter stemming (running/runs/ran -> run)
 * - Diacritics/accent folding (cafe matches cafe)
 * - Field boosting (title 5x, slug 2x, body 1x)
 * - Highlighting with <mark> tags
 * - Snippet extraction around matches
 */

import type { D1Database } from '@cloudflare/workers-types'
import type { SearchQuery, SearchResult, SearchResponse, AISearchSettings } from '../types'
import type { SynonymService } from './synonym.service'

export interface FTS5SearchOptions {
  titleBoost?: number      // Default: 5.0
  slugBoost?: number       // Default: 2.0
  bodyBoost?: number       // Default: 1.0
  snippetLength?: number   // Default: 15 tokens (~150 chars)
  highlightTag?: string    // Default: 'mark'
}

export interface FTS5SearchResult extends SearchResult {
  highlights?: {
    title?: string
    body?: string
  }
  bm25_score?: number
}

export interface FTS5IndexResult {
  total_items: number
  indexed_items: number
  errors: number
}

export class FTS5Service {
  private defaultOptions: FTS5SearchOptions = {
    titleBoost: 5.0,
    slugBoost: 2.0,
    bodyBoost: 1.0,
    snippetLength: 15,  // ~15 tokens per snippet fragment
    highlightTag: 'mark'
  }

  private options: FTS5SearchOptions
  private synonymService?: SynonymService

  constructor(
    private db: D1Database,
    options: FTS5SearchOptions = {}
  ) {
    this.options = { ...this.defaultOptions, ...options }
  }

  /** Set synonym service for query expansion */
  setSynonymService(service: SynonymService): void {
    this.synonymService = service
  }

  /**
   * Search using FTS5 with BM25 ranking and highlighting
   * Auto-indexes any missing content in selected collections before searching
   */
  async search(
    query: SearchQuery,
    settings: AISearchSettings,
    weightOverrides?: { titleBoost?: number; slugBoost?: number; bodyBoost?: number }
  ): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      // Sanitize and prepare query for FTS5 MATCH
      let escapedQuery = this.sanitizeFTS5Query(query.query)

      if (!escapedQuery || escapedQuery === '""') {
        return {
          results: [],
          total: 0,
          query_time_ms: Date.now() - startTime,
          mode: 'fts5' as any
        }
      }

      // Synonym expansion: expand terms using admin-defined synonym groups
      if (this.synonymService && settings.query_synonyms_enabled !== false) {
        escapedQuery = await this.expandWithSynonyms(escapedQuery)
      }

      // Build collection filter
      const collections = query.filters?.collections?.length
        ? query.filters.collections
        : settings.selected_collections

      if (collections.length === 0) {
        return {
          results: [],
          total: 0,
          query_time_ms: Date.now() - startTime,
          mode: 'fts5' as any
        }
      }

      // Auto-index any content not yet in the FTS5 index
      await this.ensureCollectionsIndexed(collections)

      const collectionPlaceholders = collections.map(() => '?').join(', ')
      const tag = this.options.highlightTag || 'mark'

      // Effective weights: overrides (from settings) > constructor options > defaults
      const titleBoost = weightOverrides?.titleBoost ?? this.options.titleBoost
      const slugBoost = weightOverrides?.slugBoost ?? this.options.slugBoost
      const bodyBoost = weightOverrides?.bodyBoost ?? this.options.bodyBoost

      // FTS5 query with BM25 ranking and field boosting
      // bm25 weights: title, slug, body, content_id(0), collection_id(0)
      const sql = `
        SELECT
          fts.content_id,
          fts.collection_id,
          fts.title,
          bm25(content_fts, ${titleBoost}, ${slugBoost}, ${bodyBoost}, 0, 0) as score,
          snippet(content_fts, 2, '<${tag}>', '</${tag}>', '...', ${this.options.snippetLength}) as body_snippet,
          highlight(content_fts, 0, '<${tag}>', '</${tag}>') as title_highlight,
          c.slug,
          c.status,
          c.created_at,
          c.updated_at,
          col.display_name as collection_name
        FROM content_fts fts
        JOIN content c ON fts.content_id = c.id
        JOIN collections col ON fts.collection_id = col.id
        WHERE content_fts MATCH ?
          AND fts.collection_id IN (${collectionPlaceholders})
          AND c.status != 'deleted'
        ORDER BY score
        LIMIT ? OFFSET ?
      `

      const limit = query.limit || settings.results_limit || 20
      const offset = query.offset || 0

      const { results } = await this.db
        .prepare(sql)
        .bind(escapedQuery, ...collections, limit, offset)
        .all<{
          content_id: string
          collection_id: string
          title: string
          score: number
          body_snippet: string
          title_highlight: string
          slug: string
          status: string
          created_at: number
          updated_at: number
          collection_name: string
        }>()

      // Get total count (separate query for efficiency)
      const countSql = `
        SELECT COUNT(*) as total
        FROM content_fts fts
        JOIN content c ON fts.content_id = c.id
        WHERE content_fts MATCH ?
          AND fts.collection_id IN (${collectionPlaceholders})
          AND c.status != 'deleted'
      `
      const countResult = await this.db
        .prepare(countSql)
        .bind(escapedQuery, ...collections)
        .first<{ total: number }>()

      // Map results with highlighting
      const searchResults: FTS5SearchResult[] = (results || []).map(row => ({
        id: row.content_id,
        title: row.title,
        slug: row.slug,
        collection_id: row.collection_id,
        collection_name: row.collection_name,
        snippet: row.body_snippet,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
        highlights: {
          title: row.title_highlight,
          body: row.body_snippet
        },
        // BM25 returns negative scores (more negative = better match)
        // Convert to positive for display
        bm25_score: Math.abs(row.score),
        relevance_score: Math.abs(row.score)
      }))

      const queryTime = Date.now() - startTime
      console.log(`[FTS5Service] Search completed in ${queryTime}ms, ${searchResults.length} results`)

      return {
        results: searchResults,
        total: countResult?.total || 0,
        query_time_ms: queryTime,
        mode: 'fts5' as any
      }
    } catch (error) {
      console.error('[FTS5Service] Search error:', error)
      throw error
    }
  }

  /**
   * Index a single content item
   * Indexes all non-deleted content; removes deleted content from index
   */
  async indexContent(contentId: string): Promise<void> {
    try {
      // Get content with collection info
      const content = await this.db
        .prepare(`
          SELECT c.id, c.collection_id, c.title, c.slug, c.data, c.status
          FROM content c
          WHERE c.id = ?
        `)
        .bind(contentId)
        .first<{
          id: string
          collection_id: string
          title: string
          slug: string
          data: string
          status: string
        }>()

      if (!content) {
        console.warn(`[FTS5Service] Content ${contentId} not found`)
        return
      }

      // Skip deleted content
      if (content.status === 'deleted') {
        await this.removeFromIndex(contentId)
        return
      }

      // Extract searchable text from JSON data
      const bodyText = this.extractSearchableText(content.data)

      // Atomic update: delete then insert (handles race conditions)
      await this.db.batch([
        this.db.prepare('DELETE FROM content_fts WHERE content_id = ?').bind(contentId),
        this.db.prepare(`
          INSERT INTO content_fts(title, slug, body, content_id, collection_id)
          VALUES (?, ?, ?, ?, ?)
        `).bind(
          content.title || '',
          content.slug || '',
          bodyText,
          content.id,
          content.collection_id
        ),
        this.db.prepare(`
          INSERT OR REPLACE INTO content_fts_sync(content_id, collection_id, indexed_at, status)
          VALUES (?, ?, ?, 'indexed')
        `).bind(contentId, content.collection_id, Date.now())
      ])

      // Per-item logging omitted for bulk performance
    } catch (error) {
      console.error(`[FTS5Service] Error indexing ${contentId}:`, error)
      throw error
    }
  }

  /**
   * Index all published content in a collection (bulk approach).
   * Fetches all content in one query, processes text in memory,
   * then inserts in D1 batches for efficiency.
   */
  async indexCollection(
    collectionId: string,
    onProgress?: (indexed: number, total: number) => Promise<void>
  ): Promise<FTS5IndexResult> {
    console.log(`[FTS5Service] Starting bulk indexing for collection: ${collectionId}`)

    try {
      // Fetch all content with data in one query
      const { results } = await this.db
        .prepare(`
          SELECT id, title, slug, data, collection_id
          FROM content
          WHERE collection_id = ? AND status != 'deleted'
        `)
        .bind(collectionId)
        .all<{ id: string; title: string; slug: string; data: string; collection_id: string }>()

      const totalItems = results?.length || 0

      if (totalItems === 0) {
        console.log(`[FTS5Service] No content found in collection ${collectionId}`)
        if (onProgress) await onProgress(0, 0)
        return { total_items: 0, indexed_items: 0, errors: 0 }
      }

      // Clear existing FTS5 + sync entries for this collection (clean slate)
      await this.db.batch([
        this.db.prepare('DELETE FROM content_fts WHERE collection_id = ?').bind(collectionId),
        this.db.prepare('DELETE FROM content_fts_sync WHERE collection_id = ?').bind(collectionId),
      ])

      let indexedItems = 0
      let errors = 0
      const now = Date.now()

      // Process in batches of 25 items (50 statements per batch: INSERT fts + INSERT sync)
      const BATCH_SIZE = 25
      for (let i = 0; i < totalItems; i += BATCH_SIZE) {
        const batch = results!.slice(i, i + BATCH_SIZE)
        const statements: any[] = []

        for (const item of batch) {
          try {
            const bodyText = this.extractSearchableText(item.data)
            statements.push(
              this.db.prepare(`
                INSERT INTO content_fts(title, slug, body, content_id, collection_id)
                VALUES (?, ?, ?, ?, ?)
              `).bind(item.title || '', item.slug || '', bodyText, item.id, item.collection_id)
            )
            statements.push(
              this.db.prepare(`
                INSERT OR REPLACE INTO content_fts_sync(content_id, collection_id, indexed_at, status)
                VALUES (?, ?, ?, 'indexed')
              `).bind(item.id, item.collection_id, now)
            )
          } catch (error) {
            errors++
          }
        }

        if (statements.length > 0) {
          try {
            await this.db.batch(statements)
            indexedItems += statements.length / 2 // 2 statements per item
          } catch (error) {
            console.error(`[FTS5Service] Batch insert error at offset ${i}:`, error)
            errors += batch.length
          }
        }

        // Report progress every batch
        if (onProgress) {
          await onProgress(indexedItems, totalItems)
        }
      }

      console.log(`[FTS5Service] Bulk indexing complete: ${indexedItems}/${totalItems} items, ${errors} errors`)

      return {
        total_items: totalItems,
        indexed_items: indexedItems,
        errors
      }
    } catch (error) {
      console.error(`[FTS5Service] Error indexing collection ${collectionId}:`, error)
      throw error
    }
  }

  /**
   * Index a batch of content items from a collection using batch D1 inserts.
   * Returns the number remaining so the caller can loop.
   */
  async indexCollectionBatch(
    collectionId: string,
    batchSize: number = 200
  ): Promise<{ indexed: number; remaining: number; total: number }> {
    // Find un-indexed content with data for FTS5 extraction
    const { results } = await this.db
      .prepare(`
        SELECT c.id, c.title, c.slug, c.data, c.collection_id
        FROM content c
        LEFT JOIN content_fts_sync s ON c.id = s.content_id
        WHERE c.collection_id = ? AND c.status != 'deleted'
          AND s.content_id IS NULL
        LIMIT ?
      `)
      .bind(collectionId, batchSize)
      .all<{ id: string; title: string; slug: string; data: string; collection_id: string }>()

    const toIndex = results || []
    const now = Date.now()
    let indexed = 0

    // Process in sub-batches of 25 (50 D1 statements: FTS5 INSERT + sync INSERT)
    const SUB_BATCH = 25
    for (let i = 0; i < toIndex.length; i += SUB_BATCH) {
      const batch = toIndex.slice(i, i + SUB_BATCH)
      const statements: any[] = []

      for (const item of batch) {
        try {
          const bodyText = this.extractSearchableText(item.data)
          statements.push(
            this.db.prepare(
              'INSERT INTO content_fts(title, slug, body, content_id, collection_id) VALUES (?, ?, ?, ?, ?)'
            ).bind(item.title || '', item.slug || '', bodyText, item.id, item.collection_id)
          )
          statements.push(
            this.db.prepare(
              "INSERT OR REPLACE INTO content_fts_sync(content_id, collection_id, indexed_at, status) VALUES (?, ?, ?, 'indexed')"
            ).bind(item.id, item.collection_id, now)
          )
        } catch (error) {
          // Skip items with extraction errors
        }
      }

      if (statements.length > 0) {
        try {
          await this.db.batch(statements)
          indexed += statements.length / 2
        } catch (error) {
          console.error(`[FTS5Service] Batch insert error at offset ${i}:`, error)
        }
      }
    }

    // Count remaining
    const remainResult = await this.db
      .prepare(`
        SELECT COUNT(*) as cnt FROM content c
        LEFT JOIN content_fts_sync s ON c.id = s.content_id
        WHERE c.collection_id = ? AND c.status != 'deleted'
          AND s.content_id IS NULL
      `)
      .bind(collectionId)
      .first<{ cnt: number }>()

    const totalResult = await this.db
      .prepare("SELECT COUNT(*) as cnt FROM content WHERE collection_id = ? AND status != 'deleted'")
      .bind(collectionId)
      .first<{ cnt: number }>()

    return {
      indexed,
      remaining: remainResult?.cnt || 0,
      total: totalResult?.cnt || 0,
    }
  }

  /**
   * Remove content from FTS index
   */
  async removeFromIndex(contentId: string): Promise<void> {
    try {
      await this.db.batch([
        this.db.prepare('DELETE FROM content_fts WHERE content_id = ?').bind(contentId),
        this.db.prepare('DELETE FROM content_fts_sync WHERE content_id = ?').bind(contentId)
      ])
      console.log(`[FTS5Service] Removed content ${contentId} from index`)
    } catch (error) {
      console.error(`[FTS5Service] Error removing ${contentId}:`, error)
      throw error
    }
  }

  /**
   * Process pending sync items (for deferred/batch indexing)
   */
  async processPendingSync(batchSize: number = 100): Promise<number> {
    const { results } = await this.db
      .prepare(`
        SELECT content_id FROM content_fts_sync
        WHERE status = 'pending'
        LIMIT ?
      `)
      .bind(batchSize)
      .all<{ content_id: string }>()

    let processed = 0
    for (const item of results || []) {
      try {
        await this.indexContent(item.content_id)
        processed++
      } catch (error) {
        console.error(`[FTS5Service] Error processing pending item ${item.content_id}:`, error)
      }
    }

    return processed
  }

  /**
   * Get FTS5 index statistics
   */
  async getStats(): Promise<{
    total_indexed: number
    by_collection: Record<string, number>
  }> {
    try {
      const totalResult = await this.db
        .prepare('SELECT COUNT(*) as count FROM content_fts')
        .first<{ count: number }>()

      const { results: collectionCounts } = await this.db
        .prepare(`
          SELECT collection_id, COUNT(*) as count
          FROM content_fts
          GROUP BY collection_id
        `)
        .all<{ collection_id: string; count: number }>()

      const byCollection: Record<string, number> = {}
      for (const row of collectionCounts || []) {
        byCollection[row.collection_id] = row.count
      }

      return {
        total_indexed: totalResult?.count || 0,
        by_collection: byCollection
      }
    } catch (error) {
      console.error('[FTS5Service] Error getting stats:', error)
      return { total_indexed: 0, by_collection: {} }
    }
  }

  /**
   * Check if FTS5 table is available
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.db.prepare('SELECT * FROM content_fts LIMIT 0').run()
      return true
    } catch {
      return false
    }
  }

  /**
   * Auto-index content in selected collections that isn't yet in the FTS5 index.
   * This makes FTS5 self-healing - existing content that predates the FTS5 feature
   * gets indexed on first search, so results match keyword search coverage.
   */
  private async ensureCollectionsIndexed(collections: string[]): Promise<void> {
    try {
      const collectionPlaceholders = collections.map(() => '?').join(', ')

      // Find content in selected collections that's not yet indexed
      const { results } = await this.db
        .prepare(`
          SELECT c.id FROM content c
          LEFT JOIN content_fts_sync s ON c.id = s.content_id
          WHERE c.collection_id IN (${collectionPlaceholders})
            AND c.status != 'deleted'
            AND s.content_id IS NULL
          LIMIT 200
        `)
        .bind(...collections)
        .all<{ id: string }>()

      if (!results || results.length === 0) {
        return
      }

      console.log(`[FTS5Service] Auto-indexing ${results.length} unindexed items`)

      let indexed = 0
      for (const item of results) {
        try {
          await this.indexContent(item.id)
          indexed++
        } catch (error) {
          console.error(`[FTS5Service] Error auto-indexing ${item.id}:`, error)
        }
      }

      console.log(`[FTS5Service] Auto-indexed ${indexed}/${results.length} items`)
    } catch (error) {
      // Don't fail the search if auto-indexing fails
      console.error('[FTS5Service] Error during auto-indexing:', error)
    }
  }

  /**
   * Extract searchable text from JSON content data
   * Reuses logic pattern from ChunkingService
   */
  private extractSearchableText(data: string): string {
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data
      const parts: string[] = []

      // Common text fields (in priority order)
      if (parsed.description) parts.push(String(parsed.description))
      if (parsed.content) parts.push(String(parsed.content))
      if (parsed.body) parts.push(String(parsed.body))
      if (parsed.text) parts.push(String(parsed.text))
      if (parsed.summary) parts.push(String(parsed.summary))
      if (parsed.excerpt) parts.push(String(parsed.excerpt))

      // Recursively extract from nested objects
      const extractRecursive = (obj: any, depth: number = 0): void => {
        // Limit recursion depth to avoid deep nesting issues
        if (depth > 5) return

        if (typeof obj === 'string') {
          // Skip very short strings, URLs, and likely IDs
          if (obj.length > 20 && !obj.startsWith('http') && !obj.match(/^[a-f0-9-]{36}$/i)) {
            parts.push(obj)
          }
        } else if (Array.isArray(obj)) {
          obj.forEach(item => extractRecursive(item, depth + 1))
        } else if (obj && typeof obj === 'object') {
          // Skip certain keys that don't contain searchable content
          const skipKeys = new Set([
            'id', '_id', 'slug', 'url', 'href', 'src',
            'image', 'thumbnail', 'avatar', 'icon', 'logo',
            'metadata', 'meta', 'created_at', 'updated_at',
            'author_id', 'collection_id', 'parent_id'
          ])

          Object.entries(obj).forEach(([key, value]) => {
            if (!skipKeys.has(key.toLowerCase())) {
              extractRecursive(value, depth + 1)
            }
          })
        }
      }

      extractRecursive(parsed)

      // Join with spaces, deduplicate, and trim
      const combined = parts.join(' ').trim()

      // Remove excessive whitespace
      return combined.replace(/\s+/g, ' ')
    } catch (error) {
      console.error('[FTS5Service] Error extracting text:', error)
      return ''
    }
  }

  /**
   * Expand a sanitized FTS5 query string with synonym terms.
   * Input: "coffee*" (single) or "coffee OR beans" (multiple)
   * Output: "coffee* OR espresso OR caffeine" or "coffee OR espresso OR beans"
   */
  private async expandWithSynonyms(sanitizedQuery: string): Promise<string> {
    try {
      let terms: string[]
      let hasPrefixMatch = false

      if (sanitizedQuery.endsWith('*')) {
        terms = [sanitizedQuery.slice(0, -1)]
        hasPrefixMatch = true
      } else {
        terms = sanitizedQuery.split(' OR ').map(t => t.trim()).filter(Boolean)
      }

      if (terms.length === 0) return sanitizedQuery

      const expanded = await this.synonymService!.expandQuery(terms)

      // No new terms added
      if (expanded.length === terms.length) return sanitizedQuery

      // Cap at 20 terms for safety
      const capped = expanded.slice(0, 20)

      if (hasPrefixMatch && terms.length === 1) {
        // Keep prefix on original term, synonyms are exact
        const original = terms[0] + '*'
        const synonyms = capped.filter(t => t !== terms[0])
        return [original, ...synonyms].join(' OR ')
      }

      return capped.join(' OR ')
    } catch (error) {
      console.error('[FTS5Service] Synonym expansion error (using original query):', error)
      return sanitizedQuery
    }
  }

  /**
   * Sanitize user input for FTS5 MATCH clause
   * Removes operators and special characters that could cause errors
   */
  private sanitizeFTS5Query(query: string): string {
    if (!query || typeof query !== 'string') {
      return '""'
    }

    // Step 1: Strip everything except letters, numbers, spaces, and hyphens
    let sanitized = query
      .replace(/-/g, ' ')                // Convert hyphens to spaces first
      .replace(/[^a-zA-Z0-9\s]/g, '')   // Strip all punctuation/special chars
      .replace(/\s+/g, ' ')             // Collapse whitespace
      .trim()
      .toLowerCase()

    // Step 2: Split into terms, filter short/stop words
    const stopWords = new Set(['a', 'an', 'the', 'is', 'are', 'was', 'were', 'be',
      'to', 'of', 'in', 'on', 'at', 'by', 'or', 'and', 'not', 'for', 'it',
      'as', 'do', 'if', 'no', 'so', 'up', 'but', 'its', 'has', 'had', 'near'])
    const terms = sanitized
      .split(/\s+/)
      .filter(t => t.length > 1 && !stopWords.has(t))

    if (terms.length === 0) {
      return '""'
    }

    // Single term: use prefix matching for autocomplete-like behavior
    if (terms.length === 1) {
      return `${terms[0]}*`
    }

    // Multiple terms: unquoted with OR for proper BM25 ranking
    // Unquoted terms enable porter stemming (running→run, properties→property)
    // OR means any matching term contributes to BM25 score — more matches rank higher
    return terms.join(' OR ')
  }
}
