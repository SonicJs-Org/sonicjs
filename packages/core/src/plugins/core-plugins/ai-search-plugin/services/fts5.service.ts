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

  constructor(
    private db: D1Database,
    options: FTS5SearchOptions = {}
  ) {
    this.options = { ...this.defaultOptions, ...options }
  }

  /**
   * Search using FTS5 with BM25 ranking and highlighting
   */
  async search(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      // Sanitize and prepare query for FTS5 MATCH
      const escapedQuery = this.sanitizeFTS5Query(query.query)

      if (!escapedQuery || escapedQuery === '""') {
        return {
          results: [],
          total: 0,
          query_time_ms: Date.now() - startTime,
          mode: 'fts5' as any
        }
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

      const collectionPlaceholders = collections.map(() => '?').join(', ')
      const tag = this.options.highlightTag || 'mark'

      // FTS5 query with BM25 ranking and field boosting
      // bm25 weights: title(5.0), slug(2.0), body(1.0), content_id(0), collection_id(0)
      const sql = `
        SELECT
          fts.content_id,
          fts.collection_id,
          fts.title,
          bm25(content_fts, ${this.options.titleBoost}, ${this.options.slugBoost}, ${this.options.bodyBoost}, 0, 0) as score,
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
          AND c.status = 'published'
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
          AND c.status = 'published'
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
   * Only indexes published content; removes non-published from index
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

      // Only index published content
      if (content.status !== 'published') {
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

      console.log(`[FTS5Service] Indexed content ${contentId}`)
    } catch (error) {
      console.error(`[FTS5Service] Error indexing ${contentId}:`, error)
      throw error
    }
  }

  /**
   * Index all published content in a collection
   */
  async indexCollection(collectionId: string): Promise<FTS5IndexResult> {
    console.log(`[FTS5Service] Starting indexing for collection: ${collectionId}`)

    try {
      // Get all published content from collection
      const { results } = await this.db
        .prepare(`
          SELECT id FROM content
          WHERE collection_id = ? AND status = 'published'
        `)
        .bind(collectionId)
        .all<{ id: string }>()

      const totalItems = results?.length || 0

      if (totalItems === 0) {
        console.log(`[FTS5Service] No published content found in collection ${collectionId}`)
        return { total_items: 0, indexed_items: 0, errors: 0 }
      }

      let indexedItems = 0
      let errors = 0

      for (const item of results || []) {
        try {
          await this.indexContent(item.id)
          indexedItems++
        } catch (error) {
          console.error(`[FTS5Service] Error indexing item ${item.id}:`, error)
          errors++
        }
      }

      console.log(`[FTS5Service] Indexing complete: ${indexedItems}/${totalItems} items, ${errors} errors`)

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
   * Sanitize user input for FTS5 MATCH clause
   * Removes operators and special characters that could cause errors
   */
  private sanitizeFTS5Query(query: string): string {
    if (!query || typeof query !== 'string') {
      return '""'
    }

    // Remove FTS5 special characters and operators
    let sanitized = query
      .replace(/['"]/g, '')              // Remove quotes
      .replace(/[()[\]{}]/g, '')         // Remove brackets
      .replace(/\b(AND|OR|NOT|NEAR)\b/gi, '') // Remove boolean operators
      .replace(/\*/g, '')                // Remove wildcards (we add them back)
      .replace(/:/g, '')                 // Remove column specifiers
      .replace(/\^/g, '')                // Remove boost operator
      .replace(/-/g, ' ')                // Convert hyphens to spaces
      .trim()

    // Split into terms and filter empty
    const terms = sanitized.split(/\s+/).filter(t => t.length > 0)

    if (terms.length === 0) {
      return '""'
    }

    // Single term: use prefix matching for autocomplete-like behavior
    if (terms.length === 1) {
      return `"${terms[0]}"*`
    }

    // Multiple terms: wrap each term with quotes for exact matching
    // and join with spaces (implicit AND)
    return terms.map(t => `"${t}"`).join(' ')
  }
}
