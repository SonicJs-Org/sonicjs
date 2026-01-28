import type { D1Database } from '@cloudflare/workers-types'
import type {
  AISearchSettings,
  CollectionInfo,
  NewCollectionNotification,
  SearchQuery,
  SearchResponse,
  SearchResult,
} from '../types'
import { CustomRAGService } from './custom-rag.service'

/**
 * AI Search Service
 * Handles search operations, settings management, and collection detection
 * Now uses Custom RAG with Vectorize for semantic search
 */
export class AISearchService {
  private customRAG?: CustomRAGService

  constructor(
    private db: D1Database,
    private ai?: any, // Workers AI for embeddings
    private vectorize?: any // Vectorize for vector search
  ) {
    // Initialize Custom RAG if bindings are available
    if (this.ai && this.vectorize) {
      this.customRAG = new CustomRAGService(db, ai, vectorize)
      console.log('[AISearchService] Custom RAG initialized')
    } else {
      console.log('[AISearchService] Custom RAG not available, using keyword search only')
    }
  }

  /**
   * Get plugin settings
   */
  async getSettings(): Promise<AISearchSettings | null> {
    try {
      const plugin = await this.db
        .prepare(`SELECT settings FROM plugins WHERE id = ? LIMIT 1`)
        .bind('ai-search')
        .first<{ settings: string | null }>()

      if (!plugin || !plugin.settings) {
        return this.getDefaultSettings()
      }

      return JSON.parse(plugin.settings) as AISearchSettings
    } catch (error) {
      console.error('Error fetching AI Search settings:', error)
      return this.getDefaultSettings()
    }
  }

  /**
   * Get default settings
   */
  getDefaultSettings(): AISearchSettings {
    return {
      enabled: true,
      ai_mode_enabled: true,
      selected_collections: [],
      dismissed_collections: [],
      autocomplete_enabled: true,
      cache_duration: 1,
      results_limit: 20,
      index_media: false,
    }
  }

  /**
   * Update plugin settings
   */
  async updateSettings(settings: Partial<AISearchSettings>): Promise<AISearchSettings> {
    const existing = await this.getSettings()
    const updated: AISearchSettings = {
      ...existing!,
      ...settings,
    }

    try {
      // Update plugin settings in plugins table
      await this.db
        .prepare(`
          UPDATE plugins
          SET settings = ?,
              updated_at = unixepoch()
          WHERE id = 'ai-search'
        `)
        .bind(JSON.stringify(updated))
        .run()

      return updated
    } catch (error) {
      console.error('Error updating AI Search settings:', error)
      throw error
    }
  }

  /**
   * Detect new collections that aren't indexed or dismissed
   */
  async detectNewCollections(): Promise<NewCollectionNotification[]> {
    try {
      // Get all collections (exclude test collections)
      // Note: D1 doesn't support parameterized LIKE, so we filter in JavaScript
      const collectionsStmt = this.db.prepare(
        'SELECT id, name, display_name, description FROM collections WHERE is_active = 1'
      )
      const { results: allCollections } = await collectionsStmt.all<{
        id: number
        name: string
        display_name: string
        description?: string
      }>()

      // Filter out test collections (starts with test_, ends with _test, or is test_collection)
      const collections = (allCollections || []).filter(
        (col) => {
          if (!col.name) return false
          const name = col.name.toLowerCase()
          return !name.startsWith('test_') &&
            !name.endsWith('_test') &&
            name !== 'test_collection' &&
            !name.includes('_test_') &&
            name !== 'large_payload_test' &&
            name !== 'concurrent_test'
        }
      )

      // Get settings
      const settings = await this.getSettings()
      const selected = settings?.selected_collections || []
      const dismissed = settings?.dismissed_collections || []

      // Get item counts for each collection
      const notifications: NewCollectionNotification[] = []

      for (const collection of collections || []) {
        const collectionId = String(collection.id)

        // Skip if already selected or dismissed
        if (selected.includes(collectionId) || dismissed.includes(collectionId)) {
          continue
        }

        // Get item count
        const countStmt = this.db.prepare(
          'SELECT COUNT(*) as count FROM content WHERE collection_id = ?'
        )
        const countResult = await countStmt.bind(collectionId).first<{ count: number }>()
        const itemCount = countResult?.count || 0

        notifications.push({
          collection: {
            id: collectionId,
            name: collection.name,
            display_name: collection.display_name,
            description: collection.description,
            item_count: itemCount,
            is_indexed: false,
            is_dismissed: false,
            is_new: true,
          },
          message: `New collection "${collection.display_name}" with ${itemCount} items available for indexing`,
        })
      }

      return notifications
    } catch (error) {
      console.error('Error detecting new collections:', error)
      return []
    }
  }

  /**
   * Get all collections with indexing status
   */
  async getAllCollections(): Promise<CollectionInfo[]> {
    try {
      // Get all collections (same query as content page)
      const collectionsStmt = this.db.prepare(
        'SELECT id, name, display_name, description FROM collections WHERE is_active = 1 ORDER BY display_name'
      )
      const { results: allCollections } = await collectionsStmt.all<{
        id: string
        name: string
        display_name: string
        description?: string
      }>()

      console.log('[AISearchService.getAllCollections] Raw collections from DB:', allCollections?.length || 0)
      const firstCollection = allCollections?.[0]
      if (firstCollection) {
        console.log('[AISearchService.getAllCollections] Sample collection:', {
          id: firstCollection.id,
          name: firstCollection.name,
          display_name: firstCollection.display_name
        })
      }

      // No filtering needed - test collections are now properly cleaned up by E2E tests
      const collections = (allCollections || []).filter(
        (col) => col.id && col.name
      )

      console.log('[AISearchService.getAllCollections] After filtering test collections:', collections.length)
      console.log('[AISearchService.getAllCollections] Remaining collections:', collections.map(c => c.name).join(', '))

      // Get settings
      const settings = await this.getSettings()
      const selected = settings?.selected_collections || []
      const dismissed = settings?.dismissed_collections || []

      console.log('[AISearchService.getAllCollections] Settings:', {
        selected_count: selected.length,
        dismissed_count: dismissed.length,
        selected: selected
      })

      // Get item counts and indexing status
      const collectionInfos: CollectionInfo[] = []

      for (const collection of collections) {
        if (!collection.id || !collection.name) continue
        const collectionId = String(collection.id)

        if (!collectionId) {
          console.warn('[AISearchService] Skipping invalid collection:', collection)
          continue
        }

        // Get item count
        const countStmt = this.db.prepare(
          'SELECT COUNT(*) as count FROM content WHERE collection_id = ?'
        )
        const countResult = await countStmt.bind(collectionId).first<{ count: number }>()
        const itemCount = countResult?.count || 0

        collectionInfos.push({
          id: collectionId,
          name: collection.name,
          display_name: collection.display_name || collection.name,
          description: collection.description,
          item_count: itemCount,
          is_indexed: selected.includes(collectionId),
          is_dismissed: dismissed.includes(collectionId),
          is_new: !selected.includes(collectionId) && !dismissed.includes(collectionId),
        })
      }

      console.log('[AISearchService.getAllCollections] Returning collectionInfos:', collectionInfos.length)
      const firstInfo = collectionInfos[0]
      if (collectionInfos.length > 0 && firstInfo) {
        console.log('[AISearchService.getAllCollections] First collectionInfo:', {
          id: firstInfo.id,
          name: firstInfo.name,
          display_name: firstInfo.display_name,
          item_count: firstInfo.item_count
        })
      }
      return collectionInfos
    } catch (error) {
      console.error('[AISearchService] Error fetching collections:', error)
      return []
    }
  }

  /**
   * Execute search query
   */
  async search(query: SearchQuery): Promise<SearchResponse> {
    const startTime = Date.now()
    const settings = await this.getSettings()

    if (!settings?.enabled) {
      return {
        results: [],
        total: 0,
        query_time_ms: 0,
        mode: query.mode,
      }
    }

    // Use AI Search if enabled and mode is 'ai'
    if (query.mode === 'ai' && settings.ai_mode_enabled && this.customRAG?.isAvailable()) {
      return this.searchAI(query, settings)
    }

    // Fallback to keyword search
    return this.searchKeyword(query, settings)
  }

  /**
   * AI-powered semantic search using Custom RAG
   */
  private async searchAI(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      if (!this.customRAG) {
        console.warn('[AISearchService] CustomRAG not available, falling back to keyword search')
        return this.searchKeyword(query, settings)
      }

      // Use Custom RAG for semantic search - pass the full query object and settings
      const result = await this.customRAG.search(query, settings)

      return result
    } catch (error) {
      console.error('[AISearchService] AI search error, falling back to keyword:', error)
      // Fallback to keyword search
      return this.searchKeyword(query, settings)
    }
  }

  /**
   * Traditional keyword search
   */
  private async searchKeyword(
    query: SearchQuery,
    settings: AISearchSettings
  ): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      const conditions: string[] = []
      const params: any[] = []

      // Search query
      if (query.query) {
        conditions.push('(c.title LIKE ? OR c.slug LIKE ? OR c.data LIKE ?)')
        const searchTerm = `%${query.query}%`
        params.push(searchTerm, searchTerm, searchTerm)
      }

      // Collection filter
      if (query.filters?.collections && query.filters.collections.length > 0) {
        const placeholders = query.filters.collections.map(() => '?').join(',')
        conditions.push(`c.collection_id IN (${placeholders})`)
        params.push(...query.filters.collections)
      } else if (settings.selected_collections.length > 0) {
        // Only search indexed collections
        const placeholders = settings.selected_collections.map(() => '?').join(',')
        conditions.push(`c.collection_id IN (${placeholders})`)
        params.push(...settings.selected_collections)
      }

      // Status filter
      if (query.filters?.status && query.filters.status.length > 0) {
        const placeholders = query.filters.status.map(() => '?').join(',')
        conditions.push(`c.status IN (${placeholders})`)
        params.push(...query.filters.status)
      } else {
        // Exclude deleted by default
        conditions.push("c.status != 'deleted'")
      }

      // Date range filter
      if (query.filters?.dateRange) {
        const field = query.filters.dateRange.field || 'created_at'
        if (query.filters.dateRange.start) {
          conditions.push(`c.${field} >= ?`)
          params.push(query.filters.dateRange.start.getTime())
        }
        if (query.filters.dateRange.end) {
          conditions.push(`c.${field} <= ?`)
          params.push(query.filters.dateRange.end.getTime())
        }
      }

      // Author filter
      if (query.filters?.author) {
        conditions.push('c.author_id = ?')
        params.push(query.filters.author)
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

      // Get total count
      const countStmt = this.db.prepare(`
        SELECT COUNT(*) as count 
        FROM content c
        ${whereClause}
      `)
      const countResult = await countStmt.bind(...params).first<{ count: number }>()
      const total = countResult?.count || 0

      // Get results
      const limit = query.limit || settings.results_limit
      const offset = query.offset || 0

      const resultsStmt = this.db.prepare(`
        SELECT 
          c.id, c.title, c.slug, c.collection_id, c.status,
          c.created_at, c.updated_at, c.author_id, c.data,
          col.name as collection_name, col.display_name as collection_display_name,
          u.email as author_email
        FROM content c
        JOIN collections col ON c.collection_id = col.id
        LEFT JOIN users u ON c.author_id = u.id
        ${whereClause}
        ORDER BY c.updated_at DESC
        LIMIT ? OFFSET ?
      `)

      const { results } = await resultsStmt.bind(...params, limit, offset).all<{
        id: string
        title: string
        slug: string
        collection_id: number
        collection_name: string
        collection_display_name: string
        status: string
        created_at: number
        updated_at: number
        author_id?: string
        author_email?: string
        data: string
      }>()

      const searchResults: SearchResult[] = (results || []).map((row) => ({
        id: String(row.id),
        title: row.title || 'Untitled',
        slug: row.slug || '',
        collection_id: String(row.collection_id),
        collection_name: row.collection_display_name || row.collection_name,
        snippet: this.extractSnippet(row.data, query.query),
        status: row.status,
        created_at: Number(row.created_at),
        updated_at: Number(row.updated_at),
        author_name: row.author_email,
      }))

      const queryTime = Date.now() - startTime

      // Log search history
      await this.logSearch(query.query, query.mode, searchResults.length)

      return {
        results: searchResults,
        total,
        query_time_ms: queryTime,
        mode: query.mode,
      }
    } catch (error) {
      console.error('Keyword search error:', error)
      return {
        results: [],
        total: 0,
        query_time_ms: Date.now() - startTime,
        mode: query.mode,
      }
    }
  }

  /**
   * Extract snippet from content data
   */
  private extractSnippet(data: string, query: string): string {
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data
      const text = JSON.stringify(parsed).toLowerCase()
      const queryLower = query.toLowerCase()

      const index = text.indexOf(queryLower)
      if (index === -1) {
        // Return first 200 chars
        return JSON.stringify(parsed).substring(0, 200) + '...'
      }

      // Extract context around match
      const start = Math.max(0, index - 50)
      const end = Math.min(text.length, index + query.length + 50)
      return text.substring(start, end) + '...'
    } catch {
      return data.substring(0, 200) + '...'
    }
  }

  /**
   * Get search suggestions (autocomplete)
   * Uses fast keyword prefix matching for instant results (<50ms)
   */
  async getSearchSuggestions(partial: string): Promise<string[]> {
    try {
      const settings = await this.getSettings()
      if (!settings?.autocomplete_enabled) {
        return []
      }

      // Fast keyword prefix matching from indexed content
      // This provides instant autocomplete (<50ms) without AI overhead
      try {
        const stmt = this.db.prepare(`
          SELECT DISTINCT title 
          FROM ai_search_index 
          WHERE title LIKE ? 
          ORDER BY title 
          LIMIT 10
        `)
        const { results } = await stmt.bind(`%${partial}%`).all<{ title: string }>()

        const suggestions = (results || []).map((r) => r.title).filter(Boolean)

        if (suggestions.length > 0) {
          return suggestions
        }
      } catch (indexError) {
        // Table doesn't exist yet or is empty - that's okay, fall back to history
        console.log('[AISearchService] Index table not available yet, using search history')
      }

      // Fallback to search history if no indexed titles match
      try {
        const historyStmt = this.db.prepare(`
          SELECT DISTINCT query 
          FROM ai_search_history 
          WHERE query LIKE ? 
          ORDER BY created_at DESC 
          LIMIT 10
        `)
        const { results: historyResults } = await historyStmt.bind(`%${partial}%`).all<{ query: string }>()

        return (historyResults || []).map((r) => r.query)
      } catch (historyError) {
        // History table might not exist either - return empty
        console.log('[AISearchService] No suggestions available (tables not initialized)')
        return []
      }
    } catch (error) {
      console.error('Error getting suggestions:', error)
      return []
    }
  }

  /**
   * Log search query to history
   */
  private async logSearch(query: string, mode: 'ai' | 'keyword', resultsCount: number): Promise<void> {
    try {
      const stmt = this.db.prepare(`
        INSERT INTO ai_search_history (query, mode, results_count, created_at)
        VALUES (?, ?, ?, ?)
      `)
      await stmt.bind(query, mode, resultsCount, Date.now()).run()
    } catch (error) {
      console.error('Error logging search:', error)
    }
  }

  /**
   * Get search analytics
   */
  async getSearchAnalytics(): Promise<{
    total_queries: number
    ai_queries: number
    keyword_queries: number
    popular_queries: Array<{ query: string; count: number }>
    average_query_time: number
  }> {
    try {
      // Total queries (last 30 days)
      const totalStmt = this.db.prepare(`
        SELECT COUNT(*) as count 
        FROM ai_search_history 
        WHERE created_at >= ?
      `)
      const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000
      const totalResult = await totalStmt.bind(thirtyDaysAgo).first<{ count: number }>()

      // AI vs Keyword breakdown
      const modeStmt = this.db.prepare(`
        SELECT mode, COUNT(*) as count 
        FROM ai_search_history 
        WHERE created_at >= ?
        GROUP BY mode
      `)
      const { results: modeResults } = await modeStmt.bind(thirtyDaysAgo).all<{
        mode: string
        count: number
      }>()

      const aiCount = modeResults?.find((r) => r.mode === 'ai')?.count || 0
      const keywordCount = modeResults?.find((r) => r.mode === 'keyword')?.count || 0

      // Popular queries
      const popularStmt = this.db.prepare(`
        SELECT query, COUNT(*) as count 
        FROM ai_search_history 
        WHERE created_at >= ?
        GROUP BY query 
        ORDER BY count DESC 
        LIMIT 10
      `)
      const { results: popularResults } = await popularStmt.bind(thirtyDaysAgo).all<{
        query: string
        count: number
      }>()

      return {
        total_queries: totalResult?.count || 0,
        ai_queries: aiCount,
        keyword_queries: keywordCount,
        popular_queries: (popularResults || []).map((r) => ({
          query: r.query,
          count: r.count,
        })),
        average_query_time: 0, // TODO: Track query times
      }
    } catch (error) {
      console.error('Error getting analytics:', error)
      return {
        total_queries: 0,
        ai_queries: 0,
        keyword_queries: 0,
        popular_queries: [],
        average_query_time: 0,
      }
    }
  }

  /**
   * Verify Custom RAG is available
   */
  verifyBinding(): boolean {
    return this.customRAG?.isAvailable() ?? false
  }

  /**
   * Get Custom RAG service instance (for indexer)
   */
  getCustomRAG(): CustomRAGService | undefined {
    return this.customRAG
  }
}
