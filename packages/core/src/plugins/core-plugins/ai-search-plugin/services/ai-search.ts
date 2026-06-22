import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import type {
  AISearchSettings,
  SearchQuery,
  SearchResponse,
  SearchResult,
  CollectionInfo,
  NewCollectionNotification,
} from '../types'
import { CustomRAGService } from './custom-rag.service'
import { getCollectionRegistry } from '../../../../services/collection-registry'
import { Fts5Engine } from './fts5-engine'
import { getFtsSettings } from './fts-settings.service'
import { getCachedResult, putCachedResult } from './fts-search-cache'

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
    private vectorize?: any, // Vectorize for vector search
    private tenantId: string = 'default', // tenant scope for lexical (FTS5) search
    private kv?: KVNamespace, // CACHE_KV — lexical settings + result cache
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
      // Get all active code-defined collections from the in-memory registry.
      const allCollections = getCollectionRegistry()
        .listActive()
        .filter((r) => !r.internal)
        .map((r) => ({
          id: r.id,
          name: r.name,
          display_name: r.displayName,
          description: r.description ?? undefined,
        }))

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
      // Get all active code-defined collections from the in-memory registry,
      // sorted by display name.
      const allCollections = getCollectionRegistry()
        .listActive()
        .filter((r) => !r.internal)
        .sort((a, b) => a.displayName.localeCompare(b.displayName))
        .map((r) => ({
          id: r.id,
          name: r.name,
          display_name: r.displayName,
          description: r.description ?? undefined,
        }))

      const collections = allCollections.filter((col) => col.id && col.name)

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
    const settings = await this.getSettings()

    if (!settings?.enabled) {
      return {
        results: [],
        total: 0,
        query_time_ms: 0,
        mode: query.mode,
      }
    }

    // Use AI Search if enabled, mode is 'ai', and the bindings exist.
    const wantAI = query.mode === 'ai'
    if (wantAI && settings.ai_mode_enabled && this.customRAG?.isAvailable()) {
      return this.searchAI(query, settings)
    }

    // Lexical (keyword) floor over documents_fts.
    const result = await this.searchKeyword(query, settings)
    // LA4 degrade contract: an 'ai' request served by the lexical floor is flagged, never broken.
    if (wantAI) result.degraded = true
    return result
  }

  /**
   * AI-powered semantic search using Custom RAG
   */
  private async searchAI(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    try {
      if (!this.customRAG) {
        console.warn('[AISearchService] CustomRAG not available, falling back to keyword search')
        return { ...(await this.searchKeyword(query, settings)), degraded: true }
      }

      // Use Custom RAG for semantic search - pass the full query object and settings
      const result = await this.customRAG.search(query, settings)

      return result
    } catch (error) {
      console.error('[AISearchService] AI search error, falling back to keyword:', error)
      // Fallback to keyword search (LA4: degraded, never broken).
      return { ...(await this.searchKeyword(query, settings)), degraded: true }
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
      // FTS settings (bm25 weights, result limit, cache TTL, searchable types) persist in CACHE_KV.
      const fts = await getFtsSettings(this.kv)
      const cacheable = !!this.kv && fts.cacheTtlSeconds > 0

      // Best-effort result cache, keyed by normalized query + tenant.
      if (cacheable) {
        const cached = await getCachedResult(this.kv!, query, this.tenantId)
        if (cached) return { ...cached, query_time_ms: Date.now() - startTime }
      }

      // Lexical FTS5 search over documents_fts (replaces the legacy `content LIKE` scan).
      const engine = new Fts5Engine(this.db, {
        titleBoost: fts.titleBoost,
        slugBoost: fts.slugBoost,
        bodyBoost: fts.bodyBoost,
      })

      // Restrict to requested types, else configured searchable types, else legacy selected, else all.
      const typeIds = query.filters?.collections?.length
        ? query.filters.collections
        : fts.searchableTypes.length
          ? fts.searchableTypes
          : settings.selected_collections.length
            ? settings.selected_collections
            : undefined

      // Public search is published-only unless the caller explicitly asks for other statuses.
      const wantsNonPublished = !!query.filters?.status?.some((s) => s !== 'published')

      const { hits, total } = await engine.search({
        query: query.query,
        tenantId: this.tenantId,
        typeIds,
        publishedOnly: !wantsNonPublished,
        limit: query.limit || fts.resultsLimit,
        offset: query.offset || 0,
      })

      const searchResults: SearchResult[] = hits.map((h) => ({
        id: h.documentId,
        title: h.title || 'Untitled',
        slug: h.slug,
        collection_id: h.typeId,
        collection_name: h.typeId,
        snippet: h.snippet,
        relevance_score: h.score,
        status: h.status,
        created_at: h.createdAt,
        updated_at: h.updatedAt,
      }))

      const response: SearchResponse = {
        results: searchResults,
        total,
        query_time_ms: Date.now() - startTime,
        mode: query.mode,
      }

      if (cacheable) await putCachedResult(this.kv!, query, this.tenantId, response, fts.cacheTtlSeconds)

      // Log search history (best-effort; ai_search_history has no greenfield migration — L27).
      await this.logSearch(query.query, query.mode, searchResults.length).catch(() => {})

      return response
    } catch (error) {
      console.error('Keyword (FTS5) search error:', error)
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
   */
  async getSearchSuggestions(partial: string): Promise<string[]> {
    try {
      const settings = await this.getSettings()
      if (!settings?.autocomplete_enabled) {
        return []
      }

      // If Custom RAG is available, use AI-powered suggestions
      if (this.customRAG?.isAvailable()) {
        try {
          const aiSuggestions = await this.customRAG.getSuggestions(partial, 5)
          if (aiSuggestions.length > 0) {
            return aiSuggestions
          }
        } catch (error) {
          console.error('[AISearchService] Error getting AI suggestions:', error)
          // Fall through to history-based suggestions
        }
      }

      // Fallback to history-based suggestions
      const stmt = this.db.prepare(`
        SELECT DISTINCT query 
        FROM ai_search_history 
        WHERE query LIKE ? 
        ORDER BY created_at DESC 
        LIMIT 10
      `)
      const { results } = await stmt.bind(`%${partial}%`).all<{ query: string }>()

      return (results || []).map((r) => r.query)
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
