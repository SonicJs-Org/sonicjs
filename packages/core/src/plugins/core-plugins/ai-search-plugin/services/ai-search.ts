import type { D1Database } from '@cloudflare/workers-types'
import type {
  AISearchSettings,
  CollectionInfo,
  FacetResult,
  NewCollectionNotification,
  SearchQuery,
  SearchResponse,
  SearchResult,
} from '../types'
import { CustomRAGService } from './custom-rag.service'
import { FacetService } from './facet.service'
import { FTS5Service } from './fts5.service'
import { HybridSearchService } from './hybrid-search.service'
import { QueryRewriterService } from './query-rewriter.service'
import { RankingPipelineService } from './ranking-pipeline.service'
import { SynonymService } from './synonym.service'
import { RerankerService } from './reranker.service'

/**
 * AI Search Service
 * Handles search operations, settings management, and collection detection
 * Now uses Custom RAG with Vectorize for semantic search
 */
export class AISearchService {
  private customRAG?: CustomRAGService
  private fts5Service?: FTS5Service
  private hybridService?: HybridSearchService
  private queryRewriter?: QueryRewriterService
  private reranker?: RerankerService
  private rankingPipeline: RankingPipelineService
  private synonymService: SynonymService

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

    // Initialize FTS5 service (always available, degrades gracefully if table doesn't exist)
    this.fts5Service = new FTS5Service(db)
    console.log('[AISearchService] FTS5 service initialized')

    // Initialize hybrid search (FTS5 always, AI when available)
    this.hybridService = new HybridSearchService(this.fts5Service, this.customRAG)
    console.log('[AISearchService] Hybrid search service initialized')

    // Initialize AI-dependent services
    if (this.ai) {
      this.queryRewriter = new QueryRewriterService(this.ai)
      this.reranker = new RerankerService(this.ai)
      console.log('[AISearchService] Query rewriter and reranker initialized')
    }

    // Synonym service (always available, degrades gracefully if table doesn't exist)
    this.synonymService = new SynonymService(db)
    if (this.fts5Service) {
      this.fts5Service.setSynonymService(this.synonymService)
    }

    // Ranking pipeline (always available, zero cost when no stages active)
    this.rankingPipeline = new RankingPipelineService(db)
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
      query_rewriting_enabled: false,
      reranking_enabled: true,
      fts5_title_boost: 5.0,
      fts5_slug_boost: 2.0,
      fts5_body_boost: 1.0,
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
   * Supports three modes: 'ai' (semantic), 'fts5' (full-text), 'keyword' (basic)
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

    // Determine if facets should be computed
    const shouldComputeFacets = query.facets && settings.facets_enabled

    // Auto-generate facet config on first enable (if none exists)
    if (shouldComputeFacets && (!settings.facet_config || settings.facet_config.length === 0)) {
      try {
        const facetService = new FacetService(this.db)
        const discovered = await facetService.discoverFields()
        const config = facetService.autoGenerateConfig(discovered)
        if (config.length > 0) {
          await this.updateSettings({ facet_config: config })
          settings.facet_config = config
        }
      } catch (error) {
        console.warn('[AISearchService] Auto-generate facet config failed:', error)
      }
    }

    // Build the search promise
    let searchPromise: Promise<SearchResponse>

    // Hybrid mode - FTS5 + AI combined with RRF, optional rewriting + reranking
    if (query.mode === 'hybrid') {
      searchPromise = this.searchHybrid(query, settings)
    }
    // FTS5 mode - full-text search with BM25 ranking and highlighting
    else if (query.mode === 'fts5') {
      searchPromise = this.searchFTS5(query, settings)
    }
    // AI mode - semantic search using Custom RAG with Vectorize
    else if (query.mode === 'ai' && settings.ai_mode_enabled && this.customRAG?.isAvailable()) {
      searchPromise = this.searchAI(query, settings)
    }
    // Fallback to keyword search
    else {
      searchPromise = this.searchKeyword(query, settings)
    }

    // Build the facet promise (runs in parallel with search)
    let facetPromise: Promise<FacetResult[]> | null = null
    if (shouldComputeFacets && settings.facet_config && settings.facet_config.length > 0) {
      facetPromise = this.computeFacets(query, settings)
    }

    // Execute search + facets in parallel
    const [result, facets] = await Promise.all([
      searchPromise,
      facetPromise || Promise.resolve(null),
    ])

    // In-memory facet filtering for AI/hybrid modes (SQL-based modes filter at query level)
    if (query.filters?.custom && Object.keys(query.filters.custom).length > 0
        && (query.mode === 'ai' || query.mode === 'hybrid')) {
      result.results = this.filterResultsByFacets(result.results, query.filters.custom)
      result.total = result.results.length
    }

    // Attach facets to response
    if (facets && facets.length > 0) {
      result.facets = facets
    }

    // For AI mode, compute facets from result IDs (can't run in parallel)
    if (shouldComputeFacets && query.mode === 'ai' && result.results.length > 0 && settings.facet_config?.length) {
      try {
        const facetService = new FacetService(this.db)
        const contentIds = result.results.map(r => r.id).slice(0, 50)
        result.facets = await facetService.computeFacetsFromIds(
          settings.facet_config,
          contentIds,
          settings.facet_max_values || 20
        )
      } catch (error) {
        console.warn('[AISearchService] AI mode facet computation failed:', error)
      }
    }

    // Apply ranking pipeline (post-processing: re-scores and re-sorts)
    // Zero-cost when no stages are enabled
    try {
      const ranked = await this.rankingPipeline.apply(result, query.query)
      return ranked
    } catch (error) {
      console.warn('[AISearchService] Ranking pipeline error (preserving original order):', error)
      return result
    }
  }

  /**
   * Compute facets for the current search query.
   * Delegates to FacetService with mode-appropriate strategy.
   */
  private async computeFacets(
    query: SearchQuery,
    settings: AISearchSettings
  ): Promise<FacetResult[]> {
    const facetService = new FacetService(this.db)
    const config = settings.facet_config!
    const maxValues = settings.facet_max_values || 20

    // Determine collection IDs for facet queries
    const collectionIds = query.filters?.collections?.length
      ? query.filters.collections
      : settings.selected_collections

    const activeFilters = query.filters?.custom

    try {
      // FTS5 and hybrid: SQL GROUP BY with FTS5 MATCH
      if (query.mode === 'fts5' || query.mode === 'hybrid') {
        const matchQuery = FacetService.sanitizeFTS5Query(query.query)
        return await facetService.computeFacetsFts(config, matchQuery, collectionIds, maxValues, activeFilters)
      }

      // Keyword: SQL GROUP BY with LIKE
      if (query.mode === 'keyword') {
        return await facetService.computeFacetsKeyword(config, query.query, collectionIds, maxValues, activeFilters)
      }

      // AI mode: compute from result IDs (limited to top 50)
      // For AI mode, we can't run SQL facets in parallel because we need
      // the result IDs first. Return empty and let the caller post-fill.
      return []
    } catch (error) {
      console.warn('[AISearchService] Facet computation failed:', error)
      return []
    }
  }

  /**
   * FTS5 full-text search with BM25 ranking, stemming, and highlighting
   */
  private async searchFTS5(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      if (!this.fts5Service) {
        console.warn('[AISearchService] FTS5 service not initialized, falling back to keyword search')
        return this.searchKeyword(query, settings)
      }

      // Check if FTS5 table is available
      if (!(await this.fts5Service.isAvailable())) {
        console.warn('[AISearchService] FTS5 table not available, falling back to keyword search')
        return this.searchKeyword(query, settings)
      }

      const result = await this.fts5Service.search(query, settings, {
        titleBoost: settings.fts5_title_boost,
        slugBoost: settings.fts5_slug_boost,
        bodyBoost: settings.fts5_body_boost,
      })

      // Log search to history
      const elapsed = Date.now() - startTime
      const searchId = await this.logSearch(query.query, 'fts5', result.results.length, elapsed)
      result.search_id = searchId

      return result
    } catch (error) {
      console.error('[AISearchService] FTS5 search error, falling back to keyword:', error)
      return this.searchKeyword(query, settings)
    }
  }

  /**
   * Hybrid search: FTS5 + AI combined with RRF, optional query rewriting + reranking
   */
  private async searchHybrid(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      if (!this.hybridService || !this.fts5Service) {
        console.warn('[AISearchService] Hybrid service not available, falling back to keyword search')
        return this.searchKeyword(query, settings)
      }

      // Check if FTS5 table is available (required for hybrid)
      if (!(await this.fts5Service.isAvailable())) {
        console.warn('[AISearchService] FTS5 not available for hybrid, falling back to keyword search')
        return this.searchKeyword(query, settings)
      }

      let searchQuery = query

      // Step 1: Query Rewriting (if enabled + AI available + query >= 15 chars)
      const rewritingEnabled = settings.query_rewriting_enabled ?? false
      if (
        rewritingEnabled &&
        this.queryRewriter &&
        QueryRewriterService.shouldRewrite(query.query)
      ) {
        const rewritten = await this.queryRewriter.rewrite(query.query)
        if (rewritten !== query.query) {
          console.log(`[AISearchService] Query rewritten: "${query.query}" → "${rewritten}"`)
          searchQuery = { ...query, query: rewritten }
        }
      }

      // Step 2: Hybrid Search (FTS5 + AI in parallel, semantic-first ranking)
      let result = await this.hybridService.search(searchQuery, settings)

      // Note: AI reranking is intentionally SKIPPED for hybrid mode.
      // Hybrid already ranks by Vectorize semantic scores (bi-encoder cosine similarity),
      // which outperforms the bge-reranker-base cross-encoder. Applying the reranker
      // here degrades nDCG and MRR (confirmed via BEIR benchmark evaluation).

      // Log search to history
      const elapsed = Date.now() - startTime
      const searchId = await this.logSearch(query.query, 'hybrid', result.results.length, elapsed)
      result.search_id = searchId

      return result
    } catch (error) {
      console.error('[AISearchService] Hybrid search error, falling back to keyword:', error)
      return this.searchKeyword(query, settings)
    }
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

      // Log search to history
      const elapsed = Date.now() - startTime
      const searchId = await this.logSearch(query.query, 'ai', result.results.length, elapsed)
      result.search_id = searchId

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

      // Facet filter conditions (from active facet selections)
      if (query.filters?.custom && settings.facet_config?.length) {
        const { conditions: filterConditions, params: filterParams } = FacetService.buildFacetFilterSQL(
          query.filters.custom,
          settings.facet_config
        )
        conditions.push(...filterConditions)
        params.push(...filterParams)
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

      const searchResults: SearchResult[] = (results || []).map((row) => {
        const snippet = this.extractSnippet(row.data, query.query)
        const titleHighlight = this.highlightText(row.title || 'Untitled', query.query)
        return {
          id: String(row.id),
          title: row.title || 'Untitled',
          slug: row.slug || '',
          collection_id: String(row.collection_id),
          collection_name: row.collection_display_name || row.collection_name,
          snippet,
          highlights: {
            title: titleHighlight,
            body: snippet
          },
          status: row.status,
          created_at: Number(row.created_at),
          updated_at: Number(row.updated_at),
          author_name: row.author_email,
        }
      })

      const queryTime = Date.now() - startTime

      // Log search history
      const searchId = await this.logSearch(query.query, query.mode, searchResults.length, queryTime)

      return {
        results: searchResults,
        total,
        query_time_ms: queryTime,
        mode: query.mode,
        search_id: searchId,
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
   * Pulls human-readable text from JSON data fields instead of raw JSON
   */
  private extractSnippet(data: string, query: string): string {
    try {
      const parsed = typeof data === 'string' ? JSON.parse(data) : data

      // Extract readable text from common content fields
      const textParts: string[] = []
      const textFields = ['description', 'content', 'body', 'text', 'summary', 'excerpt']
      for (const field of textFields) {
        if (parsed[field] && typeof parsed[field] === 'string') {
          textParts.push(parsed[field])
        }
      }

      // Fallback: collect all string values
      if (textParts.length === 0) {
        for (const value of Object.values(parsed)) {
          if (typeof value === 'string' && value.length > 20) {
            textParts.push(value)
          }
        }
      }

      const text = textParts.join(' ').replace(/\s+/g, ' ').trim()

      if (!text) {
        return 'No preview available'
      }

      // Try to find query match and show context around it with highlighting
      const queryLower = query.toLowerCase()
      const textLower = text.toLowerCase()
      const index = textLower.indexOf(queryLower)

      if (index === -1) {
        return text.substring(0, 200) + (text.length > 200 ? '...' : '')
      }

      const start = Math.max(0, index - 80)
      const end = Math.min(text.length, index + query.length + 120)
      const prefix = start > 0 ? '...' : ''
      const suffix = end < text.length ? '...' : ''
      const excerpt = text.substring(start, end)

      // Add <mark> highlighting around all query matches in the excerpt
      return prefix + this.highlightText(excerpt, query) + suffix
    } catch {
      return data.substring(0, 200) + '...'
    }
  }

  /**
   * Highlight query terms in text with <mark> tags
   * Case-insensitive, highlights all occurrences
   */
  private highlightText(text: string, query: string): string {
    if (!text || !query) return text
    try {
      // Split query into words and escape for regex
      const words = query.trim().split(/\s+/).filter(w => w.length > 1)
      if (words.length === 0) return text

      const escaped = words.map(w => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
      const pattern = new RegExp(`(${escaped.join('|')})`, 'gi')
      return text.replace(pattern, '<mark>$1</mark>')
    } catch {
      return text
    }
  }

  /**
   * Filter search results in-memory by active facet selections.
   * Used for AI/hybrid modes where SQL-level filtering isn't possible.
   */
  private filterResultsByFacets(
    results: SearchResult[],
    customFilters: Record<string, any>
  ): SearchResult[] {
    if (!customFilters || Object.keys(customFilters).length === 0) return results

    return results.filter(result => {
      for (const [field, values] of Object.entries(customFilters)) {
        if (!values || (Array.isArray(values) && values.length === 0)) continue
        const valueArr = Array.isArray(values) ? values : [values]
        if (valueArr.length === 0) continue

        switch (field) {
          case 'collection_name':
            if (!valueArr.includes(result.collection_name)) return false
            break
          case 'status':
            if (!valueArr.includes(result.status)) return false
            break
          case 'author':
            if (!result.author_name || !valueArr.includes(result.author_name)) return false
            break
          // JSON fields not available on SearchResult — filtered at SQL level for FTS5/keyword
        }
      }
      return true
    })
  }

  /**
   * Get search suggestions (autocomplete)
   * Routes to trending queries (empty/short input) or prefix suggestions (2+ chars)
   */
  async getSearchSuggestions(partial: string): Promise<string[]> {
    try {
      const settings = await this.getSettings()
      if (!settings?.autocomplete_enabled) {
        return []
      }

      const trimmed = partial.trim()
      if (trimmed.length < 2) {
        return this.getTrendingQueries()
      }
      return this.getPrefixSuggestions(trimmed)
    } catch (error) {
      console.error('Error getting suggestions:', error)
      return []
    }
  }

  /**
   * Get trending queries from last 7 days, ranked by frequency.
   * Excludes zero-result queries (AVG results_count < 0.5).
   */
  private async getTrendingQueries(): Promise<string[]> {
    try {
      const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
      const stmt = this.db.prepare(`
        SELECT query, COUNT(*) as cnt, AVG(results_count) as avg_res
        FROM ai_search_history
        WHERE created_at >= ?
        GROUP BY LOWER(query)
        HAVING avg_res >= 0.5
        ORDER BY cnt DESC
        LIMIT 10
      `)
      const { results } = await stmt.bind(sevenDaysAgo).all<{ query: string; cnt: number; avg_res: number }>()
      return (results || []).map((r) => r.query).filter(Boolean)
    } catch (error) {
      console.log('[AISearchService] Trending queries unavailable:', error)
      return []
    }
  }

  /**
   * Get prefix suggestions by blending popular query prefixes (30d) + FTS5 content title prefixes.
   * Popular queries appear first (real user intent), content titles fill remaining slots.
   */
  private async getPrefixSuggestions(prefix: string): Promise<string[]> {
    const [popularQueries, contentTitles] = await Promise.all([
      this.getPopularQueryPrefixes(prefix, 5),
      this.getContentTitlePrefixes(prefix, 5),
    ])

    // Dedup: popular queries first, then content titles that aren't already included
    const seen = new Set(popularQueries.map((q) => q.toLowerCase()))
    const merged = [...popularQueries]
    for (const title of contentTitles) {
      if (!seen.has(title.toLowerCase())) {
        merged.push(title)
        seen.add(title.toLowerCase())
      }
      if (merged.length >= 10) break
    }
    return merged
  }

  /**
   * Popular query prefixes from search history (last 30 days).
   * Ranked by frequency, excludes zero-result queries.
   */
  private async getPopularQueryPrefixes(prefix: string, limit: number): Promise<string[]> {
    try {
      const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000
      const stmt = this.db.prepare(`
        SELECT query, COUNT(*) as cnt, AVG(results_count) as avg_res
        FROM ai_search_history
        WHERE created_at >= ? AND LOWER(query) LIKE ?
        GROUP BY LOWER(query)
        HAVING avg_res >= 0.5
        ORDER BY cnt DESC
        LIMIT ?
      `)
      const { results } = await stmt
        .bind(thirtyDaysAgo, `${prefix.toLowerCase()}%`, limit)
        .all<{ query: string; cnt: number; avg_res: number }>()
      return (results || []).map((r) => r.query).filter(Boolean)
    } catch (error) {
      console.log('[AISearchService] Popular query prefixes unavailable:', error)
      return []
    }
  }

  /**
   * Content title prefixes via FTS5 prefix matching.
   * Falls back to ai_search_index LIKE if FTS5 is unavailable.
   */
  private async getContentTitlePrefixes(prefix: string, limit: number): Promise<string[]> {
    // Try FTS5 prefix match first (fast + ranked by BM25)
    try {
      // Sanitize prefix for FTS5: remove special chars, keep alphanumeric + spaces
      const sanitized = prefix.replace(/[^\w\s]/g, '').trim()
      if (!sanitized) return []

      const stmt = this.db.prepare(`
        SELECT DISTINCT title FROM content_fts
        WHERE content_fts MATCH ?
        ORDER BY bm25(content_fts, 5.0, 2.0, 1.0)
        LIMIT ?
      `)
      const { results } = await stmt.bind(`${sanitized}*`, limit).all<{ title: string }>()
      return (results || []).map((r) => r.title).filter(Boolean)
    } catch {
      // FTS5 table may not exist — fall back to ai_search_index
    }

    // Fallback: simple LIKE prefix on ai_search_index
    try {
      const stmt = this.db.prepare(`
        SELECT DISTINCT title FROM ai_search_index
        WHERE LOWER(title) LIKE ?
        ORDER BY title
        LIMIT ?
      `)
      const { results } = await stmt.bind(`${prefix.toLowerCase()}%`, limit).all<{ title: string }>()
      return (results || []).map((r) => r.title).filter(Boolean)
    } catch {
      return []
    }
  }

  /**
   * Log search query to history, returns the generated search_id
   */
  private async logSearch(query: string, mode: 'ai' | 'keyword' | 'fts5' | 'hybrid', resultsCount: number, responseTimeMs?: number): Promise<string | undefined> {
    try {
      const result = await this.db.prepare(`
        INSERT INTO ai_search_history (query, mode, results_count, response_time_ms, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).bind(query, mode, resultsCount, responseTimeMs ?? null, Date.now()).run()
      // D1 returns the auto-incremented rowid via meta.last_row_id
      const rowId = result?.meta?.last_row_id
      return rowId ? String(rowId) : undefined
    } catch (error) {
      console.error('Error logging search:', error)
      return undefined
    }
  }

  /**
   * Get search analytics
   */
  async getSearchAnalytics(): Promise<{
    total_queries: number
    ai_queries: number
    keyword_queries: number
    fts5_queries: number
    hybrid_queries: number
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

      // AI vs Keyword vs FTS5 breakdown
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
      const fts5Count = modeResults?.find((r) => r.mode === 'fts5')?.count || 0
      const hybridCount = modeResults?.find((r) => r.mode === 'hybrid')?.count || 0

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
        fts5_queries: fts5Count,
        hybrid_queries: hybridCount,
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
        fts5_queries: 0,
        hybrid_queries: 0,
        popular_queries: [],
        average_query_time: 0,
      }
    }
  }

  /**
   * Get extended analytics for the Analytics tab
   */
  async getAnalyticsExtended(): Promise<{
    total_queries: number
    queries_today: number
    ai_queries: number
    keyword_queries: number
    fts5_queries: number
    hybrid_queries: number
    avg_results_per_query: number
    zero_result_rate: number
    avg_response_time_ms: number
    popular_queries: Array<{ query: string; count: number }>
    zero_result_queries: Array<{ query: string; count: number }>
    recent_queries: Array<{ query: string; mode: string; results_count: number; response_time_ms: number | null; created_at: number }>
    daily_counts: Array<{ date: string; count: number }>
    // Click analytics
    total_clicks_30d: number
    ctr_30d: number
    avg_click_position_30d: number
    ctr_over_time: Array<{ date: string; searches: number; clicks: number; ctr: number }>
    most_clicked_content: Array<{ content_id: string; content_title: string; click_count: number }>
    no_click_searches: Array<{ query: string; search_count: number; results_count_avg: number }>
    // Facet analytics
    total_facet_clicks_30d: number
    top_facet_fields: Array<{ facet_field: string; click_count: number }>
    top_facet_values: Array<{ facet_field: string; facet_value: string; click_count: number }>
    facet_clicks_over_time: Array<{ date: string; count: number }>
  }> {
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000
    const todayStart = new Date()
    todayStart.setHours(0, 0, 0, 0)
    const todayStartMs = todayStart.getTime()

    try {
      // Run all queries in parallel
      const [
        totalResult,
        todayResult,
        modeResults,
        avgResults,
        zeroCountResult,
        avgTimeResult,
        popularResults,
        zeroResultResults,
        recentResults,
        dailyResults,
        // Click analytics
        clickCountResult,
        avgClickPosResult,
        ctrOverTimeResults,
        mostClickedResults,
        noClickResults,
        // Facet analytics
        facetClickCountResult,
        topFacetFieldsResult,
        topFacetValuesResult,
        facetClicksOverTimeResult,
      ] = await Promise.all([
        // Total queries (30 days)
        this.db.prepare('SELECT COUNT(*) as count FROM ai_search_history WHERE created_at >= ?')
          .bind(thirtyDaysAgo).first<{ count: number }>(),

        // Queries today
        this.db.prepare('SELECT COUNT(*) as count FROM ai_search_history WHERE created_at >= ?')
          .bind(todayStartMs).first<{ count: number }>(),

        // Mode breakdown
        this.db.prepare('SELECT mode, COUNT(*) as count FROM ai_search_history WHERE created_at >= ? GROUP BY mode')
          .bind(thirtyDaysAgo).all<{ mode: string; count: number }>(),

        // Average results per query
        this.db.prepare('SELECT AVG(results_count) as avg_results FROM ai_search_history WHERE created_at >= ?')
          .bind(thirtyDaysAgo).first<{ avg_results: number | null }>(),

        // Zero result count
        this.db.prepare('SELECT COUNT(*) as count FROM ai_search_history WHERE created_at >= ? AND results_count = 0')
          .bind(thirtyDaysAgo).first<{ count: number }>(),

        // Average response time
        this.db.prepare('SELECT AVG(response_time_ms) as avg_time FROM ai_search_history WHERE created_at >= ? AND response_time_ms IS NOT NULL')
          .bind(thirtyDaysAgo).first<{ avg_time: number | null }>(),

        // Popular queries (top 15)
        this.db.prepare('SELECT query, COUNT(*) as count FROM ai_search_history WHERE created_at >= ? GROUP BY query ORDER BY count DESC LIMIT 15')
          .bind(thirtyDaysAgo).all<{ query: string; count: number }>(),

        // Zero-result queries (top 20)
        this.db.prepare('SELECT query, COUNT(*) as count FROM ai_search_history WHERE created_at >= ? AND results_count = 0 GROUP BY query ORDER BY count DESC LIMIT 20')
          .bind(thirtyDaysAgo).all<{ query: string; count: number }>(),

        // Recent queries (last 25)
        this.db.prepare('SELECT query, mode, results_count, response_time_ms, created_at FROM ai_search_history ORDER BY created_at DESC LIMIT 25')
          .all<{ query: string; mode: string; results_count: number; response_time_ms: number | null; created_at: number }>(),

        // Daily counts for last 30 days
        this.db.prepare(`
          SELECT date(created_at / 1000, 'unixepoch') as date, COUNT(*) as count
          FROM ai_search_history
          WHERE created_at >= ?
          GROUP BY date(created_at / 1000, 'unixepoch')
          ORDER BY date ASC
        `).bind(thirtyDaysAgo).all<{ date: string; count: number }>(),

        // Click analytics: total clicks (30 days)
        this.db.prepare("SELECT COUNT(*) as count FROM ai_search_clicks WHERE created_at > datetime('now', '-30 days')")
          .first<{ count: number }>().catch(() => ({ count: 0 })),

        // Click analytics: average click position (30 days)
        this.db.prepare("SELECT AVG(click_position) as avg_pos FROM ai_search_clicks WHERE created_at > datetime('now', '-30 days')")
          .first<{ avg_pos: number | null }>().catch(() => ({ avg_pos: null })),

        // Click analytics: CTR over time (daily, 30 days)
        this.db.prepare(`
          SELECT
            date(h.created_at / 1000, 'unixepoch') as date,
            COUNT(DISTINCT h.id) as searches,
            COUNT(c.id) as clicks
          FROM ai_search_history h
          LEFT JOIN ai_search_clicks c ON c.search_id = h.id
          WHERE h.created_at >= ?
          GROUP BY date(h.created_at / 1000, 'unixepoch')
          ORDER BY date ASC
        `).bind(thirtyDaysAgo).all<{ date: string; searches: number; clicks: number }>().catch(() => ({ results: [] })),

        // Click analytics: most clicked content (top 20)
        this.db.prepare(`
          SELECT clicked_content_id as content_id, clicked_content_title as content_title, COUNT(*) as click_count
          FROM ai_search_clicks
          WHERE created_at > datetime('now', '-30 days')
          GROUP BY clicked_content_id
          ORDER BY click_count DESC
          LIMIT 20
        `).all<{ content_id: string; content_title: string; click_count: number }>().catch(() => ({ results: [] })),

        // Click analytics: searches with no clicks (top 20)
        this.db.prepare(`
          SELECT h.query, COUNT(DISTINCT h.id) as search_count, CAST(AVG(h.results_count) AS INTEGER) as results_count_avg
          FROM ai_search_history h
          LEFT JOIN ai_search_clicks c ON c.search_id = h.id
          WHERE h.created_at >= ?
            AND h.results_count > 0
            AND c.id IS NULL
          GROUP BY h.query
          ORDER BY search_count DESC
          LIMIT 20
        `).bind(thirtyDaysAgo).all<{ query: string; search_count: number; results_count_avg: number }>().catch(() => ({ results: [] })),

        // Facet analytics: total facet clicks (30 days)
        this.db.prepare("SELECT COUNT(*) as count FROM ai_search_facet_clicks WHERE created_at > datetime('now', '-30 days')")
          .first<{ count: number }>().catch(() => ({ count: 0 })),

        // Facet analytics: top facet fields by click count (30 days)
        this.db.prepare(`
          SELECT facet_field, COUNT(*) as click_count
          FROM ai_search_facet_clicks
          WHERE created_at > datetime('now', '-30 days')
          GROUP BY facet_field
          ORDER BY click_count DESC
          LIMIT 10
        `).all<{ facet_field: string; click_count: number }>().catch(() => ({ results: [] })),

        // Facet analytics: top facet values by click count (30 days)
        this.db.prepare(`
          SELECT facet_field, facet_value, COUNT(*) as click_count
          FROM ai_search_facet_clicks
          WHERE created_at > datetime('now', '-30 days')
          GROUP BY facet_field, facet_value
          ORDER BY click_count DESC
          LIMIT 15
        `).all<{ facet_field: string; facet_value: string; click_count: number }>().catch(() => ({ results: [] })),

        // Facet analytics: facet clicks over time (daily, 30 days)
        this.db.prepare(`
          SELECT date(created_at) as date, COUNT(*) as count
          FROM ai_search_facet_clicks
          WHERE created_at > datetime('now', '-30 days')
          GROUP BY date(created_at)
          ORDER BY date ASC
        `).all<{ date: string; count: number }>().catch(() => ({ results: [] })),
      ])

      const totalQueries = totalResult?.count || 0
      const zeroCount = zeroCountResult?.count || 0
      const modes = modeResults?.results || []

      // Compute click analytics
      const totalClicks = (clickCountResult as any)?.count || 0
      const avgClickPos = (avgClickPosResult as any)?.avg_pos
      const ctrRaw = (ctrOverTimeResults as any)?.results || []
      const ctrOverTime = ctrRaw.map((r: any) => ({
        date: r.date,
        searches: r.searches,
        clicks: r.clicks,
        ctr: r.searches > 0 ? Math.round((r.clicks / r.searches) * 1000) / 10 : 0,
      }))

      return {
        total_queries: totalQueries,
        queries_today: todayResult?.count || 0,
        ai_queries: modes.find(r => r.mode === 'ai')?.count || 0,
        keyword_queries: modes.find(r => r.mode === 'keyword')?.count || 0,
        fts5_queries: modes.find(r => r.mode === 'fts5')?.count || 0,
        hybrid_queries: modes.find(r => r.mode === 'hybrid')?.count || 0,
        avg_results_per_query: Math.round((avgResults?.avg_results ?? 0) * 10) / 10,
        zero_result_rate: totalQueries > 0 ? Math.round((zeroCount / totalQueries) * 1000) / 10 : 0,
        avg_response_time_ms: Math.round(avgTimeResult?.avg_time ?? 0),
        popular_queries: (popularResults?.results || []).map(r => ({ query: r.query, count: r.count })),
        zero_result_queries: (zeroResultResults?.results || []).map(r => ({ query: r.query, count: r.count })),
        recent_queries: (recentResults?.results || []).map(r => ({
          query: r.query,
          mode: r.mode,
          results_count: r.results_count,
          response_time_ms: r.response_time_ms,
          created_at: r.created_at,
        })),
        daily_counts: (dailyResults?.results || []).map(r => ({ date: r.date, count: r.count })),
        // Click analytics
        total_clicks_30d: totalClicks,
        ctr_30d: totalQueries > 0 ? Math.round((totalClicks / totalQueries) * 1000) / 10 : 0,
        avg_click_position_30d: avgClickPos != null ? Math.round(avgClickPos * 10) / 10 : 0,
        ctr_over_time: ctrOverTime,
        most_clicked_content: ((mostClickedResults as any)?.results || []).map((r: any) => ({
          content_id: r.content_id,
          content_title: r.content_title || 'Untitled',
          click_count: r.click_count,
        })),
        no_click_searches: ((noClickResults as any)?.results || []).map((r: any) => ({
          query: r.query,
          search_count: r.search_count,
          results_count_avg: r.results_count_avg,
        })),
        // Facet analytics
        total_facet_clicks_30d: (facetClickCountResult as any)?.count || 0,
        top_facet_fields: ((topFacetFieldsResult as any)?.results || []).map((r: any) => ({
          facet_field: r.facet_field,
          click_count: r.click_count,
        })),
        top_facet_values: ((topFacetValuesResult as any)?.results || []).map((r: any) => ({
          facet_field: r.facet_field,
          facet_value: r.facet_value,
          click_count: r.click_count,
        })),
        facet_clicks_over_time: ((facetClicksOverTimeResult as any)?.results || []).map((r: any) => ({
          date: r.date,
          count: r.count,
        })),
      }
    } catch (error) {
      console.error('Error getting extended analytics:', error)
      return {
        total_queries: 0,
        queries_today: 0,
        ai_queries: 0,
        keyword_queries: 0,
        fts5_queries: 0,
        hybrid_queries: 0,
        avg_results_per_query: 0,
        zero_result_rate: 0,
        avg_response_time_ms: 0,
        popular_queries: [],
        zero_result_queries: [],
        recent_queries: [],
        daily_counts: [],
        total_clicks_30d: 0,
        ctr_30d: 0,
        avg_click_position_30d: 0,
        ctr_over_time: [],
        most_clicked_content: [],
        no_click_searches: [],
        total_facet_clicks_30d: 0,
        top_facet_fields: [],
        top_facet_values: [],
        facet_clicks_over_time: [],
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

  /**
   * Get FTS5 service instance (for content sync and admin operations)
   */
  getFTS5Service(): FTS5Service | undefined {
    return this.fts5Service
  }

  /**
   * Get ranking pipeline service instance (for admin routes)
   */
  getRankingPipeline(): RankingPipelineService {
    return this.rankingPipeline
  }

  /**
   * Get synonym service instance (for admin routes)
   */
  getSynonymService(): SynonymService {
    return this.synonymService
  }
}
