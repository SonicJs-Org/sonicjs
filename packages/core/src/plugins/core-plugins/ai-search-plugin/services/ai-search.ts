import type { D1Database } from '@cloudflare/workers-types'
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
import { DocumentRepository } from '../../../../services/document-repository'
import { DocumentTypeRegistry } from '../../../../services/document-type-registry'
import { documentSecondsToMs } from '../../../../services/documents'
import { PluginService } from '../../../../services/plugin-service'
import type { DocumentTypeSettings, PrincipalRef } from '../../../../schemas/document'

/**
 * AI Search Service
 * Handles search operations, settings management, and collection detection
 * Now uses Custom RAG with Vectorize for semantic search
 */
const PLUGIN_ID = 'ai-search'
/**
 * Search history is document-backed. The `ai_search_history` table this plugin was written
 * against is not in any migration and does not exist on any install, so every log, suggestion
 * and analytics query threw `no such table` and was swallowed by its own catch — autocomplete
 * returned `[]` forever and the analytics endpoint reported zeroes.
 */
const HISTORY_TYPE = 'ai_search_history'
const HISTORY_SCOPE =
  "type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL"

export class AISearchService {
  private customRAG?: CustomRAGService
  /** Settings live in the plugin's own document (`type_id = 'plugin'`), not the dropped `plugins` table. */
  private plugins: PluginService

  constructor(
    private db: D1Database,
    private ai?: any, // Workers AI for embeddings
    private vectorize?: any, // Vectorize for vector search
    // R3: document reads are tenant-scoped. Routes pass the request's tenant; 'default' is the
    // POC-wide constant for every other caller.
    private tenantId: string = 'default'
  ) {
    this.plugins = new PluginService(db)
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
      const plugin = await this.plugins.getPlugin(PLUGIN_ID)
      const stored = plugin?.settings as Partial<AISearchSettings> | undefined
      if (!stored || Object.keys(stored).length === 0) {
        return this.getDefaultSettings()
      }

      // Merge over the defaults: a settings blob written before a new field existed would
      // otherwise read back as `undefined`, and `results_limit: undefined` becomes `LIMIT NaN`.
      return { ...this.getDefaultSettings(), ...stored }
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
      // Plugins that were never explicitly installed have no document yet — the plugins page
      // renders them from the manifest registry. Create it on first save, exactly as the
      // schema-driven settings route does.
      await this.plugins.ensurePlugin(PLUGIN_ID, {
        displayName: 'AI Search',
        description: 'Advanced search across all content collections',
        version: '1.0.0',
        author: 'SonicJS',
      })
      await this.plugins.updatePluginSettings(PLUGIN_ID, updated)

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

        const itemCount = await this.countCollectionItems(collectionId)

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
   * How many records a collection holds, for the "N items available for indexing" line.
   *
   * Counts current drafts — one row per logical record — rather than the published axis, so a
   * collection of unpublished work still reports its real size. Previously counted
   * `FROM content WHERE collection_id = ?`, which is empty on every install created after content
   * writes moved to `documents`.
   */
  private async countCollectionItems(collectionId: string): Promise<number> {
    const row = await this.db
      .prepare(
        `SELECT COUNT(*) as count FROM documents
         WHERE tenant_id = ? AND type_id = ? AND is_current_draft = 1 AND deleted_at IS NULL`
      )
      .bind(this.tenantId, collectionId)
      .first<{ count: number }>()
    return row?.count || 0
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

        const itemCount = await this.countCollectionItems(collectionId)

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
  async search(
    query: SearchQuery,
    principalSet: PrincipalRef[] = [{ type: 'public', id: '*' }]
  ): Promise<SearchResponse> {
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
      return this.searchAI(query, settings, principalSet)
    }

    // Fallback to keyword search
    return this.searchKeyword(query, settings, principalSet)
  }

  /**
   * AI-powered semantic search using Custom RAG
   */
  private async searchAI(
    query: SearchQuery,
    settings: AISearchSettings,
    principalSet: PrincipalRef[] = [{ type: 'public', id: '*' }]
  ): Promise<SearchResponse> {
    try {
      if (!this.customRAG) {
        console.warn('[AISearchService] CustomRAG not available, falling back to keyword search')
        return this.searchKeyword(query, settings, principalSet)
      }

      // Use Custom RAG for semantic search - pass the full query object and settings
      const result = await this.customRAG.search(query, settings)

      return result
    } catch (error) {
      console.error('[AISearchService] AI search error, falling back to keyword:', error)
      // Fallback to keyword search
      return this.searchKeyword(query, settings, principalSet)
    }
  }

  /**
   * Keyword search over the document repository.
   *
   * This used to read `FROM content c JOIN collections col ON c.collection_id = col.id`. The
   * `collections` table was dropped when collections became code-only, so that JOIN can never
   * resolve again: every query threw, the catch at the bottom swallowed it, and `/api/search`
   * answered 200 with zero results forever. Collection metadata now comes from the in-memory
   * registry — the same source `getAllCollections` already reads — and the rows come from
   * `documents`.
   *
   * Only the published axis is searched. `/api/search` is mounted unauthenticated, so matching
   * current drafts would hand anonymous callers unpublished content; an editor's own drafts stay
   * reachable through /admin/content. Published-but-restricted documents are then dropped by the
   * same per-document `isAllowed` filter the public document API applies, so there is no
   * is_published-only fast path here either (D5).
   */
  private async searchKeyword(
    query: SearchQuery,
    settings: AISearchSettings,
    principalSet: PrincipalRef[] = [{ type: 'public', id: '*' }]
  ): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      // R3: every document query is tenant-scoped.
      const conditions: string[] = ['d.tenant_id = ?', 'd.deleted_at IS NULL', 'd.is_published = 1']
      const params: Array<string | number> = [this.tenantId]

      if (query.query) {
        conditions.push('(d.title LIKE ? OR d.slug LIKE ? OR d.data LIKE ?)')
        const searchTerm = `%${query.query}%`
        params.push(searchTerm, searchTerm, searchTerm)
      }

      // Collection filter. type_id == collection id for code-defined collections —
      // autoRegisterCollectionDocumentTypes registers one document type per collection, id == name.
      const collectionFilter =
        query.filters?.collections && query.filters.collections.length > 0
          ? query.filters.collections
          : settings.selected_collections.length > 0
            ? settings.selected_collections
            : null
      if (collectionFilter) {
        conditions.push(`d.type_id IN (${collectionFilter.map(() => '?').join(',')})`)
        params.push(...collectionFilter.map(String))
      }

      if (query.filters?.status && query.filters.status.length > 0) {
        conditions.push(`d.status IN (${query.filters.status.map(() => '?').join(',')})`)
        params.push(...query.filters.status)
      }

      // documents timestamps are SECONDS (legacy `content` used ms) and the filter arrives as a Date.
      if (query.filters?.dateRange) {
        const field = query.filters.dateRange.field === 'updated_at' ? 'updated_at' : 'created_at'
        if (query.filters.dateRange.start) {
          conditions.push(`d.${field} >= ?`)
          params.push(Math.floor(query.filters.dateRange.start.getTime() / 1000))
        }
        if (query.filters.dateRange.end) {
          conditions.push(`d.${field} <= ?`)
          params.push(Math.floor(query.filters.dateRange.end.getTime() / 1000))
        }
      }

      if (query.filters?.author) {
        conditions.push('(d.owner_id = ? OR d.created_by = ?)')
        params.push(query.filters.author, query.filters.author)
      }

      const whereClause = `WHERE ${conditions.join(' AND ')}`
      const limit = query.limit || settings.results_limit
      const offset = query.offset || 0

      const [countResult, listed] = await Promise.all([
        this.db
          .prepare(`SELECT COUNT(*) as count FROM documents d ${whereClause}`)
          .bind(...params)
          .first<{ count: number }>(),
        this.db
          .prepare(
            `SELECT
               d.id, d.root_id, d.type_id, d.title, d.slug, d.status, d.data,
               d.created_at, d.updated_at, u.email as author_email
             FROM documents d
             LEFT JOIN auth_user u ON u.id = d.owner_id
             ${whereClause}
             ORDER BY d.updated_at DESC, d.id DESC
             LIMIT ? OFFSET ?`
          )
          .bind(...params, limit, offset)
          .all<{
            id: string
            root_id: string
            type_id: string
            title: string | null
            slug: string | null
            status: string
            data: string
            created_at: number
            updated_at: number
            author_email?: string
          }>(),
      ])

      const rows = listed.results ?? []

      // One type lookup per distinct type on the page (the registry caches), then isAllowed per row.
      // A type with no public base grant — contact_message, say — resolves to false and never
      // surfaces in search results.
      const typeRegistry = new DocumentTypeRegistry(this.db)
      const repo = new DocumentRepository(this.db, this.tenantId)
      const typeSettings = new Map<string, DocumentTypeSettings | undefined>()
      for (const typeId of new Set(rows.map((r) => r.type_id))) {
        typeSettings.set(typeId, (await typeRegistry.findById(typeId))?.settings)
      }
      const allowed = await Promise.all(
        rows.map((row) => {
          const docTypeSettings = typeSettings.get(row.type_id)
          return docTypeSettings
            ? repo.isAllowed(principalSet, row.root_id, 'read', docTypeSettings)
            : Promise.resolve(false)
        })
      )

      const registry = getCollectionRegistry()
      const searchResults: SearchResult[] = rows
        .filter((_, i) => allowed[i])
        .map((row) => {
          const collection = registry.getById(row.type_id) ?? registry.getByName(row.type_id)
          return {
            id: String(row.id),
            title: row.title || 'Untitled',
            slug: row.slug || '',
            collection_id: row.type_id,
            collection_name: collection?.displayName || collection?.name || row.type_id,
            snippet: this.extractSnippet(row.data, query.query),
            status: row.status,
            // documents stores seconds; callers (and the legacy shape) expect ms.
            created_at: documentSecondsToMs(row.created_at) ?? 0,
            updated_at: documentSecondsToMs(row.updated_at) ?? 0,
            author_name: row.author_email ?? undefined,
          }
        })

      // Matches before the per-document ACL pass, which is what the query itself found. The public
      // document API reports its pagination off the raw page the same way.
      const total = countResult?.count || 0
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
   * Pull a readable excerpt around the match out of a document's JSON `data`.
   *
   * Two fixes over the previous version, both visible in any search response: it searched and
   * returned `JSON.stringify(data).toLowerCase()`, so every snippet came back lowercased with the
   * JSON envelope still in it (`{"title":"welcome to sonicjs","slug":...`). Now the match is found
   * case-insensitively but the excerpt is cut from the original text, and the text is the string
   * values joined — the same shape the indexer feeds the embedding model — so no braces, keys or
   * quotes reach the caller.
   */
  private extractSnippet(data: string, query: string): string {
    try {
      const parsed: unknown = typeof data === 'string' ? JSON.parse(data) : data

      const parts: string[] = []
      const collect = (value: unknown): void => {
        if (typeof value === 'string') parts.push(value)
        else if (Array.isArray(value)) value.forEach(collect)
        else if (value && typeof value === 'object') Object.values(value).forEach(collect)
      }
      collect(parsed)

      // Strip HTML so a match inside markup does not come back as half a tag.
      const text = parts.join(' ').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()
      if (!text) return ''

      const index = query ? text.toLowerCase().indexOf(query.toLowerCase()) : -1
      if (index === -1) {
        return text.length > 200 ? `${text.substring(0, 200)}...` : text
      }

      const start = Math.max(0, index - 50)
      const end = Math.min(text.length, index + query.length + 50)
      return `${start > 0 ? '...' : ''}${text.substring(start, end)}${end < text.length ? '...' : ''}`
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
        SELECT json_extract(data, '$.query') AS query, MAX(created_at) AS last_used
        FROM documents
        WHERE type_id = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
          AND json_extract(data, '$.query') LIKE ?
        GROUP BY query
        ORDER BY last_used DESC
        LIMIT 10
      `)
      const { results } = await stmt
        .bind(HISTORY_TYPE, this.tenantId, `%${partial}%`)
        .all<{ query: string }>()

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
      const docId = crypto.randomUUID()
      const now = Math.floor(Date.now() / 1000)
      // `/api/search` is public, so `query` is anonymous user input that lands in a row kept for
      // analytics. Cap it: the search itself ignores anything past a sane length, and an
      // unbounded string here would be stored forever.
      const data = JSON.stringify({ query: query.slice(0, 200), mode, resultsCount })
      // R5: 17 columns, 7 ? binds (docId x2, slug, title, data, now x2), 10 literals - verified
      const stmt = this.db.prepare(`
        INSERT INTO documents (
          id, root_id, type_id, version_number, is_current_draft, is_published, status,
          parent_root_id, slug, title, tenant_id, locale, translation_group_id,
          data, metadata, created_at, updated_at
        ) VALUES (
          ?, ?, 'ai_search_history', 1, 1, 0, 'draft',
          '', ?, ?, ?, 'default', '',
          ?, '{}', ?, ?
        )
      `)
      await stmt.bind(docId, docId, docId, mode, this.tenantId, data, now, now).run()
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
      // documents.created_at is in seconds, not the milliseconds the old history table used.
      const thirtyDaysAgo = Math.floor(Date.now() / 1000) - 30 * 24 * 60 * 60
      const totalStmt = this.db.prepare(`
        SELECT COUNT(*) as count
        FROM documents
        WHERE ${HISTORY_SCOPE} AND created_at >= ?
      `)
      const totalResult = await totalStmt
        .bind(HISTORY_TYPE, this.tenantId, thirtyDaysAgo)
        .first<{ count: number }>()

      // AI vs Keyword breakdown
      const modeStmt = this.db.prepare(`
        SELECT json_extract(data, '$.mode') AS mode, COUNT(*) as count
        FROM documents
        WHERE ${HISTORY_SCOPE} AND created_at >= ?
        GROUP BY mode
      `)
      const { results: modeResults } = await modeStmt
        .bind(HISTORY_TYPE, this.tenantId, thirtyDaysAgo)
        .all<{ mode: string; count: number }>()

      const aiCount = modeResults?.find((r) => r.mode === 'ai')?.count || 0
      const keywordCount = modeResults?.find((r) => r.mode === 'keyword')?.count || 0

      // Popular queries
      const popularStmt = this.db.prepare(`
        SELECT json_extract(data, '$.query') AS query, COUNT(*) as count
        FROM documents
        WHERE ${HISTORY_SCOPE} AND created_at >= ?
        GROUP BY query
        ORDER BY count DESC
        LIMIT 10
      `)
      const { results: popularResults } = await popularStmt
        .bind(HISTORY_TYPE, this.tenantId, thirtyDaysAgo)
        .all<{ query: string; count: number }>()

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
