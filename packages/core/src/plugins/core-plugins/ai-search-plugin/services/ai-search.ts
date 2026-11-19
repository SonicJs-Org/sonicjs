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
import { DocumentRepository } from '../../../../services/document-repository'
import { DocumentTypeRegistry } from '../../../../services/document-type-registry'
import { documentSecondsToMs } from '../../../../services/documents'
import { PluginService } from '../../../../services/plugin-service'
import type { DocumentTypeSettings, PrincipalRef } from '../../../../schemas/document'
import { Fts5Engine } from './fts5-engine'
import { getFtsSettings } from './fts-settings.service'
import { getCachedResult, putCachedResult } from './fts-search-cache'

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
    private tenantId: string = 'default',
    private kv?: KVNamespace, // CACHE_KV — lexical settings + result cache
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

    // Use AI Search if enabled, mode is 'ai', and the bindings exist.
    const wantAI = query.mode === 'ai'
    if (wantAI && settings.ai_mode_enabled && this.customRAG?.isAvailable()) {
      return this.searchAI(query, settings, principalSet)
    }

    // Lexical (keyword) floor over documents_fts.
    const result = await this.searchKeyword(query, settings, principalSet)
    // LA4 degrade contract: an 'ai' request served by the lexical floor is flagged, never broken.
    if (wantAI) result.degraded = true
    return result
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
        return { ...(await this.searchKeyword(query, settings, principalSet)), degraded: true }
      }

      // Use Custom RAG for semantic search - pass the full query object and settings
      const result = await this.customRAG.search(query, settings)

      return result
    } catch (error) {
      console.error('[AISearchService] AI search error, falling back to keyword:', error)
      // Fallback to keyword search (LA4: degraded, never broken).
      return { ...(await this.searchKeyword(query, settings, principalSet)), degraded: true }
    }
  }

  /**
   * Document type ids whose base grants allow public read (settings.baseGrants.public includes
   * 'read'). The unauthenticated /api/search path is restricted to these so that indexed-but-internal
   * types never surface to anonymous callers (D5). Fails closed: any error yields an empty allowlist,
   * which makes keyword search return nothing rather than over-share.
   */
  private async publicReadableTypeIds(): Promise<string[]> {
    try {
      const types = await new DocumentTypeRegistry(this.db).findAll(true)
      return types.filter((t) => t.settings?.baseGrants?.public?.includes('read')).map((t) => t.id)
    } catch {
      return []
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

      // SECURITY (D5): /api/search is unauthenticated, so keyword results are limited to document
      // types that grant public read. Internal/admin-only types (api_key, security_event,
      // analytics_event, user_profile, rbac_*, site_settings, …) are indexed for admin tooling but
      // must never surface to an anonymous caller. Authed admin draft/all-type search is a separate
      // future endpoint, not this one.
      const publicTypeIds = await this.publicReadableTypeIds()

      // Resolve the requested type set, then intersect with the public allowlist: a client-supplied
      // `filters.collections` (or a misconfigured `searchableTypes`) can only ever NARROW the scope,
      // never widen it to an internal type.
      const requested = query.filters?.collections?.length
        ? query.filters.collections
        : fts.searchableTypes.length
          ? fts.searchableTypes
          : settings.selected_collections.length
            ? settings.selected_collections
            : publicTypeIds
      const typeIds = requested.filter((t) => publicTypeIds.includes(t))

      // No publicly-readable type in scope → return empty. This guard is REQUIRED: the engine treats
      // an empty/omitted typeIds as "no type filter = ALL types", so calling it here would leak
      // exactly the internal types the allowlist just excluded.
      if (typeIds.length === 0) {
        return { results: [], total: 0, query_time_ms: Date.now() - startTime, mode: query.mode }
      }

      const { hits, total } = await engine.search({
        query: query.query,
        tenantId: this.tenantId,
        typeIds,
        // Server-authoritative: the public endpoint returns published documents only. Never derived
        // from client-supplied `filters.status` — that previously let `status:['draft']` drop the
        // published gate and expose every draft in the tenant.
        publishedOnly: true,
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
        // FTS snapshots documents.* in SECONDS; the response boundary is ms (search-modal renders
        // `new Date(created_at)`). Convert here or every keyword hit dates to Jan 1970.
        created_at: documentSecondsToMs(h.createdAt) ?? h.createdAt,
        updated_at: documentSecondsToMs(h.updatedAt) ?? h.updatedAt,
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
