/**
 * Custom RAG Service
 * Implements full RAG pipeline using Cloudflare Vectorize
 * 
 * Fulfills GitHub Issue #362: Advanced search with Cloudflare Search
 */

import type { D1Database } from '@cloudflare/workers-types'
import { EmbeddingService } from './embedding.service'
import { ChunkingService, type ContentChunk } from './chunking.service'
import type { SearchQuery, SearchResponse, SearchResult, AISearchSettings } from '../types'

export class CustomRAGService {
  private embeddingService: EmbeddingService
  private chunkingService: ChunkingService

  constructor(
    private db: D1Database,
    private ai: any,
    private vectorize: any
  ) {
    this.embeddingService = new EmbeddingService(ai)
    this.chunkingService = new ChunkingService()
  }

  /**
   * Index all content from a collection.
   * onProgress reports (phase, processedItems, totalItems) so callers can update UI.
   * Phases: 'chunking' → 'embedding' → 'storing'
   */
  async indexCollection(
    collectionId: string,
    onProgress?: (phase: string, processed: number, total: number) => Promise<void>
  ): Promise<{
    total_items: number
    total_chunks: number
    indexed_chunks: number
    errors: number
  }> {
    console.log(`[CustomRAG] Starting indexing for collection: ${collectionId}`)

    try {
      // Get all published content from collection
      const { results: contentItems } = await this.db
        .prepare(`
          SELECT c.id, c.title, c.data, c.collection_id, c.status,
                 c.created_at, c.updated_at, c.author_id,
                 col.name as collection_name, col.display_name as collection_display_name
          FROM content c
          JOIN collections col ON c.collection_id = col.id
          WHERE c.collection_id = ? AND c.status != 'deleted'
        `)
        .bind(collectionId)
        .all<{
          id: string
          title: string
          data: string
          collection_id: string
          status: string
          created_at: number
          updated_at: number
          author_id?: string
          collection_name: string
          collection_display_name: string
        }>()

      const totalItems = contentItems?.length || 0

      if (totalItems === 0) {
        console.log(`[CustomRAG] No content found in collection ${collectionId}`)
        return { total_items: 0, total_chunks: 0, indexed_chunks: 0, errors: 0 }
      }

      // Chunk all content
      if (onProgress) await onProgress('chunking', 0, totalItems)

      const items = (contentItems || []).map(item => ({
        id: item.id,
        collection_id: item.collection_id,
        title: item.title || 'Untitled',
        data: typeof item.data === 'string' ? JSON.parse(item.data) : item.data,
        metadata: {
          status: item.status,
          created_at: item.created_at,
          updated_at: item.updated_at,
          author_id: item.author_id,
          collection_name: item.collection_name,
          collection_display_name: item.collection_display_name
        }
      }))

      const chunks = this.chunkingService.chunkContentBatch(items)
      const totalChunks = chunks.length

      console.log(`[CustomRAG] Generated ${totalChunks} chunks from ${totalItems} items`)

      // Generate embeddings with progress callback
      if (onProgress) await onProgress('embedding', 0, totalChunks)

      const embeddings = await this.embeddingService.generateBatch(
        chunks.map(c => `${c.title}\n\n${c.text}`),
        onProgress ? async (completed, total) => {
          await onProgress('embedding', completed, total)
        } : undefined
      )

      console.log(`[CustomRAG] Generated ${embeddings.length} embeddings`)

      // Store in Vectorize
      if (onProgress) await onProgress('storing', 0, totalChunks)

      let indexedChunks = 0
      let errors = 0
      const batchSize = 100

      for (let i = 0; i < chunks.length; i += batchSize) {
        const chunkBatch = chunks.slice(i, i + batchSize)
        const embeddingBatch = embeddings.slice(i, i + batchSize)

        try {
          await this.vectorize.upsert(
            chunkBatch.map((chunk, idx) => ({
              id: chunk.id,
              values: embeddingBatch[idx],
              metadata: {
                content_id: chunk.content_id,
                collection_id: chunk.collection_id,
                title: chunk.title,
                text: chunk.text.substring(0, 500),
                chunk_index: chunk.chunk_index,
                ...chunk.metadata
              }
            }))
          )

          indexedChunks += chunkBatch.length
          if (onProgress) await onProgress('storing', indexedChunks, totalChunks)
        } catch (error) {
          console.error(`[CustomRAG] Error indexing batch ${i / batchSize + 1}:`, error)
          errors += chunkBatch.length
        }
      }

      console.log(`[CustomRAG] Indexing complete: ${indexedChunks}/${totalChunks} chunks indexed`)

      return {
        total_items: totalItems,
        total_chunks: totalChunks,
        indexed_chunks: indexedChunks,
        errors
      }
    } catch (error) {
      console.error(`[CustomRAG] Error indexing collection ${collectionId}:`, error)
      throw error
    }
  }

  /**
   * Auto-index content in selected collections that hasn't been indexed into Vectorize yet.
   * Mirrors FTS5's ensureCollectionsIndexed() self-healing pattern.
   */
  private async ensureCollectionsIndexed(collections: string[]): Promise<void> {
    if (collections.length === 0) return

    try {
      // Check which collections have been indexed via ai_search_index_meta
      // Require both 'completed' status AND indexed_items > 0 to avoid
      // false positives from IndexManager marking empty indexes as completed
      const placeholders = collections.map(() => '?').join(', ')
      const { results: indexedCollections } = await this.db
        .prepare(`
          SELECT collection_id, status, indexed_items FROM ai_search_index_meta
          WHERE collection_id IN (${placeholders}) AND status = 'completed' AND indexed_items > 0
        `)
        .bind(...collections)
        .all<{ collection_id: string; status: string; indexed_items: number }>()

      const completedIds = new Set((indexedCollections || []).map(r => r.collection_id))
      const unindexedCollections = collections.filter(id => !completedIds.has(id))

      if (unindexedCollections.length === 0) return

      console.log(`[CustomRAG] Auto-indexing ${unindexedCollections.length} collection(s) into Vectorize...`)

      for (const collectionId of unindexedCollections) {
        try {
          // Mark as indexing
          await this.db
            .prepare(`
              INSERT OR REPLACE INTO ai_search_index_meta(collection_id, collection_name, status, total_items, indexed_items)
              VALUES (?, ?, 'indexing', 0, 0)
            `)
            .bind(collectionId, collectionId)
            .run()

          const result = await this.indexCollection(collectionId)

          // Mark as completed
          await this.db
            .prepare(`
              UPDATE ai_search_index_meta
              SET status = 'completed', total_items = ?, indexed_items = ?, last_sync_at = ?
              WHERE collection_id = ?
            `)
            .bind(result.total_items, result.indexed_chunks, Date.now(), collectionId)
            .run()

          console.log(`[CustomRAG] Auto-indexed collection ${collectionId}: ${result.indexed_chunks} chunks from ${result.total_items} items`)
        } catch (error) {
          console.error(`[CustomRAG] Error auto-indexing collection ${collectionId}:`, error)
          // Mark as error but don't fail the search
          await this.db
            .prepare(`
              UPDATE ai_search_index_meta SET status = 'error', error_message = ?
              WHERE collection_id = ?
            `)
            .bind(String(error), collectionId)
            .run().catch(() => {})
        }
      }
    } catch (error) {
      // Don't fail the search if auto-indexing fails
      console.error('[CustomRAG] Error during auto-indexing check:', error)
    }
  }

  /**
   * Search using RAG (semantic search with Vectorize)
   */
  async search(query: SearchQuery, settings: AISearchSettings): Promise<SearchResponse> {
    const startTime = Date.now()

    try {
      // Auto-index selected collections that haven't been indexed yet
      const collections = query.filters?.collections?.length
        ? query.filters.collections
        : settings.selected_collections
      await this.ensureCollectionsIndexed(collections)

      // Generate query embedding
      const queryEmbedding = await this.embeddingService.generateEmbedding(query.query)

      // Build Vectorize query filters
      const filter: any = {}
      
      if (query.filters?.collections && query.filters.collections.length > 0) {
        filter.collection_id = { $in: query.filters.collections }
      } else if (settings.selected_collections.length > 0) {
        filter.collection_id = { $in: settings.selected_collections }
      }

      if (query.filters?.status && query.filters.status.length > 0) {
        filter.status = { $in: query.filters.status }
      }

      // Vectorize filters have issues, so we query without filter and manually filter results
      const vectorResults = await this.vectorize.query(queryEmbedding, {
        topK: 50, // Max allowed with returnMetadata: true
        returnMetadata: 'all'
      })

      // Manually filter results by collection_id if filter exists
      let filteredMatches = vectorResults.matches || []
      if (filter.collection_id?.$in && Array.isArray(filter.collection_id.$in)) {
        const allowedCollections = filter.collection_id.$in
        const beforeCount = filteredMatches.length
        filteredMatches = filteredMatches.filter((match: any) =>
          allowedCollections.includes(match.metadata?.collection_id)
        )
      }

      // Apply status filter if exists
      if (filter.status?.$in && Array.isArray(filter.status.$in)) {
        const allowedStatuses = filter.status.$in
        filteredMatches = filteredMatches.filter((match: any) =>
          allowedStatuses.includes(match.metadata?.status)
        )
      }

      // Limit to requested topK
      const topK = query.limit || settings.results_limit || 20
      filteredMatches = filteredMatches.slice(0, topK)

      // Replace matches with filtered results
      vectorResults.matches = filteredMatches

      if (!vectorResults.matches || vectorResults.matches.length === 0) {
        return {
          results: [],
          total: 0,
          query_time_ms: Date.now() - startTime,
          mode: 'ai'
        }
      }

      // Get unique content IDs from Vectorize matches
      const contentIds = [...new Set(
        vectorResults.matches.map((m: any) => m.metadata.content_id)
      )]


      // Fetch full content from D1
      const placeholders = contentIds.map(() => '?').join(',')
      const { results: contentItems } = await this.db
        .prepare(`
          SELECT c.id, c.title, c.slug, c.collection_id, c.status,
                 c.created_at, c.updated_at, c.author_id,
                 col.display_name as collection_name
          FROM content c
          JOIN collections col ON c.collection_id = col.id
          WHERE c.id IN (${placeholders})
        `)
        .bind(...contentIds)
        .all<{
          id: string
          title: string
          slug: string
          collection_id: string
          collection_name: string
          status: string
          created_at: number
          updated_at: number
          author_id?: string
        }>()

      // Only include results that exist in D1 (skip stale Vectorize entries)
      const d1Map = new Map((contentItems || []).map(item => [item.id, item]))

      // Deduplicate by content_id, keeping the best score per content item
      const bestByContent = new Map<string, any>()
      for (const match of vectorResults.matches) {
        const cid = match.metadata?.content_id
        if (!cid || !d1Map.has(cid)) continue  // Skip stale entries
        const existing = bestByContent.get(cid)
        if (!existing || match.score > existing.score) {
          bestByContent.set(cid, match)
        }
      }

      // Sort by score descending and apply score filtering.
      // Skip filtering in hybrid mode — RRF handles ranking and needs the full candidate set.
      const sortedEntries = [...bestByContent.entries()]
        .sort((a, b) => b[1].score - a[1].score)

      if (query.mode !== 'hybrid') {
        const MIN_RELEVANCE_SCORE = 0.45
        const SCORE_GAP_THRESHOLD = 0.15
        const filteredEntries: [string, any][] = []
        for (let i = 0; i < sortedEntries.length; i++) {
          const entry = sortedEntries[i]!
          const score = entry[1].score
          if (score < MIN_RELEVANCE_SCORE) break

          if (i > 0) {
            const prevScore = sortedEntries[i - 1]![1].score
            const gap = prevScore - score
            if (gap > SCORE_GAP_THRESHOLD) {
              break
            }
          }

          filteredEntries.push(entry)
        }

        bestByContent.clear()
        for (const [key, value] of filteredEntries) {
          bestByContent.set(key, value)
        }
      }

      const searchResults: SearchResult[] = []
      for (const [contentId, bestMatch] of bestByContent) {
        const d1Item = d1Map.get(contentId)!
        searchResults.push({
          id: d1Item.id,
          title: d1Item.title || 'Untitled',
          slug: d1Item.slug || '',
          collection_id: d1Item.collection_id,
          collection_name: d1Item.collection_name,
          snippet: bestMatch.metadata?.text || '',
          relevance_score: bestMatch.score || 0,
          status: d1Item.status,
          created_at: d1Item.created_at,
          updated_at: d1Item.updated_at
        })
      }

      // Sort by relevance score
      searchResults.sort((a, b) => (b.relevance_score || 0) - (a.relevance_score || 0))

      const queryTime = Date.now() - startTime
      console.log(`[CustomRAG] Search completed in ${queryTime}ms, ${searchResults.length} results`)

      return {
        results: searchResults,
        total: searchResults.length,
        query_time_ms: queryTime,
        mode: 'ai'
      }
    } catch (error) {
      console.error('[CustomRAG] Search error:', error)
      throw error
    }
  }

  /**
   * Update index for a single content item
   */
  async updateContentIndex(contentId: string): Promise<void> {
    try {
      // Get content item
      const content = await this.db
        .prepare(`
          SELECT c.id, c.title, c.data, c.collection_id, c.status,
                 c.created_at, c.updated_at, c.author_id,
                 col.name as collection_name, col.display_name as collection_display_name
          FROM content c
          JOIN collections col ON c.collection_id = col.id
          WHERE c.id = ?
        `)
        .bind(contentId)
        .first<{
          id: string
          title: string
          data: string
          collection_id: string
          status: string
          created_at: number
          updated_at: number
          author_id?: string
          collection_name: string
          collection_display_name: string
        }>()

      if (!content) {
        console.warn(`[CustomRAG] Content ${contentId} not found`)
        return
      }

      // If content is not published, remove from index
      if (content.status !== 'published') {
        await this.removeContentFromIndex(contentId)
        return
      }

      // Chunk content
      const chunks = this.chunkingService.chunkContent(
        content.id,
        content.collection_id,
        content.title || 'Untitled',
        typeof content.data === 'string' ? JSON.parse(content.data) : content.data,
        {
          status: content.status,
          created_at: content.created_at,
          updated_at: content.updated_at,
          author_id: content.author_id,
          collection_name: content.collection_name,
          collection_display_name: content.collection_display_name
        }
      )

      // Generate embeddings
      const embeddings = await this.embeddingService.generateBatch(
        chunks.map(c => `${c.title}\n\n${c.text}`)
      )

      // Update in Vectorize
      await this.vectorize.upsert(
        chunks.map((chunk, idx) => ({
          id: chunk.id,
          values: embeddings[idx],
          metadata: {
            content_id: chunk.content_id,
            collection_id: chunk.collection_id,
            title: chunk.title,
            text: chunk.text.substring(0, 500),
            chunk_index: chunk.chunk_index,
            ...chunk.metadata
          }
        }))
      )

      console.log(`[CustomRAG] Updated index for content ${contentId}: ${chunks.length} chunks`)
    } catch (error) {
      console.error(`[CustomRAG] Error updating index for ${contentId}:`, error)
      throw error
    }
  }

  /**
   * Remove content from index
   */
  async removeContentFromIndex(contentId: string): Promise<void> {
    try {
      // Note: Vectorize doesn't have a bulk delete by metadata filter
      // We need to delete each chunk individually
      // In practice, we would track chunk IDs or use a different approach
      
      console.log(`[CustomRAG] Removing content ${contentId} from index`)
      
      // For now, we'll let stale chunks age out
      // A better approach would be to maintain a mapping in D1
      // TODO: Implement proper chunk tracking
      
    } catch (error) {
      console.error(`[CustomRAG] Error removing content ${contentId}:`, error)
      throw error
    }
  }

  /**
   * Get search suggestions based on query
   */
  async getSuggestions(partialQuery: string, limit: number = 5): Promise<string[]> {
    try {
      // Generate embedding for partial query
      const queryEmbedding = await this.embeddingService.generateEmbedding(partialQuery)

      // Search for similar content titles
      const results = await this.vectorize.query(queryEmbedding, {
        topK: limit * 2, // Get more to filter
        returnMetadata: true
      })

      // Extract unique titles
      const suggestions = [...new Set(
        results.matches?.map((m: any) => m.metadata.title).filter(Boolean) || []
      )].slice(0, limit)

      return suggestions as string[]
    } catch (error) {
      console.error('[CustomRAG] Error getting suggestions:', error)
      return []
    }
  }

  /**
   * Check if Vectorize is available and configured
   */
  isAvailable(): boolean {
    return !!this.vectorize && !!this.ai
  }
}
