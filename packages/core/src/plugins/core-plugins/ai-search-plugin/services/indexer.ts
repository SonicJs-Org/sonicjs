import type { D1Database } from '@cloudflare/workers-types'
import type { AISearchSettings, IndexStatus } from '../types'
import { CustomRAGService } from './custom-rag.service'
import { FTS5Service } from './fts5.service'

/**
 * Index Manager Service
 * Handles indexing of content items using Custom RAG with Vectorize
 * Falls back to FTS5 indexing when Vectorize is not available
 */
export class IndexManager {
  private customRAG?: CustomRAGService
  private fts5Service: FTS5Service

  constructor(
    private db: D1Database,
    private ai?: any, // Workers AI for embeddings
    private vectorize?: any // Vectorize for vector search
  ) {
    this.fts5Service = new FTS5Service(db)

    // Initialize Custom RAG if bindings are available
    if (this.ai && this.vectorize) {
      this.customRAG = new CustomRAGService(db, ai, vectorize)
      console.log('[IndexManager] Custom RAG initialized')
    }
  }

  /**
   * Index all content items within a collection using Custom RAG
   */
  async indexCollection(collectionId: string): Promise<IndexStatus> {
    try {
      // Get collection info
      const collectionStmt = this.db.prepare(
        'SELECT id, name, display_name FROM collections WHERE id = ?'
      )
      const collection = await collectionStmt.bind(collectionId).first<{
        id: string
        name: string
        display_name: string
      }>()

      if (!collection) {
        throw new Error(`Collection ${collectionId} not found`)
      }

      // Count total items before setting status so progress bar shows correctly
      const countResult = await this.db.prepare(
        "SELECT COUNT(*) as cnt FROM content WHERE collection_id = ? AND status != 'deleted'"
      ).bind(collectionId).first<{ cnt: number }>()
      const totalItems = countResult?.cnt || 0

      // Update status to indexing with actual total
      await this.updateIndexStatus(collectionId, {
        collection_id: collectionId,
        collection_name: collection.display_name,
        total_items: totalItems,
        indexed_items: 0,
        status: 'indexing',
      })

      // Use Custom RAG for indexing if available
      if (this.customRAG?.isAvailable()) {
        console.log(`[IndexManager] Using Custom RAG to index collection ${collectionId}`)

        // Track highest progress to prevent UI from jumping backward between phases
        let highWaterMark = 0

        let result: { total_items: number; total_chunks: number; indexed_chunks: number; errors: number }
        try {
          result = await this.customRAG.indexCollection(
            collectionId,
            async (phase, processed, total) => {
              // Map chunk progress to approximate item progress for the UI
              // Embedding phase = 0-90%, storing phase = 90-100%
              let itemProgress: number
              if (phase === 'chunking') {
                itemProgress = 0
              } else if (phase === 'embedding') {
                // Embedding is the slow part — map to 0-90% of total items
                itemProgress = Math.round((processed / Math.max(total, 1)) * totalItems * 0.9)
              } else {
                // Storing phase — map to 90-100% of total items
                itemProgress = Math.round(totalItems * 0.9 + (processed / Math.max(total, 1)) * totalItems * 0.1)
              }
              itemProgress = Math.min(totalItems, itemProgress)
              // Never go backward
              if (itemProgress > highWaterMark) {
                highWaterMark = itemProgress
              }
              await this.updateIndexStatus(collectionId, {
                collection_id: collectionId,
                collection_name: collection.display_name,
                total_items: totalItems,
                indexed_items: highWaterMark,
                status: 'indexing',
              })
            }
          )
        } catch (ragError) {
          // Ensure we mark as error even if the Worker is about to die
          console.error(`[IndexManager] CustomRAG indexing failed for ${collectionId}:`, ragError)
          await this.updateIndexStatus(collectionId, {
            collection_id: collectionId,
            collection_name: collection.display_name,
            total_items: totalItems,
            indexed_items: highWaterMark,
            status: 'error',
            error_message: ragError instanceof Error ? ragError.message : String(ragError),
          })
          return {
            collection_id: collectionId,
            collection_name: collection.display_name,
            total_items: totalItems,
            indexed_items: highWaterMark,
            status: 'error' as const,
            error_message: ragError instanceof Error ? ragError.message : String(ragError),
          }
        }

        const finalStatus: IndexStatus = {
          collection_id: collectionId,
          collection_name: collection.display_name,
          total_items: result.total_items,
          indexed_items: result.total_items, // Use total_items, not chunks, for final display
          last_sync_at: Date.now(),
          status: result.errors > 0 ? 'error' : 'completed',
          error_message: result.errors > 0 ? `${result.errors} errors during indexing` : undefined
        }

        await this.updateIndexStatus(collectionId, finalStatus)
        return finalStatus
      }

      // Fallback: No Vectorize — use FTS5 for indexing
      console.log(`[IndexManager] Using FTS5 to index collection ${collectionId}`)

      // Check if FTS5 is available
      const fts5Available = await this.fts5Service.isAvailable()

      if (fts5Available) {
        // Run FTS5 indexing with progress updates
        const fts5Result = await this.fts5Service.indexCollection(
          collectionId,
          async (indexed, total) => {
            // Update progress in the database so polling picks it up
            await this.updateIndexStatus(collectionId, {
              collection_id: collectionId,
              collection_name: collection.display_name,
              total_items: total,
              indexed_items: indexed,
              status: 'indexing',
            })
          }
        )

        const fallbackStatus: IndexStatus = {
          collection_id: collectionId,
          collection_name: collection.display_name,
          total_items: fts5Result.total_items,
          indexed_items: fts5Result.indexed_items,
          last_sync_at: Date.now(),
          status: fts5Result.errors > 0 ? 'error' : 'completed',
          error_message: fts5Result.errors > 0 ? `${fts5Result.errors} errors during FTS5 indexing` : undefined
        }

        await this.updateIndexStatus(collectionId, fallbackStatus)
        return fallbackStatus
      }

      // No FTS5 either — just count content items for display
      console.warn(`[IndexManager] No FTS5 available, counting content items for ${collectionId}`)
      const fallbackCount = await this.db.prepare(
        'SELECT COUNT(*) as cnt FROM content WHERE collection_id = ?'
      ).bind(collectionId).first<{ cnt: number }>()

      const fallbackStatus: IndexStatus = {
        collection_id: collectionId,
        collection_name: collection.display_name,
        total_items: fallbackCount?.cnt || 0,
        indexed_items: 0,
        last_sync_at: Date.now(),
        status: 'completed',
        error_message: 'No search index available (Vectorize and FTS5 both unavailable)'
      }

      await this.updateIndexStatus(collectionId, fallbackStatus)
      return fallbackStatus
    } catch (error) {
      console.error(`[IndexManager] Error indexing collection ${collectionId}:`, error)
      const errorStatus: IndexStatus = {
        collection_id: collectionId,
        collection_name: 'Unknown',
        total_items: 0,
        indexed_items: 0,
        status: 'error',
        error_message: error instanceof Error ? error.message : String(error),
      }
      await this.updateIndexStatus(collectionId, errorStatus)
      return errorStatus
    }
  }

  /**
   * Index a single content item
   */
  private async indexContentItem(
    item: {
      id: string
      title: string
      slug: string
      data: string
      status: string
      created_at: number
      updated_at: number
      author_id?: string
      collection_name: string
      collection_display_name: string
    },
    collectionId: string
  ): Promise<void> {
        try {
          // Parse content data
          let parsedData: any = {}
          try {
            parsedData = typeof item.data === 'string' ? JSON.parse(item.data) : item.data
          } catch {
            parsedData = {}
          }

          // Prepare document for AI Search
          const document = {
            id: `content_${item.id}`,
            title: item.title || 'Untitled',
            slug: item.slug || '',
            content: this.extractSearchableText(parsedData),
            metadata: {
              collection_id: collectionId,
              collection_name: item.collection_name,
              collection_display_name: item.collection_display_name,
              status: item.status,
              created_at: item.created_at,
              updated_at: item.updated_at,
              author_id: item.author_id,
            },
          }

      // TODO: Call Cloudflare AI Search API to index document
      // await this.aiSearch.index(document)

      // For now, just log (actual implementation will use AI Search API)
      console.log(`Indexed content item: ${item.id}`)
    } catch (error) {
      console.error(`Error indexing content item ${item.id}:`, error)
      throw error
    }
  }

  /**
   * Extract searchable text from content data
   */
  private extractSearchableText(data: any): string {
    const parts: string[] = []

    // Add title if present
    if (data.title) parts.push(String(data.title))
    if (data.name) parts.push(String(data.name))

    // Add description/content fields
    if (data.description) parts.push(String(data.description))
    if (data.content) parts.push(String(data.content))
    if (data.body) parts.push(String(data.body))
    if (data.text) parts.push(String(data.text))

    // Add all string values from data
    const extractStrings = (obj: any): void => {
      if (typeof obj === 'string') {
        parts.push(obj)
      } else if (Array.isArray(obj)) {
        obj.forEach(extractStrings)
      } else if (obj && typeof obj === 'object') {
        Object.values(obj).forEach(extractStrings)
      }
    }

    extractStrings(data)

    return parts.join(' ')
  }

  /**
   * Update a single content item in the index
   */
  async updateIndex(collectionId: number, contentId: string): Promise<void> {
    try {
      // Get content item
          const stmt = this.db.prepare(`
            SELECT 
              c.id, c.title, c.slug, c.data, c.status,
              c.created_at, c.updated_at, c.author_id,
              col.name as collection_name, col.display_name as collection_display_name
            FROM content c
            JOIN collections col ON c.collection_id = col.id
            WHERE c.id = ? AND c.collection_id = ?
          `)
          const item = await stmt.bind(contentId, collectionId).first<{
            id: string
            title: string
            slug: string
            data: string
            status: string
            created_at: number
            updated_at: number
            author_id?: string
            collection_name: string
            collection_display_name: string
          }>()

      if (!item) {
        throw new Error(`Content item ${contentId} not found`)
      }

      // Re-index the item
      await this.indexContentItem(item, String(collectionId))

      // Update last sync time for collection
      const status = await this.getIndexStatus(String(collectionId))
      if (status) {
        await this.updateIndexStatus(String(collectionId), {
          ...status,
          last_sync_at: Date.now(),
        })
      }
    } catch (error) {
      console.error(`Error updating index for content ${contentId}:`, error)
      throw error
    }
  }

  /**
   * Remove a content item from the index using Custom RAG
   */
  async removeFromIndex(collectionId: string, contentId: string): Promise<void> {
    try {
      if (this.customRAG?.isAvailable()) {
        console.log(`[IndexManager] Removing content ${contentId} from index`)
        await this.customRAG.removeContentFromIndex(contentId)
      } else {
        console.warn(`[IndexManager] Custom RAG not available, skipping removal for ${contentId}`)
      }
    } catch (error) {
      console.error(`[IndexManager] Error removing content ${contentId} from index:`, error)
      throw error
    }
  }

      /**
       * Get indexing status for a collection
       */
      async getIndexStatus(collectionId: string): Promise<IndexStatus | null> {
    try {
      const stmt = this.db.prepare(
        'SELECT * FROM ai_search_index_meta WHERE collection_id = ?'
      )
      const result = await stmt.bind(collectionId).first<{
        id: number
        collection_id: string
        collection_name: string
        total_items: number
        indexed_items: number
        last_sync_at?: number
        status: string
        error_message?: string
      }>()

      if (!result) {
        return null
      }

      return {
        collection_id: String(result.collection_id),
        collection_name: result.collection_name,
        total_items: result.total_items,
        indexed_items: result.indexed_items,
        last_sync_at: result.last_sync_at,
        status: result.status as IndexStatus['status'],
        error_message: result.error_message,
      }
    } catch (error) {
      console.error(`Error getting index status for collection ${collectionId}:`, error)
      return null
    }
  }

      /**
       * Get indexing status for all collections
       */
      async getAllIndexStatus(): Promise<Record<string, IndexStatus>> {
    try {
      const stmt = this.db.prepare('SELECT * FROM ai_search_index_meta')
      const { results } = await stmt.all<{
        id: number
        collection_id: number
        collection_name: string
        total_items: number
        indexed_items: number
        last_sync_at?: number
        status: string
        error_message?: string
      }>()

          const statusMap: Record<string, IndexStatus> = {}

          for (const row of results || []) {
            const collectionId = String(row.collection_id)
            statusMap[collectionId] = {
              collection_id: collectionId,
          collection_name: row.collection_name,
          total_items: row.total_items,
          indexed_items: row.indexed_items,
          last_sync_at: row.last_sync_at,
          status: row.status as IndexStatus['status'],
          error_message: row.error_message,
        }
      }

      return statusMap
    } catch (error) {
      console.error('Error getting all index status:', error)
      return {}
    }
  }

      /**
       * Update index status in database
       */
      private async updateIndexStatus(collectionId: string, status: IndexStatus): Promise<void> {
        try {
          // Check if record exists
          const checkStmt = this.db.prepare(
            'SELECT id FROM ai_search_index_meta WHERE collection_id = ?'
          )
          const existing = await checkStmt.bind(collectionId).first<{ id: number }>()

          if (existing) {
            // Update existing
            const stmt = this.db.prepare(`
              UPDATE ai_search_index_meta 
              SET collection_name = ?,
                  total_items = ?,
                  indexed_items = ?,
                  last_sync_at = ?,
                  status = ?,
                  error_message = ?
              WHERE collection_id = ?
            `)
            await stmt
              .bind(
                status.collection_name,
                status.total_items,
                status.indexed_items,
                status.last_sync_at || null,
                status.status,
                status.error_message || null,
                String(collectionId)
              )
              .run()
          } else {
            // Insert new
            const stmt = this.db.prepare(`
              INSERT INTO ai_search_index_meta (
                collection_id, collection_name, total_items, indexed_items,
                last_sync_at, status, error_message
              ) VALUES (?, ?, ?, ?, ?, ?, ?)
            `)
            await stmt
              .bind(
                String(status.collection_id),
                status.collection_name,
                status.total_items,
                status.indexed_items,
                status.last_sync_at || null,
                status.status,
                status.error_message || null
              )
              .run()
          }
        } catch (error) {
          console.error(`Error updating index status for collection ${collectionId}:`, error)
          throw error
        }
      }

      /**
       * Sync all selected collections
       */
      async syncAll(selectedCollections: string[]): Promise<void> {
    for (const collectionId of selectedCollections) {
      try {
        await this.indexCollection(collectionId)
      } catch (error) {
        console.error(`Error syncing collection ${collectionId}:`, error)
      }
    }
  }
}
