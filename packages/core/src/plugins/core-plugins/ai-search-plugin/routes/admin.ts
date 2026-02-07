import { Hono } from 'hono'
import type { Bindings } from '../../../../app'
import { requireAuth } from '../../../../middleware'
import { AISearchService } from '../services/ai-search'
import { IndexManager } from '../services/indexer'
import { FTS5Service } from '../services/fts5.service'
import { renderSettingsPage } from '../components/settings-page'
import type { AISearchSettings, SearchQuery } from '../types'

type Variables = {
  user: {
    id: number
    email: string
    role: string
  }
}

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminRoutes.use('*', requireAuth())

/**
 * GET /admin/plugins/ai-search
 * Render settings page
 */
adminRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const ai = (c.env as any).AI // Workers AI for embeddings
    const vectorize = (c.env as any).VECTORIZE_INDEX // Vectorize for vector search

    const service = new AISearchService(db, ai, vectorize)
    const indexer = new IndexManager(db, ai, vectorize)

    // Get settings
    const settings = await service.getSettings()
    console.log('[AI Search Settings Route] Settings loaded:', !!settings)

    // Get all collections with status
    const collections = await service.getAllCollections()
    console.log('[AI Search Settings Route] Collections returned:', collections.length)
    
    // If no collections, try direct query
    if (collections.length === 0) {
      const directQuery = await db.prepare('SELECT id, name, display_name FROM collections WHERE is_active = 1').all()
      console.log('[AI Search Settings Route] Direct DB query found:', directQuery.results?.length || 0, 'collections')
      if (directQuery.results && directQuery.results.length > 0) {
        console.log('[AI Search Settings Route] Sample from DB:', directQuery.results[0])
      }
    } else if (collections.length > 0 && collections[0]) {
      console.log('[AI Search Settings Route] First collection:', {
        id: collections[0].id,
        name: collections[0].name,
        display_name: collections[0].display_name
      })
    }

    // Get new collections notifications
    const newCollections = await service.detectNewCollections()
    console.log('AI Search: New collections:', newCollections.length)

    // Get index status for all collections
    const indexStatus = await indexer.getAllIndexStatus()
    console.log('AI Search: Index status:', Object.keys(indexStatus).length)

    // Get analytics
    const analytics = await service.getSearchAnalytics()

    return c.html(
      renderSettingsPage({
        settings,
        collections: collections || [],
        newCollections: newCollections || [],
        indexStatus: indexStatus || {},
        analytics,
        user: {
          name: user.email,
          email: user.email,
          role: user.role,
        },
      })
    )
  } catch (error) {
    console.error('Error rendering AI Search settings:', error)
    return c.html(`<p>Error loading settings: ${error instanceof Error ? error.message : String(error)}</p>`, 500)
  }
})

/**
 * POST /admin/plugins/ai-search
 * Update settings
 */
adminRoutes.post('/', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)
    const indexer = new IndexManager(db, ai, vectorize)

    const body = await c.req.json()
    console.log('[AI Search POST] Received body:', JSON.stringify(body, null, 2))

    // Get current settings
    const currentSettings = await service.getSettings()
    console.log('[AI Search POST] Current settings selected_collections:', currentSettings?.selected_collections)

    // Update settings
    const updatedSettings: Partial<AISearchSettings> = {
      enabled: body.enabled !== undefined ? Boolean(body.enabled) : currentSettings?.enabled,
      ai_mode_enabled: body.ai_mode_enabled !== undefined ? Boolean(body.ai_mode_enabled) : currentSettings?.ai_mode_enabled,
      selected_collections: Array.isArray(body.selected_collections) ? body.selected_collections.map(String) : (currentSettings?.selected_collections || []),
      dismissed_collections: Array.isArray(body.dismissed_collections) ? body.dismissed_collections.map(String) : (currentSettings?.dismissed_collections || []),
      autocomplete_enabled: body.autocomplete_enabled !== undefined ? Boolean(body.autocomplete_enabled) : currentSettings?.autocomplete_enabled,
      cache_duration: body.cache_duration ? Number(body.cache_duration) : currentSettings?.cache_duration,
      results_limit: body.results_limit ? Number(body.results_limit) : currentSettings?.results_limit,
      index_media: body.index_media !== undefined ? Boolean(body.index_media) : currentSettings?.index_media,
    }

    console.log('[AI Search POST] Updated settings selected_collections:', updatedSettings.selected_collections)

    // If collections changed, trigger indexing
    const collectionsChanged =
      JSON.stringify(updatedSettings.selected_collections) !==
      JSON.stringify(currentSettings?.selected_collections || [])

    const saved = await service.updateSettings(updatedSettings)
    console.log('[AI Search POST] Settings saved, selected_collections:', saved.selected_collections)

    // Start indexing if collections were added
    if (collectionsChanged && updatedSettings.selected_collections) {
      console.log('[AI Search POST] Collections changed, starting background indexing')
      // Start indexing in background (non-blocking) - must use waitUntil to ensure it completes
      c.executionCtx.waitUntil(
        indexer
          .syncAll(updatedSettings.selected_collections)
          .then(() => console.log('[AI Search POST] Background indexing completed'))
          .catch((error) => console.error('[AI Search POST] Background indexing error:', error))
      )
    }

    return c.json({ success: true, settings: saved })
  } catch (error) {
    console.error('Error updating AI Search settings:', error)
    return c.json({ error: 'Failed to update settings' }, 500)
  }
})

/**
 * GET /admin/api/ai-search/settings
 * Get settings API endpoint
 */
adminRoutes.get('/api/settings', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)

    const settings = await service.getSettings()
    return c.json({ success: true, data: settings })
  } catch (error) {
    console.error('Error fetching settings:', error)
    return c.json({ error: 'Failed to fetch settings' }, 500)
  }
})

/**
 * GET /admin/api/ai-search/new-collections
 * Get new collections that aren't indexed or dismissed
 */
adminRoutes.get('/api/new-collections', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)

    const notifications = await service.detectNewCollections()
    return c.json({ success: true, data: notifications })
  } catch (error) {
    console.error('Error detecting new collections:', error)
    return c.json({ error: 'Failed to detect new collections' }, 500)
  }
})

/**
 * GET /admin/api/ai-search/status
 * Get indexing status
 */
adminRoutes.get('/api/status', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const indexer = new IndexManager(db, ai, vectorize)

    const status = await indexer.getAllIndexStatus()
    return c.json({ success: true, data: status })
  } catch (error) {
    console.error('Error fetching index status:', error)
    return c.json({ error: 'Failed to fetch status' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/reindex
 * Trigger re-indexing for a collection
 */
adminRoutes.post('/api/reindex', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const indexer = new IndexManager(db, ai, vectorize)

      const body = await c.req.json()
      const collectionIdRaw: unknown = body.collection_id
      const collectionId = collectionIdRaw ? String(collectionIdRaw) : ''

      if (!collectionId || collectionId === 'undefined' || collectionId === 'null') {
        return c.json({ error: 'collection_id is required' }, 400)
      }

      // Start indexing in background - must use waitUntil to ensure it completes
      c.executionCtx.waitUntil(
        indexer
          .indexCollection(collectionId)
          .then(() => console.log(`[AI Search Reindex] Completed for collection ${collectionId}`))
          .catch((error) => console.error(`[AI Search Reindex] Error for collection ${collectionId}:`, error))
      )

    return c.json({ success: true, message: 'Re-indexing started' })
  } catch (error) {
    console.error('Error starting re-index:', error)
    return c.json({ error: 'Failed to start re-indexing' }, 500)
  }
})

/**
 * GET /admin/api/ai-search/fts5/status
 * Get FTS5 index status and statistics
 */
adminRoutes.get('/api/fts5/status', async (c) => {
  try {
    const db = c.env.DB
    const fts5Service = new FTS5Service(db)

    const isAvailable = await fts5Service.isAvailable()
    if (!isAvailable) {
      return c.json({
        success: true,
        data: {
          available: false,
          message: 'FTS5 tables not yet created. Run migrations to enable FTS5 search.'
        }
      })
    }

    const stats = await fts5Service.getStats()
    return c.json({
      success: true,
      data: {
        available: true,
        total_indexed: stats.total_indexed,
        by_collection: stats.by_collection
      }
    })
  } catch (error) {
    console.error('Error fetching FTS5 status:', error)
    return c.json({ error: 'Failed to fetch FTS5 status' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/fts5/index-collection
 * Index a specific collection for FTS5 search
 */
adminRoutes.post('/api/fts5/index-collection', async (c) => {
  try {
    const db = c.env.DB
    const fts5Service = new FTS5Service(db)

    const isAvailable = await fts5Service.isAvailable()
    if (!isAvailable) {
      return c.json({
        error: 'FTS5 tables not available. Run migrations first.'
      }, 400)
    }

    const body = await c.req.json()
    const collectionIdRaw: unknown = body.collection_id
    const collectionId = collectionIdRaw ? String(collectionIdRaw) : ''

    if (!collectionId || collectionId === 'undefined' || collectionId === 'null') {
      return c.json({ error: 'collection_id is required' }, 400)
    }

    // Start FTS5 indexing in background
    c.executionCtx.waitUntil(
      fts5Service
        .indexCollection(collectionId)
        .then((result) => {
          console.log(`[FTS5 Admin] Indexing completed for collection ${collectionId}:`, result)
        })
        .catch((error) => {
          console.error(`[FTS5 Admin] Indexing error for collection ${collectionId}:`, error)
        })
    )

    return c.json({
      success: true,
      message: 'FTS5 indexing started for collection'
    })
  } catch (error) {
    console.error('Error starting FTS5 index:', error)
    return c.json({ error: 'Failed to start FTS5 indexing' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/fts5/reindex-all
 * Reindex all selected collections for FTS5 search
 */
adminRoutes.post('/api/fts5/reindex-all', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)
    const fts5Service = new FTS5Service(db)

    const isAvailable = await fts5Service.isAvailable()
    if (!isAvailable) {
      return c.json({
        error: 'FTS5 tables not available. Run migrations first.'
      }, 400)
    }

    // Get current settings to find selected collections
    const settings = await service.getSettings()
    const collections = settings?.selected_collections || []

    if (collections.length === 0) {
      return c.json({
        success: true,
        message: 'No collections selected for indexing'
      })
    }

    // Start FTS5 indexing for all collections in background
    c.executionCtx.waitUntil(
      (async () => {
        console.log(`[FTS5 Admin] Starting reindex-all for ${collections.length} collections`)
        const results: Record<string, any> = {}

        for (const collectionId of collections) {
          try {
            const result = await fts5Service.indexCollection(collectionId)
            results[collectionId] = result
            console.log(`[FTS5 Admin] Indexed collection ${collectionId}:`, result)
          } catch (error) {
            console.error(`[FTS5 Admin] Error indexing collection ${collectionId}:`, error)
            results[collectionId] = { error: error instanceof Error ? error.message : String(error) }
          }
        }

        console.log('[FTS5 Admin] Reindex-all completed:', results)
      })()
    )

    return c.json({
      success: true,
      message: `FTS5 indexing started for ${collections.length} collections`,
      collections
    })
  } catch (error) {
    console.error('Error starting FTS5 reindex-all:', error)
    return c.json({ error: 'Failed to start FTS5 reindex' }, 500)
  }
})

export default adminRoutes
