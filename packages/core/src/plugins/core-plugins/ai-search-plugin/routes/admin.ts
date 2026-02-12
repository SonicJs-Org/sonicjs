import { Hono } from 'hono'
import type { Bindings } from '../../../../app'
import { requireAuth } from '../../../../middleware'
import { AISearchService } from '../services/ai-search'
import { IndexManager } from '../services/indexer'
import { FTS5Service } from '../services/fts5.service'
import { BenchmarkService } from '../services/benchmark.service'
import { BENCHMARK_DATASETS } from '../data/benchmark-datasets'
import { RankingPipelineService } from '../services/ranking-pipeline.service'
import { SynonymService } from '../services/synonym.service'
import { EmbeddingService } from '../services/embedding.service'
import { ChunkingService } from '../services/chunking.service'
import type { AISearchSettings, SearchQuery } from '../types'

type Variables = {
  user: {
    id: number
    email: string
    role: string
  }
}

const clampWeight = (val: any, fallback: number): number => {
  const n = Number(val)
  return (isNaN(n) || !isFinite(n)) ? fallback : Math.round(Math.min(10, Math.max(0, n)) * 10) / 10
}

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminRoutes.use('*', requireAuth())

/**
 * GET /admin/plugins/ai-search
 * Redirect to the dedicated Search admin page
 */
adminRoutes.get('/', async (c) => {
  return c.redirect('/admin/search')
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
      reranking_enabled: body.reranking_enabled !== undefined ? Boolean(body.reranking_enabled) : currentSettings?.reranking_enabled,
      query_rewriting_enabled: body.query_rewriting_enabled !== undefined ? Boolean(body.query_rewriting_enabled) : currentSettings?.query_rewriting_enabled,
      fts5_title_boost: body.fts5_title_boost !== undefined ? clampWeight(body.fts5_title_boost, currentSettings?.fts5_title_boost ?? 5.0) : currentSettings?.fts5_title_boost,
      fts5_slug_boost: body.fts5_slug_boost !== undefined ? clampWeight(body.fts5_slug_boost, currentSettings?.fts5_slug_boost ?? 2.0) : currentSettings?.fts5_slug_boost,
      fts5_body_boost: body.fts5_body_boost !== undefined ? clampWeight(body.fts5_body_boost, currentSettings?.fts5_body_boost ?? 1.0) : currentSettings?.fts5_body_boost,
      query_synonyms_enabled: body.query_synonyms_enabled !== undefined ? Boolean(body.query_synonyms_enabled) : currentSettings?.query_synonyms_enabled,
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

    // Clean up FTS5 entries for collections NOT in the selected list
    try {
      const placeholders = collections.map(() => '?').join(',')
      await db.batch([
        db.prepare(`DELETE FROM content_fts WHERE collection_id NOT IN (${placeholders})`).bind(...collections),
        db.prepare(`DELETE FROM content_fts_sync WHERE collection_id NOT IN (${placeholders})`).bind(...collections),
      ])
      console.log(`[FTS5 Admin] Cleaned up FTS5 entries for unselected collections`)
    } catch (e) {
      console.warn('[FTS5 Admin] Cleanup of unselected collections failed (non-fatal):', e)
    }

    // Start FTS5 indexing for all selected collections in background
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

/**
 * POST /admin/api/ai-search/vectorize/reindex-all
 * Reset and reindex all selected collections into Vectorize
 */
adminRoutes.post('/api/vectorize/reindex-all', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX

    if (!ai || !vectorize) {
      return c.json({ error: 'Vectorize reindexing requires AI and VECTORIZE_INDEX bindings.' }, 400)
    }

    const service = new AISearchService(db, ai, vectorize)
    const settings = await service.getSettings()
    const collections = settings?.selected_collections || []

    if (collections.length === 0) {
      return c.json({ error: 'No collections selected. Configure collections in the Configuration tab first.' }, 400)
    }

    // Reset index meta and pre-populate with correct total_items for progress tracking
    for (const collectionId of collections) {
      try {
        await db.prepare(
          "DELETE FROM ai_search_index_meta WHERE collection_id = ?"
        ).bind(collectionId).run()

        // Count items and get collection name for progress display
        const countResult = await db.prepare(
          "SELECT COUNT(*) as cnt FROM content WHERE collection_id = ? AND status != 'deleted'"
        ).bind(collectionId).first<{ cnt: number }>()
        const colInfo = await db.prepare(
          "SELECT display_name FROM collections WHERE id = ?"
        ).bind(collectionId).first<{ display_name: string }>()

        await db.prepare(`
          INSERT INTO ai_search_index_meta (collection_id, collection_name, total_items, indexed_items, status, last_sync_at)
          VALUES (?, ?, ?, 0, 'indexing', ?)
        `).bind(
          collectionId,
          colInfo?.display_name || collectionId,
          countResult?.cnt || 0,
          Date.now()
        ).run()
      } catch (e) { /* table might not exist */ }
    }

    // Also clean up any orphaned benchmark vectors from the main index
    try {
      const benchmarkIds: string[] = []
      // Clean up known benchmark dataset prefixes
      for (const dsId of BENCHMARK_DATASETS.map(d => d.id)) {
        for (let i = 0; i < 6000; i++) {
          for (let chunk = 0; chunk < 3; chunk++) {
            benchmarkIds.push(`beir-${dsId}-${i}-chunk-${chunk}`)
          }
        }
      }
      for (let i = 0; i < benchmarkIds.length; i += 1000) {
        await vectorize.deleteByIds(benchmarkIds.slice(i, i + 1000))
      }
      console.log('[Vectorize Reindex] Cleaned orphaned benchmark vectors from main index')
    } catch (e) {
      console.warn('[Vectorize Reindex] Orphan cleanup failed (non-fatal):', e)
    }

    // Trigger full reindex via IndexManager in background
    const indexer = new IndexManager(db, ai, vectorize)
    c.executionCtx.waitUntil(
      indexer
        .syncAll(collections)
        .then(() => console.log('[Vectorize Reindex] All collections reindexed'))
        .catch((error) => console.error('[Vectorize Reindex] Error:', error))
    )

    return c.json({
      success: true,
      message: `Vectorize reindexing started for ${collections.length} collection(s)`,
      collections,
    })
  } catch (error) {
    console.error('Error starting Vectorize reindex-all:', error)
    return c.json({ error: 'Failed to start Vectorize reindexing' }, 500)
  }
})

// ==========================================
// Relevance Preview Routes
// ==========================================

/**
 * POST /admin/api/ai-search/relevance/preview
 * Search with custom weight overrides without saving settings.
 * Used by the Live Preview on the Relevance tab.
 *
 * Body: { query: string, title_weight?: number, slug_weight?: number, body_weight?: number, limit?: number }
 */
adminRoutes.post('/api/relevance/preview', async (c) => {
  try {
    const db = c.env.DB
    const body = await c.req.json()

    const query = body.query?.trim()
    if (!query) return c.json({ error: 'query is required' }, 400)

    const limit = Math.min(body.limit || 10, 20)

    const service = new AISearchService(db)
    const settings = await service.getSettings()

    const titleWeight = clampWeight(body.title_weight, settings?.fts5_title_boost ?? 5.0)
    const slugWeight = clampWeight(body.slug_weight, settings?.fts5_slug_boost ?? 2.0)
    const bodyWeight = clampWeight(body.body_weight, settings?.fts5_body_boost ?? 1.0)

    const previewSettings = {
      ...settings!,
      fts5_title_boost: titleWeight,
      fts5_slug_boost: slugWeight,
      fts5_body_boost: bodyWeight,
    }

    const fts5Service = new FTS5Service(db)
    let result = await fts5Service.search(
      { query, mode: 'fts5' as any, limit, offset: 0 },
      previewSettings,
      { titleBoost: titleWeight, slugBoost: slugWeight, bodyBoost: bodyWeight }
    )

    // Apply ranking pipeline if active stages exist
    const pipelineService = new RankingPipelineService(db)
    let pipelineApplied = false
    try {
      const config = await pipelineService.getConfig()
      const activeStages = config.filter(s => s.enabled && s.weight > 0)
      if (activeStages.length > 0) {
        result = await pipelineService.apply(result, query)
        pipelineApplied = true
      }
    } catch (err) {
      console.warn('[Relevance Preview] Pipeline application failed:', err)
    }

    return c.json({
      success: true,
      data: {
        results: result.results,
        total: result.total,
        query_time_ms: result.query_time_ms,
        weights: { title: titleWeight, slug: slugWeight, body: bodyWeight },
        pipeline_applied: pipelineApplied,
      }
    })
  } catch (error) {
    console.error('Error in relevance preview:', error)
    return c.json({ error: 'Preview search failed: ' + (error instanceof Error ? error.message : String(error)) }, 500)
  }
})

// ==========================================
// Ranking Pipeline Routes
// ==========================================

/** GET /api/relevance/pipeline — get pipeline config */
adminRoutes.get('/api/relevance/pipeline', async (c) => {
  try {
    const pipelineService = new RankingPipelineService(c.env.DB)
    const config = await pipelineService.getConfig()
    return c.json({ success: true, data: config })
  } catch (error) {
    console.error('Error fetching pipeline config:', error)
    return c.json({ error: 'Failed to fetch pipeline config' }, 500)
  }
})

/** POST /api/relevance/pipeline — save pipeline config */
adminRoutes.post('/api/relevance/pipeline', async (c) => {
  try {
    const body = await c.req.json()
    if (!Array.isArray(body.stages)) {
      return c.json({ error: 'stages must be an array' }, 400)
    }
    const pipelineService = new RankingPipelineService(c.env.DB)
    await pipelineService.saveConfig(body.stages)
    const saved = await pipelineService.getConfig()
    return c.json({ success: true, data: saved })
  } catch (error) {
    console.error('Error saving pipeline config:', error)
    return c.json({ error: 'Failed to save pipeline config' }, 500)
  }
})

/** GET /api/relevance/content-scores — get a content score */
adminRoutes.get('/api/relevance/content-scores', async (c) => {
  try {
    const contentId = c.req.query('content_id')
    const scoreType = c.req.query('score_type') || 'popularity'
    if (!contentId) {
      return c.json({ error: 'content_id query parameter is required' }, 400)
    }
    const pipelineService = new RankingPipelineService(c.env.DB)
    const scores = await pipelineService.getContentScores([contentId], scoreType)
    return c.json({
      success: true,
      data: { content_id: contentId, score_type: scoreType, score: scores.get(contentId) ?? null }
    })
  } catch (error) {
    console.error('Error fetching content scores:', error)
    return c.json({ error: 'Failed to fetch content scores' }, 500)
  }
})

/** POST /api/relevance/content-scores — set a content score */
adminRoutes.post('/api/relevance/content-scores', async (c) => {
  try {
    const body = await c.req.json()
    const { content_id: contentId, score_type: scoreType, score } = body
    if (!contentId || !scoreType || score == null) {
      return c.json({ error: 'content_id, score_type, and score are required' }, 400)
    }
    if (!['popularity', 'custom'].includes(scoreType)) {
      return c.json({ error: 'score_type must be "popularity" or "custom"' }, 400)
    }
    const pipelineService = new RankingPipelineService(c.env.DB)
    await pipelineService.setContentScore(String(contentId), scoreType, Number(score))
    return c.json({ success: true })
  } catch (error) {
    console.error('Error setting content score:', error)
    return c.json({ error: 'Failed to set content score' }, 500)
  }
})

/** DELETE /api/relevance/content-scores — delete a content score */
adminRoutes.delete('/api/relevance/content-scores', async (c) => {
  try {
    const body = await c.req.json()
    const { content_id: contentId, score_type: scoreType } = body
    if (!contentId || !scoreType) {
      return c.json({ error: 'content_id and score_type are required' }, 400)
    }
    const pipelineService = new RankingPipelineService(c.env.DB)
    await pipelineService.deleteContentScore(String(contentId), scoreType)
    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting content score:', error)
    return c.json({ error: 'Failed to delete content score' }, 500)
  }
})

// ==========================================
// Synonym Routes
// ==========================================

/** GET /api/relevance/synonyms — list all synonym groups */
adminRoutes.get('/api/relevance/synonyms', async (c) => {
  try {
    const synonymService = new SynonymService(c.env.DB)
    const groups = await synonymService.getAll()
    return c.json({ success: true, data: groups })
  } catch (error) {
    console.error('Error fetching synonym groups:', error)
    return c.json({ error: 'Failed to fetch synonym groups' }, 500)
  }
})

/** POST /api/relevance/synonyms — create a synonym group */
adminRoutes.post('/api/relevance/synonyms', async (c) => {
  try {
    const body = await c.req.json()
    if (!Array.isArray(body.terms) || body.terms.length < 2) {
      return c.json({ error: 'terms must be an array with at least 2 items' }, 400)
    }
    const synonymService = new SynonymService(c.env.DB)
    const group = await synonymService.create(body.terms, body.enabled !== false)
    return c.json({ success: true, data: group })
  } catch (error) {
    console.error('Error creating synonym group:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to create synonym group' }, 500)
  }
})

/** PUT /api/relevance/synonyms/:id — update a synonym group */
adminRoutes.put('/api/relevance/synonyms/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const synonymService = new SynonymService(c.env.DB)
    const group = await synonymService.update(id, {
      terms: body.terms,
      enabled: body.enabled,
    })
    if (!group) {
      return c.json({ error: 'Synonym group not found' }, 404)
    }
    return c.json({ success: true, data: group })
  } catch (error) {
    console.error('Error updating synonym group:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to update synonym group' }, 500)
  }
})

/** DELETE /api/relevance/synonyms/:id — delete a synonym group */
adminRoutes.delete('/api/relevance/synonyms/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const synonymService = new SynonymService(c.env.DB)
    const deleted = await synonymService.delete(id)
    if (!deleted) {
      return c.json({ error: 'Synonym group not found' }, 404)
    }
    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting synonym group:', error)
    return c.json({ error: 'Failed to delete synonym group' }, 500)
  }
})

// ==========================================
// Analytics Routes
// ==========================================

/**
 * GET /api/analytics/extended
 * Extended analytics data for the Analytics tab
 */
adminRoutes.get('/api/analytics/extended', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)
    const data = await service.getAnalyticsExtended()
    return c.json({ success: true, data })
  } catch (error) {
    console.error('Error fetching extended analytics:', error)
    return c.json({ success: false, error: error instanceof Error ? error.message : String(error) }, 500)
  }
})

// ==========================================
// Benchmark Routes (Multi-Dataset BEIR, KV-Backed)
// ==========================================

/**
 * GET /admin/api/ai-search/benchmark/datasets
 * List all available benchmark datasets
 */
adminRoutes.get('/api/benchmark/datasets', async (c) => {
  return c.json({ success: true, datasets: BENCHMARK_DATASETS })
})

/**
 * GET /admin/api/ai-search/benchmark/status
 * Check if benchmark data is seeded and get corpus metadata
 * Query: ?dataset=scifact (default: scifact)
 */
adminRoutes.get('/api/benchmark/status', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const dataset = c.req.query('dataset') || 'scifact'
    const benchmarkService = new BenchmarkService(db, kv, undefined, dataset)

    const { seeded, count } = await benchmarkService.isSeeded()
    const meta = benchmarkService.getMeta()
    const dataAvailable = await benchmarkService.isDataAvailable()

    // Only compute subset/query sizes if data is available in KV
    let subsetSize = 0
    let evaluableQueries = 0
    if (dataAvailable) {
      try {
        const [ss, eqIds] = await Promise.all([
          benchmarkService.getSubsetSize(),
          benchmarkService.getEvaluableQueryIds(0),
        ])
        subsetSize = ss
        evaluableQueries = eqIds.length
      } catch (e) {
        // Data not in KV yet — that's fine
      }
    }

    return c.json({
      success: true,
      data: {
        seeded,
        seeded_count: count,
        corpus_size: meta.corpus_size,
        subset_size: subsetSize,
        query_count: meta.query_count,
        evaluable_queries: evaluableQueries,
        dataset: meta.name,
        dataset_id: dataset,
        license: meta.license,
        data_available: dataAvailable,
      },
    })
  } catch (error) {
    console.error('Error fetching benchmark status:', error)
    return c.json({ error: `Failed to fetch benchmark status: ${error instanceof Error ? error.message : String(error)}` }, 500)
  }
})

/**
 * POST /admin/api/ai-search/benchmark/seed
 * Seed benchmark documents into the content table
 * Body: { corpus_size?: string, dataset?: string }
 */
adminRoutes.post('/api/benchmark/seed', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const kv = c.env.CACHE_KV

    const body = await c.req.json<{ corpus_size?: string; dataset?: string }>().catch(() => ({} as { corpus_size?: string; dataset?: string }))
    const dataset = body.dataset || 'scifact'
    const useSubset = body.corpus_size !== 'full'
    const benchmarkService = new BenchmarkService(db, kv, undefined, dataset)
    const collectionId = benchmarkService.getCollectionId()

    // JWT payload uses 'userId' not 'id'
    const userId = (user as any).userId || (user as any).id
    const result = await benchmarkService.seed(String(userId), useSubset)

    // For small corpora (subset), auto-trigger FTS5 indexing in background.
    if (useSubset) {
      const fts5Service = new FTS5Service(db)
      c.executionCtx.waitUntil(
        fts5Service.indexCollection(collectionId)
          .then((r) => console.log(`[Benchmark:${dataset}] FTS5 indexed ${r.indexed_items}/${r.total_items} docs`))
          .catch((e) => console.error(`[Benchmark:${dataset}] FTS5 indexing error:`, e))
      )
    }

    const meta = benchmarkService.getMeta()
    const indexNote = useSubset
      ? 'FTS5 indexing started in background.'
      : 'Use the Index buttons to index before evaluating.'

    if (result.skipped) {
      return c.json({
        success: true,
        message: `Benchmark data already exists (${result.seeded} documents). ${indexNote}`,
        seeded: result.seeded,
        skipped: true,
      })
    }

    return c.json({
      success: true,
      message: `Seeded ${result.seeded} ${meta.name} documents. ${indexNote}`,
      seeded: result.seeded,
      skipped: false,
    })
  } catch (error) {
    console.error('Error seeding benchmark data:', error)
    return c.json(
      { error: `Failed to seed benchmark data: ${error instanceof Error ? error.message : String(error)}` },
      500
    )
  }
})

/**
 * POST /admin/api/ai-search/benchmark/purge
 * Remove all benchmark documents and index entries
 * Body: { dataset?: string }
 */
adminRoutes.post('/api/benchmark/purge', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const vectorize = (c.env as any).VECTORIZE_BENCHMARK_INDEX || (c.env as any).VECTORIZE_INDEX

    const body = await c.req.json<{ dataset?: string }>().catch((): { dataset?: string } => ({}))
    const dataset = body.dataset || 'scifact'
    const benchmarkService = new BenchmarkService(db, kv, vectorize, dataset)

    const deleted = await benchmarkService.purge()

    return c.json({
      success: true,
      message: `Removed ${deleted} benchmark documents`,
      deleted,
    })
  } catch (error) {
    console.error('Error purging benchmark data:', error)
    return c.json({ error: 'Failed to purge benchmark data' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/benchmark/index-fts5-batch
 * Index a batch of benchmark docs into FTS5. Call repeatedly until remaining=0.
 * Body: { batch_size?: number, dataset?: string }
 */
adminRoutes.post('/api/benchmark/index-fts5-batch', async (c) => {
  try {
    const db = c.env.DB
    const fts5Service = new FTS5Service(db)

    if (!(await fts5Service.isAvailable())) {
      return c.json({ error: 'FTS5 tables not available.' }, 400)
    }

    const body = await c.req.json<{ batch_size?: number; dataset?: string }>().catch((): { batch_size?: number; dataset?: string } => ({}))
    const dataset = body.dataset || 'scifact'
    const batchSize = body.batch_size || 200
    const collectionId = `benchmark-${dataset}-collection`

    const result = await fts5Service.indexCollectionBatch(
      collectionId,
      batchSize
    )

    return c.json({
      success: true,
      indexed: result.indexed,
      remaining: result.remaining,
      total: result.total,
    })
  } catch (error) {
    console.error('Error in FTS5 batch indexing:', error)
    return c.json({ error: `FTS5 batch indexing failed: ${error instanceof Error ? error.message : String(error)}` }, 500)
  }
})

/**
 * POST /admin/api/ai-search/benchmark/index-vectorize-batch
 * Index a batch of benchmark docs into Vectorize. Call repeatedly until remaining=0.
 * Body: { batch_size?: number, offset?: number, dataset?: string }
 */
adminRoutes.post('/api/benchmark/index-vectorize-batch', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_BENCHMARK_INDEX || (c.env as any).VECTORIZE_INDEX

    if (!ai || !vectorize) {
      return c.json({ error: 'Vectorize indexing requires AI and VECTORIZE_BENCHMARK_INDEX bindings.' }, 400)
    }

    const body = await c.req.json<{ batch_size?: number; offset?: number; dataset?: string }>().catch((): { batch_size?: number; offset?: number; dataset?: string } => ({}))
    const dataset = body.dataset || 'scifact'
    const batchSize = body.batch_size || 25
    const offset = body.offset || 0

    const benchmarkCollectionId = `benchmark-${dataset}-collection`
    const datasetInfo = BENCHMARK_DATASETS.find(d => d.id === dataset)
    const displayName = datasetInfo ? `${datasetInfo.name} Benchmark` : `BEIR ${dataset} Benchmark`
    const embeddingService = new EmbeddingService(ai)
    const chunkingService = new ChunkingService()

    // Get total count
    const totalResult = await db
      .prepare("SELECT COUNT(*) as cnt FROM content WHERE collection_id = ? AND status != 'deleted'")
      .bind(benchmarkCollectionId)
      .first<{ cnt: number }>()
    const total = totalResult?.cnt || 0

    if (offset >= total) {
      try {
        await db.prepare(`
          INSERT OR REPLACE INTO ai_search_index_meta
          (collection_id, collection_name, total_items, indexed_items, last_sync_at, status)
          VALUES (?, ?, ?, ?, ?, 'completed')
        `).bind(benchmarkCollectionId, displayName, total, total, Date.now()).run()
      } catch (e) { /* ignore */ }

      return c.json({ success: true, indexed: 0, offset: offset, total: total, remaining: 0 })
    }

    // Fetch this batch of content items
    const { results: contentItems } = await db
      .prepare(`
        SELECT c.id, c.title, c.data, c.collection_id, c.status,
               c.created_at, c.author_id
        FROM content c
        WHERE c.collection_id = ? AND c.status != 'deleted'
        ORDER BY c.id
        LIMIT ? OFFSET ?
      `)
      .bind(benchmarkCollectionId, batchSize, offset)
      .all<{
        id: string; title: string; data: string; collection_id: string;
        status: string; created_at: number; author_id?: string
      }>()

    const items = (contentItems || []).map(item => ({
      id: item.id,
      collection_id: item.collection_id,
      title: item.title || 'Untitled',
      data: typeof item.data === 'string' ? JSON.parse(item.data) : item.data,
      metadata: {
        status: item.status,
        created_at: item.created_at,
        author_id: item.author_id,
        collection_name: `benchmark_${dataset}`,
        collection_display_name: displayName,
      }
    }))

    // Chunk content
    const chunks = chunkingService.chunkContentBatch(items)

    // Generate embeddings (processes 10 at a time internally)
    const embeddings = await embeddingService.generateBatch(
      chunks.map(ch => `${ch.title}\n\n${ch.text}`)
    )

    // Upsert to Vectorize in sub-batches of 100
    let indexedChunks = 0
    const upsertBatchSize = 100
    for (let i = 0; i < chunks.length; i += upsertBatchSize) {
      const chunkBatch = chunks.slice(i, i + upsertBatchSize)
      const embBatch = embeddings.slice(i, i + upsertBatchSize)
      try {
        await vectorize.upsert(
          chunkBatch.map((chunk, idx) => ({
            id: chunk.id,
            values: embBatch[idx],
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
      } catch (error) {
        console.error(`[Benchmark:${dataset} Vectorize] Upsert error at batch offset ${i}:`, error)
      }
    }

    const newOffset = offset + (contentItems?.length || 0)
    const remaining = Math.max(0, total - newOffset)

    try {
      await db.prepare(`
        INSERT OR REPLACE INTO ai_search_index_meta
        (collection_id, collection_name, total_items, indexed_items, last_sync_at, status)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        benchmarkCollectionId, displayName, total, newOffset, Date.now(),
        remaining > 0 ? 'indexing' : 'completed'
      ).run()
    } catch (e) { /* ignore */ }

    return c.json({
      success: true,
      indexed: indexedChunks,
      items_processed: contentItems?.length || 0,
      offset: newOffset,
      total: total,
      remaining: remaining,
    })
  } catch (error) {
    console.error('Error in Vectorize batch indexing:', error)
    return c.json({ error: `Vectorize batch indexing failed: ${error instanceof Error ? error.message : String(error)}` }, 500)
  }
})

/**
 * POST /admin/api/ai-search/benchmark/index-vectorize
 * Reset Vectorize index meta for benchmark — prepares for batch indexing
 * Body: { dataset?: string }
 */
adminRoutes.post('/api/benchmark/index-vectorize', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_BENCHMARK_INDEX || (c.env as any).VECTORIZE_INDEX

    if (!ai || !vectorize) {
      return c.json(
        { error: 'Vectorize indexing requires AI and VECTORIZE_BENCHMARK_INDEX bindings. Configure them in wrangler.toml.' },
        400
      )
    }

    const body = await c.req.json<{ dataset?: string }>().catch((): { dataset?: string } => ({}))
    const dataset = body.dataset || 'scifact'
    const benchmarkService = new BenchmarkService(db, kv, undefined, dataset)
    const { seeded } = await benchmarkService.isSeeded()
    if (!seeded) {
      return c.json({ error: 'Benchmark data not seeded. Seed first.' }, 400)
    }

    const collectionId = benchmarkService.getCollectionId()
    const meta = benchmarkService.getMeta()
    const displayName = `${meta.name} Benchmark`

    // Reset the index meta to allow fresh batch indexing
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO ai_search_index_meta
        (collection_id, collection_name, total_items, indexed_items, last_sync_at, status)
        VALUES (?, ?, 0, 0, ?, 'indexing')
      `).bind(collectionId, displayName, Date.now()).run()
    } catch (e) { /* ignore */ }

    return c.json({
      success: true,
      message: 'Vectorize index reset. Use batch indexing to process documents.',
    })
  } catch (error) {
    console.error('Error starting Vectorize indexing:', error)
    return c.json({ error: 'Failed to start Vectorize indexing' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/benchmark/evaluate
 * Run benchmark evaluation against a search mode
 * Body: { mode?: string, limit?: number, max_queries?: number, dataset?: string }
 */
adminRoutes.post('/api/benchmark/evaluate', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_BENCHMARK_INDEX || (c.env as any).VECTORIZE_INDEX

    const body = await c.req.json<{
      mode?: string
      limit?: number
      max_queries?: number
      dataset?: string
    }>()

    const mode = body.mode || 'fts5'
    const limit = body.limit || 10
    const maxQueries = body.max_queries || 0
    const dataset = body.dataset || 'scifact'

    const benchmarkService = new BenchmarkService(db, kv, undefined, dataset)
    const collectionId = benchmarkService.getCollectionId()

    // Check if benchmark data is seeded
    const { seeded } = await benchmarkService.isSeeded()
    if (!seeded) {
      return c.json(
        { error: 'Benchmark data not seeded. Call /api/benchmark/seed first.' },
        400
      )
    }

    if (mode === 'fts5' || mode === 'hybrid') {
      const fts5Service = new FTS5Service(db)
      if (await fts5Service.isAvailable()) {
        const ftsCount = await db
          .prepare("SELECT COUNT(*) as cnt FROM content_fts WHERE collection_id = ?")
          .bind(collectionId)
          .first<{ cnt: number }>()

        if (!ftsCount || ftsCount.cnt === 0) {
          return c.json(
            { error: 'Benchmark data not yet FTS5-indexed. Click "Seed Data" again or wait for background indexing to complete, then retry.' },
            400
          )
        }
      }
    }

    if ((mode === 'ai' || mode === 'hybrid') && !vectorize) {
      return c.json(
        { error: `${mode.toUpperCase()} mode requires a Vectorize index binding. Configure it in wrangler.toml.` },
        400
      )
    }

    if (mode === 'ai' || mode === 'hybrid') {
      try {
        const indexMeta = await db
          .prepare("SELECT status, indexed_items FROM ai_search_index_meta WHERE collection_id = ?")
          .bind(collectionId)
          .first<{ status: string; indexed_items: number }>()

        if (!indexMeta || indexMeta.indexed_items === 0) {
          return c.json(
            { error: 'Benchmark data not yet Vectorize-indexed. Click "Index (Vectorize)" first and wait for it to complete.' },
            400
          )
        }

        if (indexMeta.status === 'indexing') {
          return c.json(
            { error: 'Vectorize indexing is still in progress. Wait for it to complete, then retry.' },
            400
          )
        }
      } catch (e) {
        return c.json(
          { error: 'Benchmark data not yet Vectorize-indexed. Click "Index (Vectorize)" first.' },
          400
        )
      }
    }

    const aiSearchService = new AISearchService(db, ai, vectorize)

    const searchFn = async (
      query: string,
      searchMode: string,
      searchLimit: number
    ) => {
      const response = await aiSearchService.search({
        query,
        mode: searchMode as any,
        limit: searchLimit,
        filters: { collections: [collectionId] },
      })
      return { results: response.results.map((r) => ({ id: r.id })) }
    }

    const results = await benchmarkService.evaluate(
      searchFn,
      mode,
      limit,
      maxQueries
    )

    return c.json({ success: true, ...results })
  } catch (error) {
    console.error('Error running benchmark evaluation:', error)
    return c.json(
      { error: `Benchmark evaluation failed: ${error instanceof Error ? error.message : String(error)}` },
      500
    )
  }
})

/**
 * GET /admin/api/ai-search/benchmark/query-ids
 * Returns the list of evaluable query IDs (those with relevance judgments).
 * Query: ?max_queries=0&dataset=scifact
 */
adminRoutes.get('/api/benchmark/query-ids', async (c) => {
  try {
    const maxQueries = parseInt(c.req.query('max_queries') || '0', 10)
    const dataset = c.req.query('dataset') || 'scifact'
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const benchmarkService = new BenchmarkService(db, kv, undefined, dataset)
    const ids = await benchmarkService.getEvaluableQueryIds(maxQueries)
    return c.json({ success: true, query_ids: ids, total: ids.length })
  } catch (error) {
    return c.json({ error: String(error) }, 500)
  }
})

/**
 * POST /admin/api/ai-search/benchmark/evaluate-batch
 * Evaluate a batch of specific query IDs.
 * Body: { mode: string, limit: number, query_ids: string[], dataset?: string }
 */
adminRoutes.post('/api/benchmark/evaluate-batch', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_BENCHMARK_INDEX || (c.env as any).VECTORIZE_INDEX

    const body = await c.req.json<{
      mode: string
      limit: number
      query_ids: string[]
      dataset?: string
    }>()

    const mode = body.mode || 'fts5'
    const limit = body.limit || 10
    const queryIds = body.query_ids || []
    const dataset = body.dataset || 'scifact'

    if (queryIds.length === 0) {
      return c.json({ error: 'No query_ids provided' }, 400)
    }

    if ((mode === 'ai' || mode === 'hybrid') && !vectorize) {
      return c.json({ error: `${mode.toUpperCase()} mode requires Vectorize binding.` }, 400)
    }

    const benchmarkService = new BenchmarkService(db, kv, undefined, dataset)
    const collectionId = benchmarkService.getCollectionId()
    const aiSearchService = new AISearchService(db, ai, vectorize)

    const searchFn = async (query: string, searchMode: string, searchLimit: number) => {
      const response = await aiSearchService.search({
        query,
        mode: searchMode as any,
        limit: searchLimit,
        filters: { collections: [collectionId] },
      })
      return { results: response.results.map((r) => ({ id: r.id })) }
    }

    const perQuery = await benchmarkService.evaluateBatch(searchFn, mode, limit, queryIds)

    return c.json({
      success: true,
      per_query: perQuery,
      evaluated: perQuery.length,
    })
  } catch (error) {
    console.error('Error in batch evaluation:', error)
    return c.json({ error: String(error) }, 500)
  }
})

export default adminRoutes
