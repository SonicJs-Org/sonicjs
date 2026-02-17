import { Hono } from 'hono'
import type { Bindings } from '../../../../app'
import { requireAuth } from '../../../../middleware'
import { AISearchService } from '../services/ai-search'
import { IndexManager } from '../services/indexer'
import { FTS5Service } from '../services/fts5.service'
import { FacetService } from '../services/facet.service'
import { BenchmarkService } from '../services/benchmark.service'
import { BENCHMARK_DATASETS } from '../data/benchmark-datasets'
import { RankingPipelineService } from '../services/ranking-pipeline.service'
import { SynonymService } from '../services/synonym.service'
import { QueryRulesService } from '../services/query-rules.service'
import { EmbeddingService } from '../services/embedding.service'
import { ChunkingService } from '../services/chunking.service'
import { RecommendationService } from '../services/recommendation.service'
import { RelatedSearchService } from '../services/related-search.service'
import { ExperimentService } from '../services/experiment.service'
import { renderSearchDashboard } from '../../../../templates/pages/admin-search.template'
import type { AISearchSettings, ExperimentMode, FacetDefinition, SearchQuery } from '../types'

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
 * Render search dashboard
 */
adminRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const kv = c.env.CACHE_KV

    const service = new AISearchService(db, ai, vectorize, kv)
    const indexer = new IndexManager(db, ai, vectorize)
    const fts5Service = new FTS5Service(db)

    // Wrap each call individually so a single failure doesn't break the whole dashboard
    let settings: AISearchSettings | null = null
    try { settings = await service.getSettings() } catch { /* use defaults */ }

    let collections: any[] = []
    try { collections = await service.getAllCollections() || [] } catch { /* empty */ }

    let newCollections: any[] = []
    try {
      const detected = await service.detectNewCollections()
      newCollections = (detected || []).map(n => ({ id: String(n.collection.id), name: n.collection.name }))
    } catch { /* empty */ }

    let indexStatus: any = {}
    try { indexStatus = await indexer.getAllIndexStatus() || {} } catch { /* empty */ }

    let analytics: any = null
    try { analytics = await service.getSearchAnalytics() } catch { /* null */ }

    let fts5Status = null
    try {
      const available = await fts5Service.isAvailable()
      if (available) {
        const stats = await fts5Service.getStats()
        fts5Status = { available: true, total_indexed: stats.total_indexed, by_collection: stats.by_collection }
      } else {
        fts5Status = { available: false, total_indexed: 0, by_collection: {} }
      }
    } catch { /* ignore */ }

    return c.html(
      renderSearchDashboard({
        settings,
        collections: collections || [],
        newCollections: newCollections,
        indexStatus: indexStatus || {},
        analytics,
        fts5Status,
        benchmarkStatus: null,
        user: {
          name: user.email,
          email: user.email,
          role: user.role,
        },
      })
    )
  } catch (error) {
    console.error('Error rendering search dashboard:', error)
    return c.html(`<p>Error loading dashboard: ${error instanceof Error ? error.message : String(error)}</p>`, 500)
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
      reranking_enabled: body.reranking_enabled !== undefined ? Boolean(body.reranking_enabled) : currentSettings?.reranking_enabled,
      query_rewriting_enabled: body.query_rewriting_enabled !== undefined ? Boolean(body.query_rewriting_enabled) : currentSettings?.query_rewriting_enabled,
      fts5_title_boost: body.fts5_title_boost !== undefined ? clampWeight(body.fts5_title_boost, currentSettings?.fts5_title_boost ?? 5.0) : currentSettings?.fts5_title_boost,
      fts5_slug_boost: body.fts5_slug_boost !== undefined ? clampWeight(body.fts5_slug_boost, currentSettings?.fts5_slug_boost ?? 2.0) : currentSettings?.fts5_slug_boost,
      fts5_body_boost: body.fts5_body_boost !== undefined ? clampWeight(body.fts5_body_boost, currentSettings?.fts5_body_boost ?? 1.0) : currentSettings?.fts5_body_boost,
      query_synonyms_enabled: body.query_synonyms_enabled !== undefined ? Boolean(body.query_synonyms_enabled) : currentSettings?.query_synonyms_enabled,
      facets_enabled: body.facets_enabled !== undefined ? Boolean(body.facets_enabled) : currentSettings?.facets_enabled,
      facet_config: Array.isArray(body.facet_config) ? body.facet_config : currentSettings?.facet_config,
      facet_max_values: body.facet_max_values !== undefined ? Number(body.facet_max_values) : currentSettings?.facet_max_values,
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
// Query Substitution Rules Routes
// ==========================================

/** GET /api/relevance/rules — list all query substitution rules */
adminRoutes.get('/api/relevance/rules', async (c) => {
  try {
    const rulesService = new QueryRulesService(c.env.DB)
    const rules = await rulesService.getAll()
    return c.json({ success: true, data: rules })
  } catch (error) {
    console.error('Error fetching query rules:', error)
    return c.json({ error: 'Failed to fetch query rules' }, 500)
  }
})

/** POST /api/relevance/rules — create a query substitution rule */
adminRoutes.post('/api/relevance/rules', async (c) => {
  try {
    const body = await c.req.json()
    if (!body.match_pattern || !body.substitute_query) {
      return c.json({ error: 'match_pattern and substitute_query are required' }, 400)
    }
    const rulesService = new QueryRulesService(c.env.DB)
    const rule = await rulesService.create({
      match_pattern: body.match_pattern,
      match_type: body.match_type,
      substitute_query: body.substitute_query,
      enabled: body.enabled,
      priority: body.priority,
    })
    return c.json({ success: true, data: rule })
  } catch (error) {
    console.error('Error creating query rule:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to create query rule' }, 500)
  }
})

/** PUT /api/relevance/rules/:id — update a query substitution rule */
adminRoutes.put('/api/relevance/rules/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const rulesService = new QueryRulesService(c.env.DB)
    const rule = await rulesService.update(id, {
      match_pattern: body.match_pattern,
      match_type: body.match_type,
      substitute_query: body.substitute_query,
      enabled: body.enabled,
      priority: body.priority,
    })
    if (!rule) {
      return c.json({ error: 'Query rule not found' }, 404)
    }
    return c.json({ success: true, data: rule })
  } catch (error) {
    console.error('Error updating query rule:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to update query rule' }, 500)
  }
})

/** DELETE /api/relevance/rules/:id — delete a query substitution rule */
adminRoutes.delete('/api/relevance/rules/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const rulesService = new QueryRulesService(c.env.DB)
    const deleted = await rulesService.delete(id)
    if (!deleted) {
      return c.json({ error: 'Query rule not found' }, 404)
    }
    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting query rule:', error)
    return c.json({ error: 'Failed to delete query rule' }, 500)
  }
})

// ==========================================
// Related Searches Routes
// ==========================================

/**
 * GET /admin/api/ai-search/related-searches
 * List related search pairs (filterable by source_query, source, enabled)
 */
adminRoutes.get('/api/related-searches', async (c) => {
  try {
    const service = new RelatedSearchService(c.env.DB, c.env.CACHE_KV)
    const sourceQuery = c.req.query('source_query')
    const source = c.req.query('source') as 'manual' | 'agent' | undefined
    const enabled = c.req.query('enabled')

    const results = await service.getAll({
      source_query: sourceQuery,
      source,
      enabled: enabled !== undefined ? enabled === 'true' : undefined,
    })

    return c.json({ success: true, data: results })
  } catch (error) {
    console.error('Error listing related searches:', error)
    return c.json({ error: 'Failed to list related searches' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/related-searches
 * Create a manual related search pair
 */
adminRoutes.post('/api/related-searches', async (c) => {
  try {
    const body = await c.req.json()
    const { source_query: sourceQuery, related_query: relatedQuery, position, bidirectional } = body

    if (!sourceQuery || typeof sourceQuery !== 'string' || !sourceQuery.trim()) {
      return c.json({ success: false, error: 'source_query is required' }, 400)
    }
    if (!relatedQuery || typeof relatedQuery !== 'string' || !relatedQuery.trim()) {
      return c.json({ success: false, error: 'related_query is required' }, 400)
    }

    const service = new RelatedSearchService(c.env.DB, c.env.CACHE_KV)
    const result = await service.create(sourceQuery, relatedQuery, {
      source: 'manual',
      position: typeof position === 'number' ? position : 0,
      bidirectional: bidirectional === true,
    })

    return c.json({ success: true, data: result })
  } catch (error: any) {
    if (error?.message?.includes?.('UNIQUE constraint')) {
      return c.json({ success: false, error: 'This related search pair already exists' }, 409)
    }
    console.error('Error creating related search:', error)
    return c.json({ error: 'Failed to create related search' }, 500)
  }
})

/**
 * PUT /admin/api/ai-search/related-searches/:id
 * Update a related search entry
 */
adminRoutes.put('/api/related-searches/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const body = await c.req.json()
    const service = new RelatedSearchService(c.env.DB, c.env.CACHE_KV)

    const updated = await service.update(id, {
      related_query: body.related_query,
      position: body.position,
      enabled: body.enabled,
    })

    if (!updated) {
      return c.json({ error: 'Related search not found' }, 404)
    }

    return c.json({ success: true, data: updated })
  } catch (error) {
    console.error('Error updating related search:', error)
    return c.json({ error: 'Failed to update related search' }, 500)
  }
})

/**
 * DELETE /admin/api/ai-search/related-searches/cache
 * Invalidate auto-generation KV cache
 * NOTE: Must be defined BEFORE the /:id route to avoid "cache" matching as an ID
 */
adminRoutes.delete('/api/related-searches/cache', async (c) => {
  try {
    const query = c.req.query('query')
    const service = new RelatedSearchService(c.env.DB, c.env.CACHE_KV)
    await service.invalidateCache(query || undefined)

    return c.json({ success: true, message: query ? `Cache cleared for "${query}"` : 'All auto-generation cache cleared' })
  } catch (error) {
    console.error('Error clearing related search cache:', error)
    return c.json({ error: 'Failed to clear cache' }, 500)
  }
})

/**
 * DELETE /admin/api/ai-search/related-searches/:id
 * Delete a related search entry
 */
adminRoutes.delete('/api/related-searches/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const service = new RelatedSearchService(c.env.DB, c.env.CACHE_KV)
    const deleted = await service.delete(id)

    if (!deleted) {
      return c.json({ error: 'Related search not found' }, 404)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting related search:', error)
    return c.json({ error: 'Failed to delete related search' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/related-searches/bulk
 * Bulk create related search pairs
 */
adminRoutes.post('/api/related-searches/bulk', async (c) => {
  try {
    const body = await c.req.json()
    const { entries } = body

    if (!Array.isArray(entries) || entries.length === 0) {
      return c.json({ success: false, error: 'entries array is required and must not be empty' }, 400)
    }

    const service = new RelatedSearchService(c.env.DB, c.env.CACHE_KV)
    const count = await service.bulkCreate(entries)

    return c.json({ success: true, data: { created: count, total: entries.length } })
  } catch (error) {
    console.error('Error bulk creating related searches:', error)
    return c.json({ error: 'Failed to bulk create related searches' }, 500)
  }
})

// ==========================================
// Facet Routes
// ==========================================

/**
 * GET /admin/api/ai-search/facets/discover
 * Discover facetable fields from all collection schemas
 */
adminRoutes.get('/api/facets/discover', async (c) => {
  try {
    const facetService = new FacetService(c.env.DB)
    const discovered = await facetService.discoverFields()
    return c.json({ success: true, data: discovered })
  } catch (error) {
    console.error('Error discovering facet fields:', error)
    return c.json({ error: 'Failed to discover facet fields' }, 500)
  }
})

// Fields that shadow built-in facets — strip from saved config to clean up stale data
const BUILTIN_SHADOW_FIELDS = new Set(['$.author', '$.status'])
function stripShadowFacets(config: FacetDefinition[]): FacetDefinition[] {
  return config.filter(f => !BUILTIN_SHADOW_FIELDS.has(f.field))
}

/**
 * GET /admin/api/ai-search/facets/config
 * Get current facet configuration from settings
 */
adminRoutes.get('/api/facets/config', async (c) => {
  try {
    const service = new AISearchService(c.env.DB)
    const settings = await service.getSettings()
    const config = stripShadowFacets(settings?.facet_config ?? [])
    return c.json({
      success: true,
      data: {
        enabled: settings?.facets_enabled ?? false,
        config,
        max_values: settings?.facet_max_values ?? 20,
      }
    })
  } catch (error) {
    console.error('Error fetching facet config:', error)
    return c.json({ error: 'Failed to fetch facet config' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/facets/config
 * Save facet configuration
 * Body: { enabled: boolean, config: FacetDefinition[], max_values?: number }
 */
adminRoutes.post('/api/facets/config', async (c) => {
  try {
    const body = await c.req.json()
    const service = new AISearchService(c.env.DB)

    const updates: Partial<AISearchSettings> = {}
    if (body.enabled !== undefined) updates.facets_enabled = Boolean(body.enabled)
    if (Array.isArray(body.config)) updates.facet_config = stripShadowFacets(body.config as FacetDefinition[])
    if (body.max_values !== undefined) updates.facet_max_values = Number(body.max_values)

    const saved = await service.updateSettings(updates)
    return c.json({
      success: true,
      data: {
        enabled: saved.facets_enabled ?? false,
        config: saved.facet_config ?? [],
        max_values: saved.facet_max_values ?? 20,
      }
    })
  } catch (error) {
    console.error('Error saving facet config:', error)
    return c.json({ error: 'Failed to save facet config' }, 500)
  }
})

/**
 * POST /admin/api/ai-search/facets/auto-generate
 * Run discovery and auto-generate facet config from recommended fields
 */
adminRoutes.post('/api/facets/auto-generate', async (c) => {
  try {
    const facetService = new FacetService(c.env.DB)
    const discovered = await facetService.discoverFields()
    const config = facetService.autoGenerateConfig(discovered)

    // Save to settings
    const service = new AISearchService(c.env.DB)
    const saved = await service.updateSettings({
      facets_enabled: true,
      facet_config: config,
    })

    return c.json({
      success: true,
      data: {
        enabled: true,
        config: saved.facet_config ?? config,
        discovered_count: discovered.length,
        auto_enabled_count: config.length,
      }
    })
  } catch (error) {
    console.error('Error auto-generating facet config:', error)
    return c.json({ error: 'Failed to auto-generate facet config' }, 500)
  }
})

// ==========================================
// Seeding Routes (Dev/Test)
// ==========================================

/**
 * POST /admin/api/ai-search/seed/clicks
 * Seed synthetic click tracking data spread over 30 days.
 * Body: { searches: Array<{ query, mode, results_count, response_time_ms, clicks: Array<{ content_id, content_title, position }> }>, days?: number }
 * Each search gets a historical timestamp; clicks link to their search_id.
 */
adminRoutes.post('/api/seed/clicks', async (c) => {
  try {
    const body = await c.req.json<{
      searches: Array<{
        query: string
        mode: string
        results_count: number
        response_time_ms: number
        clicks: Array<{ content_id: string; content_title: string; position: number }>
      }>
      days?: number
    }>()

    if (!Array.isArray(body.searches) || body.searches.length === 0) {
      return c.json({ error: 'searches array is required' }, 400)
    }

    const db = c.env.DB
    const days = body.days || 30
    const now = Date.now()
    const msPerDay = 24 * 60 * 60 * 1000
    let searchCount = 0
    let clickCount = 0

    for (const [i, s] of body.searches.entries()) {
      // Spread searches across the time range with some randomness
      const daysAgo = (i / body.searches.length) * days
      const jitter = (Math.random() - 0.5) * msPerDay // +/- 12 hours
      const searchTimestamp = now - (daysAgo * msPerDay) + jitter

      // Insert search history record
      const historyResult = await db.prepare(
        `INSERT INTO ai_search_history (query, mode, results_count, response_time_ms, created_at) VALUES (?, ?, ?, ?, ?)`
      ).bind(s.query, s.mode, s.results_count, s.response_time_ms, Math.floor(searchTimestamp)).run()

      const searchId = historyResult.meta?.last_row_id?.toString()
      searchCount++

      // Insert click records linked to this search
      if (s.clicks && searchId) {
        for (const click of s.clicks) {
          const clickId = crypto.randomUUID()
          // Click happens shortly after search (1-60 seconds)
          const clickOffset = Math.floor(Math.random() * 60) * 1000
          const clickDatetime = new Date(searchTimestamp + clickOffset).toISOString().replace('T', ' ').replace('Z', '').slice(0, 19)

          await db.prepare(
            `INSERT INTO ai_search_clicks (id, search_id, query, mode, clicked_content_id, clicked_content_title, click_position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(clickId, searchId, s.query, s.mode, click.content_id, click.content_title, click.position, clickDatetime).run()
          clickCount++
        }
      }
    }

    return c.json({
      success: true,
      data: { searches_inserted: searchCount, clicks_inserted: clickCount }
    })
  } catch (error) {
    console.error('Error seeding click data:', error)
    return c.json({ error: `Seed failed: ${error instanceof Error ? error.message : String(error)}` }, 500)
  }
})

/**
 * POST /admin/api/ai-search/seed/facet-clicks
 * Seed synthetic facet click data spread over 30 days.
 * Body: { clicks: Array<{ facet_field, facet_value, search_id? }>, days?: number }
 */
adminRoutes.post('/api/seed/facet-clicks', async (c) => {
  try {
    const body = await c.req.json<{
      clicks: Array<{ facet_field: string; facet_value: string; search_id?: string }>
      days?: number
    }>()

    if (!Array.isArray(body.clicks) || body.clicks.length === 0) {
      return c.json({ error: 'clicks array is required' }, 400)
    }

    const db = c.env.DB
    const days = body.days || 30
    const now = Date.now()
    const msPerDay = 24 * 60 * 60 * 1000
    let insertCount = 0

    for (const [i, fc] of body.clicks.entries()) {
      const id = crypto.randomUUID()

      // Spread across time range
      const daysAgo = (i / body.clicks.length) * days
      const jitter = (Math.random() - 0.5) * msPerDay
      const timestamp = now - (daysAgo * msPerDay) + jitter
      const datetime = new Date(timestamp).toISOString().replace('T', ' ').replace('Z', '').slice(0, 19)

      await db.prepare(
        `INSERT INTO ai_search_facet_clicks (id, search_id, facet_field, facet_value, created_at) VALUES (?, ?, ?, ?, ?)`
      ).bind(id, fc.search_id || null, fc.facet_field, fc.facet_value, datetime).run()
      insertCount++
    }

    return c.json({
      success: true,
      data: { facet_clicks_inserted: insertCount }
    })
  } catch (error) {
    console.error('Error seeding facet click data:', error)
    return c.json({ error: `Seed failed: ${error instanceof Error ? error.message : String(error)}` }, 500)
  }
})

/**
 * DELETE /admin/api/ai-search/seed/clicks
 * Clear all seeded/synthetic click + search history data (for re-seeding)
 */
adminRoutes.delete('/api/seed/clicks', async (c) => {
  try {
    const db = c.env.DB
    await db.prepare('DELETE FROM ai_search_clicks').run()
    await db.prepare('DELETE FROM ai_search_history').run()
    return c.json({ success: true, message: 'Cleared click tracking and search history data' })
  } catch (error) {
    return c.json({ error: `Clear failed: ${error instanceof Error ? error.message : String(error)}` }, 500)
  }
})

/**
 * DELETE /admin/api/ai-search/seed/facet-clicks
 * Clear all facet click data (for re-seeding)
 */
adminRoutes.delete('/api/seed/facet-clicks', async (c) => {
  try {
    const db = c.env.DB
    await db.prepare('DELETE FROM ai_search_facet_clicks').run()
    return c.json({ success: true, message: 'Cleared facet click data' })
  } catch (error) {
    return c.json({ error: `Clear failed: ${error instanceof Error ? error.message : String(error)}` }, 500)
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

// ==========================================
// Search Quality Agent Routes
// ==========================================

/** POST /api/agent/run — Trigger analysis via waitUntil() */
adminRoutes.post('/api/agent/run', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)

    // Check if already running
    const latest = await recService.getLatestRun()
    if (latest && latest.status === 'running') {
      return c.json({ error: 'Analysis already running' }, 409)
    }

    // Run analysis in background via waitUntil
    const runIdPromise = recService.runAnalysis()

    // We need the runId to return it immediately, but runAnalysis creates the run
    // internally. Instead, start the run, return immediately, UI polls for status.
    c.executionCtx.waitUntil(runIdPromise.then(runId => {
      console.log(`[Agent] Analysis run ${runId} completed`)
    }).catch(error => {
      console.error('[Agent] Analysis failed:', error)
    }))

    return c.json({ success: true, message: 'Analysis started' })
  } catch (error) {
    console.error('Error starting agent analysis:', error)
    return c.json({ error: 'Failed to start analysis' }, 500)
  }
})

/** GET /api/agent/status — Latest run + aggregate stats */
adminRoutes.get('/api/agent/status', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)

    const [latestRun, stats] = await Promise.all([
      recService.getLatestRun(),
      recService.getStats(),
    ])

    return c.json({
      success: true,
      data: {
        latest_run: latestRun,
        stats,
      }
    })
  } catch (error) {
    console.error('Error fetching agent status:', error)
    return c.json({ error: 'Failed to fetch agent status' }, 500)
  }
})

/** GET /api/agent/recommendations — List with ?status=&category= filters */
adminRoutes.get('/api/agent/recommendations', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)

    const status = c.req.query('status') || undefined
    const category = c.req.query('category') || undefined
    const limit = parseInt(c.req.query('limit') || '100', 10)
    const offset = parseInt(c.req.query('offset') || '0', 10)

    const recs = await recService.getAll({
      status: status as any,
      category: category as any,
      limit,
      offset,
    })

    return c.json({ success: true, data: recs })
  } catch (error) {
    console.error('Error fetching recommendations:', error)
    return c.json({ error: 'Failed to fetch recommendations' }, 500)
  }
})

/** POST /api/agent/recommendations/:id/apply — Auto-apply (creates synonym/rule) */
adminRoutes.post('/api/agent/recommendations/:id/apply', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)
    const id = c.req.param('id')

    const result = await recService.applyRecommendation(id)
    if (!result.success) {
      return c.json({ success: false, error: result.message }, 400)
    }

    return c.json({ success: true, message: result.message })
  } catch (error) {
    console.error('Error applying recommendation:', error)
    return c.json({ error: 'Failed to apply recommendation' }, 500)
  }
})

/** POST /api/agent/recommendations/:id/dismiss — Dismiss single */
adminRoutes.post('/api/agent/recommendations/:id/dismiss', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)
    const id = c.req.param('id')

    const updated = await recService.updateStatus(id, 'dismissed')
    if (!updated) {
      return c.json({ error: 'Recommendation not found' }, 404)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Error dismissing recommendation:', error)
    return c.json({ error: 'Failed to dismiss recommendation' }, 500)
  }
})

/** POST /api/agent/recommendations/dismiss-all — Dismiss all pending */
adminRoutes.post('/api/agent/recommendations/dismiss-all', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)

    const dismissed = await recService.dismissAll()

    return c.json({ success: true, data: { dismissed } })
  } catch (error) {
    console.error('Error dismissing all recommendations:', error)
    return c.json({ error: 'Failed to dismiss recommendations' }, 500)
  }
})

/** GET /api/agent/runs — Run history */
adminRoutes.get('/api/agent/runs', async (c) => {
  try {
    const db = c.env.DB
    const recService = new RecommendationService(db)

    const limit = parseInt(c.req.query('limit') || '20', 10)
    const runs = await recService.getRunHistory(limit)

    return c.json({ success: true, data: runs })
  } catch (error) {
    console.error('Error fetching run history:', error)
    return c.json({ error: 'Failed to fetch run history' }, 500)
  }
})

// =============================================
// Experiment Routes
// =============================================

/** GET /api/experiments — List experiments */
adminRoutes.get('/api/experiments', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const analytics = (c.env as any).SEARCH_EXPERIMENTS
    const expService = new ExperimentService(db, kv, analytics)

    const status = c.req.query('status') as any
    const mode = c.req.query('mode') as ExperimentMode | undefined
    const limit = parseInt(c.req.query('limit') || '50', 10)
    const offset = parseInt(c.req.query('offset') || '0', 10)

    const experiments = await expService.getAll({ status, mode, limit, offset })
    return c.json({ success: true, data: experiments })
  } catch (error) {
    console.error('Error listing experiments:', error)
    return c.json({ error: 'Failed to list experiments' }, 500)
  }
})

/** POST /api/experiments — Create experiment */
adminRoutes.post('/api/experiments', async (c) => {
  try {
    const db = c.env.DB
    const expService = new ExperimentService(db)
    const body = await c.req.json()

    if (!body.name || !body.variants) {
      return c.json({ error: 'name and variants are required' }, 400)
    }

    const experiment = await expService.create({
      name: body.name,
      description: body.description,
      mode: body.mode,
      traffic_pct: body.traffic_pct,
      split_ratio: body.split_ratio,
      variants: body.variants,
      min_searches: body.min_searches,
    })

    return c.json({ success: true, data: experiment })
  } catch (error) {
    console.error('Error creating experiment:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to create experiment' }, 500)
  }
})

/** GET /api/experiments/:id — Get experiment */
adminRoutes.get('/api/experiments/:id', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const analytics = (c.env as any).SEARCH_EXPERIMENTS
    const expService = new ExperimentService(db, kv, analytics)
    const id = c.req.param('id')

    const experiment = await expService.getById(id)
    if (!experiment) {
      return c.json({ error: 'Experiment not found' }, 404)
    }

    return c.json({ success: true, data: experiment })
  } catch (error) {
    console.error('Error fetching experiment:', error)
    return c.json({ error: 'Failed to fetch experiment' }, 500)
  }
})

/** PUT /api/experiments/:id — Update experiment */
adminRoutes.put('/api/experiments/:id', async (c) => {
  try {
    const db = c.env.DB
    const expService = new ExperimentService(db)
    const id = c.req.param('id')
    const body = await c.req.json()

    const experiment = await expService.update(id, body)
    if (!experiment) {
      return c.json({ error: 'Experiment not found' }, 404)
    }

    return c.json({ success: true, data: experiment })
  } catch (error) {
    console.error('Error updating experiment:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to update experiment' }, 500)
  }
})

/** POST /api/experiments/:id/start — Start experiment */
adminRoutes.post('/api/experiments/:id/start', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const expService = new ExperimentService(db, kv)
    const id = c.req.param('id')

    const experiment = await expService.start(id)
    return c.json({ success: true, data: experiment })
  } catch (error) {
    console.error('Error starting experiment:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to start experiment' }, 500)
  }
})

/** POST /api/experiments/:id/pause — Pause experiment */
adminRoutes.post('/api/experiments/:id/pause', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const expService = new ExperimentService(db, kv)
    const id = c.req.param('id')

    const experiment = await expService.pause(id)
    return c.json({ success: true, data: experiment })
  } catch (error) {
    console.error('Error pausing experiment:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to pause experiment' }, 500)
  }
})

/** POST /api/experiments/:id/complete — Complete experiment */
adminRoutes.post('/api/experiments/:id/complete', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const expService = new ExperimentService(db, kv)
    const id = c.req.param('id')
    const body = await c.req.json().catch(() => ({}))

    const experiment = await expService.complete(id, body.winner)
    return c.json({ success: true, data: experiment })
  } catch (error) {
    console.error('Error completing experiment:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to complete experiment' }, 500)
  }
})

/** DELETE /api/experiments/:id — Delete experiment */
adminRoutes.delete('/api/experiments/:id', async (c) => {
  try {
    const db = c.env.DB
    const expService = new ExperimentService(db)
    const id = c.req.param('id')

    const deleted = await expService.delete(id)
    if (!deleted) {
      return c.json({ error: 'Experiment not found' }, 404)
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Error deleting experiment:', error)
    return c.json({ error: error instanceof Error ? error.message : 'Failed to delete experiment' }, 500)
  }
})

/** GET /api/experiments/:id/metrics — Live metrics */
adminRoutes.get('/api/experiments/:id/metrics', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const analytics = (c.env as any).SEARCH_EXPERIMENTS
    const expService = new ExperimentService(db, kv, analytics)
    const id = c.req.param('id')

    const metrics = await expService.evaluateExperiment(id)
    if (!metrics) {
      return c.json({ error: 'Experiment not found or not running' }, 404)
    }

    return c.json({ success: true, data: metrics })
  } catch (error) {
    console.error('Error fetching experiment metrics:', error)
    return c.json({ error: 'Failed to fetch metrics' }, 500)
  }
})

export default adminRoutes
