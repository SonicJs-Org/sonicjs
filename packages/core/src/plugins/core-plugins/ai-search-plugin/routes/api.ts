import { Hono } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import type { Bindings } from '../../../../app'
import { AISearchService } from '../services/ai-search'
import { ExperimentService } from '../services/experiment.service'
import { RelatedSearchService } from '../services/related-search.service'
import { TrendingSearchService } from '../services/trending-search.service'
import { teamDraftInterleave } from '../services/interleave.service'
import type { SearchQuery } from '../types'

type Variables = {
  user?: {
    id: number
    email: string
    role: string
  }
}

const apiRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

/**
 * POST /api/search
 * Execute search query
 */
apiRoutes.post('/', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const kv = c.env.CACHE_KV
    const service = new AISearchService(db, ai, vectorize, kv)

    const body = await c.req.json()

    const query: SearchQuery = {
      query: body.query || '',
      mode: body.mode || 'keyword',
      filters: body.filters || {},
      limit: body.limit ? Number(body.limit) : undefined,
      offset: body.offset ? Number(body.offset) : undefined,
      facets: body.facets === true,
      cache: body.cache !== false,
    }

    // Convert date strings to Date objects if present
    if (query.filters?.dateRange) {
      if (typeof query.filters.dateRange.start === 'string') {
        query.filters.dateRange.start = new Date(query.filters.dateRange.start)
      }
      if (typeof query.filters.dateRange.end === 'string') {
        query.filters.dateRange.end = new Date(query.filters.dateRange.end)
      }
    }

    // ── Experiment awareness ──
    let experimentMeta: Record<string, any> | undefined
    try {
      const analytics = (c.env as any).SEARCH_EXPERIMENTS as any
      const expService = new ExperimentService(db, kv, analytics)
      const activeExp = await expService.getActiveExperiment()

      if (activeExp && query.query) {
        const userId = getCookie(c, 'sonicjs_uid')
          || c.req.header('x-forwarded-for')
          || c.req.header('user-agent')
          || 'anon'

        if (!getCookie(c, 'sonicjs_uid')) {
          const uid = crypto.randomUUID()
          setCookie(c, 'sonicjs_uid', uid, { path: '/', maxAge: 365 * 86400, sameSite: 'Lax' })
        }

        if (expService.shouldEnroll(activeExp.id, userId, activeExp.traffic_pct)) {
          const variant = expService.assignVariant(activeExp.id, userId, activeExp.split_ratio)
          const startTime = Date.now()

          if (activeExp.mode === 'interleave') {
            const [controlResults, treatmentResults] = await Promise.all([
              service.searchWithOverrides({ ...query, cache: false }, activeExp.variants.control),
              service.searchWithOverrides({ ...query, cache: false }, activeExp.variants.treatment),
            ])

            const interleaved = teamDraftInterleave(
              controlResults.results,
              treatmentResults.results,
              query.limit || 20
            )

            const elapsed = Date.now() - startTime
            experimentMeta = {
              experiment_id: activeExp.id,
              experiment_mode: activeExp.mode,
              experiment_variant: variant,
              result_origins: interleaved.origins,
            }

            expService.trackSearchEvent({
              experimentId: activeExp.id,
              variantId: variant,
              query: query.query,
              searchMode: query.mode,
              userId,
              searchId: '',
              resultsCount: interleaved.results.length,
              responseTimeMs: elapsed,
            })

            return c.json({
              success: true,
              data: {
                results: interleaved.results,
                total: interleaved.results.length,
                query_time_ms: elapsed,
                mode: query.mode,
              },
              experiment: experimentMeta,
            })
          } else {
            const overrides = variant === 'treatment' ? activeExp.variants.treatment : activeExp.variants.control
            const results = Object.keys(overrides).length > 0
              ? await service.searchWithOverrides({ ...query, cache: false }, overrides)
              : await service.search(query)

            experimentMeta = {
              experiment_id: activeExp.id,
              experiment_mode: activeExp.mode,
              experiment_variant: variant,
            }

            expService.trackSearchEvent({
              experimentId: activeExp.id,
              variantId: variant,
              query: query.query,
              searchMode: query.mode,
              userId,
              searchId: results.search_id || '',
              resultsCount: results.results.length,
              responseTimeMs: results.query_time_ms,
            })

            return c.json({
              success: true,
              data: results,
              experiment: experimentMeta,
            })
          }
        }
      }
    } catch (expError) {
      console.warn('[Search API] Experiment error (falling through):', expError)
    }

    // Standard search (no experiment)
    const results = await service.search(query)

    return c.json({
      success: true,
      data: results,
    })
  } catch (error) {
    console.error('Search error:', error)
    return c.json(
      {
        success: false,
        error: 'Search failed',
        message: error instanceof Error ? error.message : String(error),
      },
      500
    )
  }
})

/**
 * GET /api/search/suggest
 * Get search suggestions (autocomplete)
 */
apiRoutes.get('/suggest', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)

    const query = c.req.query('q') || ''

    const suggestions = await service.getSearchSuggestions(query)

    return c.json({
      success: true,
      data: suggestions,
    })
  } catch (error) {
    console.error('Suggestions error:', error)
    return c.json(
      {
        success: false,
        error: 'Failed to get suggestions',
      },
      500
    )
  }
})

/**
 * POST /api/search/click
 * Record a click event on a search result
 */
apiRoutes.post('/click', async (c) => {
  try {
    const db = c.env.DB
    const body = await c.req.json()

    // Validate required fields
    const searchId = body.search_id
    const contentId = body.content_id
    const clickPosition = body.click_position

    if (!contentId || typeof contentId !== 'string') {
      return c.json({ success: false, error: 'content_id is required' }, 400)
    }
    if (!clickPosition || typeof clickPosition !== 'number' || clickPosition < 1 || !Number.isInteger(clickPosition)) {
      return c.json({ success: false, error: 'click_position must be a positive integer' }, 400)
    }

    // Look up search history for denormalization (id is INTEGER in the DB)
    let query: string | null = null
    let mode: string | null = null
    if (searchId) {
      try {
        const historyRow = await db
          .prepare('SELECT query, mode FROM ai_search_history WHERE id = ? LIMIT 1')
          .bind(Number(searchId))
          .first<{ query: string; mode: string }>()
        if (historyRow) {
          query = historyRow.query
          mode = historyRow.mode
        }
      } catch {
        // History lookup failed — still record the click
      }
    }

    const clickId = crypto.randomUUID()
    await db
      .prepare(`
        INSERT INTO ai_search_clicks (id, search_id, query, mode, clicked_content_id, clicked_content_title, click_position, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `)
      .bind(
        clickId,
        searchId || null,
        query,
        mode,
        contentId,
        body.content_title || null,
        clickPosition
      )
      .run()

    // Experiment click attribution
    if (body.experiment_id && body.experiment_variant) {
      try {
        const kv = c.env.CACHE_KV
        const analytics = (c.env as any).SEARCH_EXPERIMENTS as any
        const expService = new ExperimentService(db, kv, analytics)
        expService.trackClickEvent({
          experimentId: body.experiment_id,
          variantId: body.experiment_variant,
          searchId: searchId || '',
          contentId,
          clickPosition,
        })
      } catch {
        // Best-effort
      }
    }

    return c.json({ success: true })
  } catch (error) {
    console.error('Click tracking error:', error)
    return c.json({ success: true }) // Don't fail the client for tracking errors
  }
})

/**
 * POST /api/search/facet-click
 * Record a facet interaction for Phase 6 agent optimization
 */
apiRoutes.post('/facet-click', async (c) => {
  try {
    const db = c.env.DB
    const body = await c.req.json()

    const facetField = body.facet_field
    const facetValue = body.facet_value
    const searchId = body.search_id

    if (!facetField || typeof facetField !== 'string') {
      return c.json({ success: false, error: 'facet_field is required' }, 400)
    }
    if (!facetValue || typeof facetValue !== 'string') {
      return c.json({ success: false, error: 'facet_value is required' }, 400)
    }

    const id = crypto.randomUUID()
    await db
      .prepare(`
        INSERT INTO ai_search_facet_clicks (id, search_id, facet_field, facet_value, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `)
      .bind(id, searchId || null, facetField, facetValue)
      .run()

    return c.json({ success: true })
  } catch (error) {
    console.error('Facet click tracking error:', error)
    return c.json({ success: true }) // Don't fail the client for tracking errors
  }
})

/**
 * GET /admin/api/search/analytics
 * Get search analytics
 */
apiRoutes.get('/analytics', async (c) => {
  try {
    const db = c.env.DB
    const ai = (c.env as any).AI
    const vectorize = (c.env as any).VECTORIZE_INDEX
    const service = new AISearchService(db, ai, vectorize)

    const analytics = await service.getSearchAnalytics()

    return c.json({
      success: true,
      data: analytics,
    })
  } catch (error) {
    console.error('Analytics error:', error)
    return c.json(
      {
        success: false,
        error: 'Failed to get analytics',
      },
      500
    )
  }
})

/**
 * GET /api/search/related
 * Get related searches for a query
 */
apiRoutes.get('/related', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const q = c.req.query('q') || ''
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 5, 1), 20)

    const service = new RelatedSearchService(db, kv)
    const related = await service.getRelatedSearches(q, limit)

    return c.json({
      success: true,
      data: {
        query: q,
        related,
      },
    })
  } catch (error) {
    console.error('Related searches error:', error)
    return c.json({ success: false, error: 'Failed to get related searches' }, 500)
  }
})

/**
 * GET /api/search/trending
 * Get trending search queries
 */
apiRoutes.get('/trending', async (c) => {
  try {
    const db = c.env.DB
    const kv = c.env.CACHE_KV
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 5, 1), 20)
    const period = Math.min(Math.max(Number(c.req.query('period')) || 7, 1), 30)

    const service = new TrendingSearchService(db, kv)
    const result = await service.getTrending(limit, period)

    return c.json({
      trending: result.items,
      period_days: period,
      generated_at: new Date().toISOString(),
      cached: result.cached,
    })
  } catch (error) {
    console.error('Trending searches error:', error)
    return c.json({ success: false, error: 'Failed to get trending searches' }, 500)
  }
})

export default apiRoutes
