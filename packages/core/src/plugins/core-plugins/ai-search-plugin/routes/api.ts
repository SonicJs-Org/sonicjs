import { Hono } from 'hono'
import type { Bindings } from '../../../../app'
import { AISearchService } from '../services/ai-search'
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
    const service = new AISearchService(db, ai, vectorize)

    const body = await c.req.json()

    const query: SearchQuery = {
      query: body.query || '',
      mode: body.mode || 'keyword',
      filters: body.filters || {},
      limit: body.limit ? Number(body.limit) : undefined,
      offset: body.offset ? Number(body.offset) : undefined,
      facets: body.facets === true,
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

    if (!query || query.length < 2) {
      return c.json({ success: true, data: [] })
    }

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

export default apiRoutes
