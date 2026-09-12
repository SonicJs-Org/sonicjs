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
  tenantId?: string
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
    const tenantId = c.get('tenantId') || 'default'
    const service = new AISearchService(db, ai, vectorize, tenantId, (c.env as any).CACHE_KV)

    const body = await c.req.json()

    const query: SearchQuery = {
      query: body.query || '',
      mode: body.mode || 'keyword',
      filters: body.filters || {},
      limit: body.limit ? Number(body.limit) : undefined,
      offset: body.offset ? Number(body.offset) : undefined,
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
    const tenantId = c.get('tenantId') || 'default'
    const service = new AISearchService(db, ai, vectorize, tenantId, (c.env as any).CACHE_KV)

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
