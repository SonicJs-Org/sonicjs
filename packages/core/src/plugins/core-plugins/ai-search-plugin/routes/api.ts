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

// Roles allowed to search across non-published content and to read search
// analytics. Everyone else (including anonymous callers) is limited to published
// results. The app-level session middleware populates `c.get('user')` on every
// route, so this reflects the real signed-in principal even though these routes
// carry no auth middleware of their own.
const PRIVILEGED_SEARCH_ROLES = ['admin', 'editor', 'author']

function isPrivilegedSearcher(c: { get: (k: 'user') => { role?: string } | undefined }): boolean {
  const user = c.get('user')
  return !!user && PRIVILEGED_SEARCH_ROLES.includes(user.role || '')
}

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

    // Non-privileged callers only ever see published content — override any
    // status filter supplied in the body so drafts/archived rows cannot be
    // requested from the public endpoint.
    if (!isPrivilegedSearcher(c)) {
      query.filters = { ...(query.filters || {}), status: ['published'] }
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
 * GET /admin/api/search/analytics
 * Get search analytics
 */
apiRoutes.get('/analytics', async (c) => {
  // Analytics exposes aggregate query volume and other users' popular search
  // terms — restrict to privileged sessions. (This route is intended as
  // /admin/api/search/analytics; the guard makes the current mount safe.)
  if (!isPrivilegedSearcher(c)) {
    return c.json({ success: false, error: 'Unauthorized' }, 403)
  }
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
