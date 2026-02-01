import { Hono } from 'hono'
import { bearerAuth } from 'hono/bearer-auth'
import { RedirectService } from '../services/redirect'
import type {
  RedirectFilter,
  CreateRedirectInput,
  UpdateRedirectInput,
  MatchType,
  StatusCode
} from '../types'

/**
 * RFC 9457 Problem Details error response
 */
interface APIError {
  type: string
  title: string
  status: number
  detail: string
  instance?: string
}

/**
 * Helper: Create RFC 9457-compliant error response
 */
function apiError(status: number, detail: string, title?: string): APIError {
  const titles: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    500: 'Internal Server Error',
    503: 'Service Unavailable'
  }

  return {
    type: 'about:blank',
    title: title || titles[status] || 'Error',
    status,
    detail
  }
}

/**
 * Create API route handlers for redirect management
 */
export function createRedirectApiRoutes(): Hono {
  const api = new Hono()

  // Optional: Apply Bearer auth to all API routes
  // Skip if request has user context (internal plugin call)
  api.use('/*', async (c: any, next) => {
    // Internal authenticated calls bypass Bearer auth
    const user = c.get('user')
    if (user) {
      return next()
    }

    // External calls require API key
    const apiKey = (c.env as any)?.REDIRECTS_API_KEY
    if (apiKey) {
      return bearerAuth({ token: apiKey })(c, next)
    }

    // No API key configured - allow in dev, block in prod
    if ((c.env as any)?.ENVIRONMENT === 'production') {
      return c.json(apiError(401, 'API key required'), 401)
    }

    return next()
  })

  // GET /api/redirects - List redirects with filtering
  api.get('/', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      // Parse query parameters
      const isActiveParam = c.req.query('isActive')
      const statusCodeParam = c.req.query('statusCode')
      const matchTypeParam = c.req.query('matchType')
      const searchParam = c.req.query('search')

      const filter: RedirectFilter = {
        limit: parseInt(c.req.query('limit') || '50'),
        offset: parseInt(c.req.query('offset') || '0')
      }

      if (isActiveParam === 'true') {
        filter.isActive = true
      } else if (isActiveParam === 'false') {
        filter.isActive = false
      }

      if (statusCodeParam) {
        filter.statusCode = parseInt(statusCodeParam) as StatusCode
      }

      if (matchTypeParam) {
        filter.matchType = parseInt(matchTypeParam) as MatchType
      }

      if (searchParam) {
        filter.search = searchParam
      }

      // Fetch data
      const service = new RedirectService(db)
      const [redirects, total] = await Promise.all([
        service.list(filter),
        service.count(filter)
      ])

      return c.json({
        data: redirects,
        pagination: {
          limit: filter.limit,
          offset: filter.offset,
          total
        }
      })
    } catch (error) {
      console.error('Error listing redirects:', error)
      return c.json(
        apiError(500, 'Failed to list redirects'),
        500
      )
    }
  })

  // GET /api/redirects/:id - Get redirect by ID
  api.get('/:id', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const id = c.req.param('id')
      const service = new RedirectService(db)
      const redirect = await service.getById(id)

      if (!redirect) {
        return c.json(
          apiError(404, `Redirect with ID ${id} not found`),
          404
        )
      }

      return c.json({ data: redirect })
    } catch (error) {
      console.error('Error getting redirect:', error)
      return c.json(
        apiError(500, 'Failed to get redirect'),
        500
      )
    }
  })

  // POST /api/redirects - Create new redirect
  api.post('/', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const body = await c.req.json() as CreateRedirectInput

      // Basic validation
      if (!body.source || !body.destination) {
        return c.json(
          apiError(400, 'Source and destination are required'),
          400
        )
      }

      // Get user ID (from authenticated user or API context)
      const userId = c.get('user')?.id || 'api'

      const service = new RedirectService(db)
      const result = await service.create(body, userId)

      if (!result.success) {
        return c.json(
          apiError(400, result.error!),
          400
        )
      }

      return c.json({ data: result.redirect }, 201)
    } catch (error) {
      console.error('Error creating redirect:', error)
      return c.json(
        apiError(500, 'Failed to create redirect'),
        500
      )
    }
  })

  // PUT /api/redirects/:id - Update redirect
  api.put('/:id', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const id = c.req.param('id')
      const body = await c.req.json() as UpdateRedirectInput

      const service = new RedirectService(db)
      const result = await service.update(id, body)

      if (!result.success) {
        const status = result.error === 'Redirect not found' ? 404 : 400
        return c.json(
          apiError(status, result.error!),
          status
        )
      }

      return c.json({ data: result.redirect })
    } catch (error) {
      console.error('Error updating redirect:', error)
      return c.json(
        apiError(500, 'Failed to update redirect'),
        500
      )
    }
  })

  // DELETE /api/redirects/:id - Delete redirect
  api.delete('/:id', async (c: any) => {
    try {
      const db = c.env?.DB || c.get('db')
      if (!db) {
        return c.json(apiError(503, 'Database unavailable'), 503)
      }

      const id = c.req.param('id')

      const service = new RedirectService(db)
      const result = await service.delete(id)

      if (!result.success) {
        const status = result.error === 'Redirect not found' ? 404 : 400
        return c.json(
          apiError(status, result.error!),
          status
        )
      }

      return c.json({ success: true }, 200)
    } catch (error) {
      console.error('Error deleting redirect:', error)
      return c.json(
        apiError(500, 'Failed to delete redirect'),
        500
      )
    }
  })

  return api
}

export default createRedirectApiRoutes
