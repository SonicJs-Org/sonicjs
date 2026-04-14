import { Hono } from 'hono'
import { EventTrackingService } from '../services/event-tracking-service'
import type { Bindings, Variables } from '../../../../app'

const apiRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// POST /api/events - Track a single event or batch of events
apiRoutes.post('/', async (c) => {
  const db = c.env.DB
  const service = new EventTrackingService(db)

  const ip = c.req.header('cf-connecting-ip')
    || c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    || 'unknown'
  const userAgent = c.req.header('user-agent') || ''
  const user = c.get('user')

  let body: any
  try {
    body = await c.req.json()
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400)
  }

  // Batch support: accept an array of events
  if (Array.isArray(body)) {
    if (body.length > 100) {
      return c.json({ error: 'Batch size limit is 100 events' }, 400)
    }

    const events = body.map(e => ({
      event: e.event,
      category: e.category || 'user-activity',
      properties: e.properties,
      userId: user?.userId || e.userId,
      sessionId: e.sessionId,
      ipAddress: ip,
      userAgent,
      path: e.path
    }))

    // Validate all events have an event name
    const invalid = events.find(e => !e.event || typeof e.event !== 'string')
    if (invalid) {
      return c.json({ error: 'Each event must have an "event" string field' }, 400)
    }

    const ids = await service.trackBatch(events)
    return c.json({ success: true, eventIds: ids, count: ids.length })
  }

  // Single event
  if (!body.event || typeof body.event !== 'string') {
    return c.json({ error: '"event" field is required and must be a string' }, 400)
  }

  const eventId = await service.trackEvent({
    event: body.event,
    category: body.category || 'user-activity',
    properties: body.properties,
    userId: user?.userId || body.userId,
    sessionId: body.sessionId,
    ipAddress: ip,
    userAgent,
    path: body.path
  })

  return c.json({ success: true, eventId })
})

// GET /api/events - Query events (admin only)
apiRoutes.get('/', async (c) => {
  const user = c.get('user')
  if (!user || user.role !== 'admin') {
    return c.json({ error: 'Admin access required' }, 403)
  }

  const db = c.env.DB
  const service = new EventTrackingService(db)

  const filters = {
    event: c.req.query('event') || undefined,
    category: c.req.query('category') || undefined,
    userId: c.req.query('userId') || undefined,
    sessionId: c.req.query('sessionId') || undefined,
    startDate: c.req.query('startDate') ? parseInt(c.req.query('startDate')!) : undefined,
    endDate: c.req.query('endDate') ? parseInt(c.req.query('endDate')!) : undefined,
    limit: c.req.query('limit') ? parseInt(c.req.query('limit')!) : 50,
    offset: c.req.query('offset') ? parseInt(c.req.query('offset')!) : 0
  }

  const result = await service.queryEvents(filters)
  return c.json(result)
})

// GET /api/events/stats - Aggregated event stats (admin only)
apiRoutes.get('/stats', async (c) => {
  const user = c.get('user')
  if (!user || user.role !== 'admin') {
    return c.json({ error: 'Admin access required' }, 403)
  }

  const db = c.env.DB
  const service = new EventTrackingService(db)

  const startDate = c.req.query('startDate') ? parseInt(c.req.query('startDate')!) : undefined
  const endDate = c.req.query('endDate') ? parseInt(c.req.query('endDate')!) : undefined

  const stats = await service.getStats(startDate, endDate)
  return c.json(stats)
})

export { apiRoutes as eventsApiRoutes }
