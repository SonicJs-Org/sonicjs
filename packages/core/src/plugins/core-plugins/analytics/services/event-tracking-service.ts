import type { D1Database } from '@cloudflare/workers-types'

export interface TrackEventInput {
  event: string
  properties?: Record<string, unknown>
  userId?: string
  sessionId?: string
  ipAddress?: string
  userAgent?: string
  path?: string
  category?: string
}

export interface EventQueryFilters {
  event?: string
  category?: string
  userId?: string
  sessionId?: string
  startDate?: number
  endDate?: number
  limit?: number
  offset?: number
}

export interface EventStats {
  totalEvents: number
  uniqueUsers: number
  uniqueSessions: number
  topEvents: Array<{ event: string; count: number }>
}

export class EventTrackingService {
  constructor(private db: D1Database) {}

  async trackEvent(input: TrackEventInput): Promise<string> {
    const id = crypto.randomUUID()
    const category = input.category || 'user-activity'

    await this.db.prepare(`
      INSERT INTO analytics_events (id, event, category, properties, user_id, session_id, ip_address, user_agent, path)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      input.event,
      category,
      input.properties ? JSON.stringify(input.properties) : null,
      input.userId || null,
      input.sessionId || null,
      input.ipAddress || null,
      input.userAgent || null,
      input.path || null
    ).run()

    return id
  }

  async trackBatch(events: TrackEventInput[]): Promise<string[]> {
    const ids: string[] = []

    const stmts = events.map(input => {
      const id = crypto.randomUUID()
      ids.push(id)
      const category = input.category || 'user-activity'

      return this.db.prepare(`
        INSERT INTO analytics_events (id, event, category, properties, user_id, session_id, ip_address, user_agent, path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id,
        input.event,
        category,
        input.properties ? JSON.stringify(input.properties) : null,
        input.userId || null,
        input.sessionId || null,
        input.ipAddress || null,
        input.userAgent || null,
        input.path || null
      )
    })

    await this.db.batch(stmts)
    return ids
  }

  async queryEvents(filters: EventQueryFilters = {}): Promise<{ events: any[]; total: number }> {
    const conditions: string[] = []
    const params: any[] = []

    if (filters.event) {
      conditions.push('event = ?')
      params.push(filters.event)
    }
    if (filters.category) {
      conditions.push('category = ?')
      params.push(filters.category)
    }
    if (filters.userId) {
      conditions.push('user_id = ?')
      params.push(filters.userId)
    }
    if (filters.sessionId) {
      conditions.push('session_id = ?')
      params.push(filters.sessionId)
    }
    if (filters.startDate) {
      conditions.push('created_at >= ?')
      params.push(filters.startDate)
    }
    if (filters.endDate) {
      conditions.push('created_at <= ?')
      params.push(filters.endDate)
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''
    const limit = filters.limit || 50
    const offset = filters.offset || 0

    const [countResult, eventsResult] = await Promise.all([
      this.db.prepare(`SELECT COUNT(*) as total FROM analytics_events ${where}`).bind(...params).first() as Promise<{ total: number } | null>,
      this.db.prepare(`SELECT * FROM analytics_events ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`).bind(...params, limit, offset).all()
    ])

    const events = (eventsResult.results || []).map((e: any) => ({
      ...e,
      properties: e.properties ? JSON.parse(e.properties) : null
    }))

    return { events, total: countResult?.total || 0 }
  }

  async getStats(startDate?: number, endDate?: number): Promise<EventStats> {
    const conditions: string[] = []
    const params: any[] = []

    if (startDate) {
      conditions.push('created_at >= ?')
      params.push(startDate)
    }
    if (endDate) {
      conditions.push('created_at <= ?')
      params.push(endDate)
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

    const [totals, topEvents] = await Promise.all([
      this.db.prepare(`
        SELECT
          COUNT(*) as total_events,
          COUNT(DISTINCT user_id) as unique_users,
          COUNT(DISTINCT session_id) as unique_sessions
        FROM analytics_events ${where}
      `).bind(...params).first() as Promise<{ total_events: number; unique_users: number; unique_sessions: number } | null>,
      this.db.prepare(`
        SELECT event, COUNT(*) as count
        FROM analytics_events ${where}
        GROUP BY event ORDER BY count DESC LIMIT 20
      `).bind(...params).all()
    ])

    return {
      totalEvents: totals?.total_events || 0,
      uniqueUsers: totals?.unique_users || 0,
      uniqueSessions: totals?.unique_sessions || 0,
      topEvents: (topEvents.results || []).map((r: any) => ({ event: r.event, count: r.count }))
    }
  }
}
