import type { D1Database } from '@cloudflare/workers-types'
import { DocumentsService } from '../../../../services/documents'

const ANALYTICS_TYPE = 'analytics_event'
const TENANT = 'default'

const QUERYABLE_FIELDS = [
  { name: 'event',     kind: 'scalar' as const, type: 'text' as const,    column: 'q_evt_event' },
  { name: 'category',  kind: 'scalar' as const, type: 'text' as const,    column: 'q_evt_category' },
  { name: 'userId',    kind: 'scalar' as const, type: 'text' as const,    column: 'q_evt_user_id' },
  { name: 'sessionId', kind: 'scalar' as const, type: 'text' as const,    column: 'q_evt_session_id' },
  { name: 'path',      kind: 'scalar' as const, type: 'text' as const,    column: 'q_evt_path' },
]

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
  private docsService: DocumentsService

  constructor(private db: D1Database) {
    this.docsService = new DocumentsService(db, {
      queryableFields: QUERYABLE_FIELDS,
      maxVersionsPerRoot: 1,
      tenantId: TENANT,
    })
  }

  async trackEvent(input: TrackEventInput): Promise<string> {
    const doc = await this.docsService.create({
      typeId: ANALYTICS_TYPE,
      title: input.event,
      publishOnCreate: true,
      tenantId: TENANT,
      locale: 'default',
      parentRootId: '',
      sortOrder: 0,
      visible: true,
      metadata: {},
      data: {
        event: input.event,
        category: input.category ?? 'user-activity',
        properties: input.properties ?? null,
        userId: input.userId ?? null,
        sessionId: input.sessionId ?? null,
        ipAddress: input.ipAddress ?? null,
        userAgent: input.userAgent ?? null,
        path: input.path ?? null,
      },
    })
    return doc.id
  }

  async trackBatch(events: TrackEventInput[]): Promise<string[]> {
    const ids: string[] = []
    for (const e of events) {
      ids.push(await this.trackEvent(e))
    }
    return ids
  }

  async queryEvents(filters: EventQueryFilters = {}): Promise<{ events: any[]; total: number }> {
    const conditions: string[] = [
      'type_id = ?', 'tenant_id = ?', 'is_published = 1', 'deleted_at IS NULL',
    ]
    const params: (string | number)[] = [ANALYTICS_TYPE, TENANT]

    if (filters.event)     { conditions.push('q_evt_event = ?');      params.push(filters.event) }
    if (filters.category)  { conditions.push('q_evt_category = ?');   params.push(filters.category) }
    if (filters.userId)    { conditions.push('q_evt_user_id = ?');    params.push(filters.userId) }
    if (filters.sessionId) { conditions.push('q_evt_session_id = ?'); params.push(filters.sessionId) }
    if (filters.startDate) { conditions.push('created_at >= ?');      params.push(filters.startDate) }
    if (filters.endDate)   { conditions.push('created_at <= ?');      params.push(filters.endDate) }

    const where = `WHERE ${conditions.join(' AND ')}`
    const limit  = filters.limit  ?? 50
    const offset = filters.offset ?? 0

    const [countResult, eventsResult] = await Promise.all([
      this.db.prepare(`SELECT COUNT(*) as total FROM documents ${where}`)
        .bind(...params).first() as Promise<{ total: number } | null>,
      this.db.prepare(`SELECT * FROM documents ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
        .bind(...params, limit, offset).all(),
    ])

    const events = (eventsResult.results ?? []).map((e: any) => ({
      id: e.id,
      createdAt: e.created_at,
      ...(e.data ? JSON.parse(e.data) : {}),
    }))

    return { events, total: countResult?.total ?? 0 }
  }

  async getStats(startDate?: number, endDate?: number): Promise<EventStats> {
    const conditions: string[] = [
      'type_id = ?', 'tenant_id = ?', 'is_published = 1', 'deleted_at IS NULL',
    ]
    const params: (string | number)[] = [ANALYTICS_TYPE, TENANT]

    if (startDate) { conditions.push('created_at >= ?'); params.push(startDate) }
    if (endDate)   { conditions.push('created_at <= ?'); params.push(endDate) }

    const where = `WHERE ${conditions.join(' AND ')}`

    const [totals, topEvents] = await Promise.all([
      this.db.prepare(`
        SELECT
          COUNT(*) as total_events,
          COUNT(DISTINCT q_evt_user_id) as unique_users,
          COUNT(DISTINCT q_evt_session_id) as unique_sessions
        FROM documents ${where}
      `).bind(...params).first() as Promise<{ total_events: number; unique_users: number; unique_sessions: number } | null>,
      this.db.prepare(`
        SELECT q_evt_event as event, COUNT(*) as count
        FROM documents ${where}
        GROUP BY q_evt_event ORDER BY count DESC LIMIT 20
      `).bind(...params).all(),
    ])

    return {
      totalEvents:    totals?.total_events   ?? 0,
      uniqueUsers:    totals?.unique_users    ?? 0,
      uniqueSessions: totals?.unique_sessions ?? 0,
      topEvents: (topEvents.results ?? []).map((r: any) => ({ event: r.event, count: r.count })),
    }
  }
}
