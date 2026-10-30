import type { D1Database } from '@cloudflare/workers-types'
import { DocumentsService } from '../../../../services/documents'
import type {
  SecurityEvent,
  SecurityEventInsert,
  SecurityEventFilters,
  SecurityStats,
  TopIP,
  HourlyBucket,
  SecurityAuditSettings
} from '../types'
import { DEFAULT_SETTINGS } from '../types'

const SECURITY_EVENT_TYPE = 'security_event'
const TENANT = 'default'

const QUERYABLE_FIELDS = [
  { name: 'eventType',  kind: 'scalar' as const, type: 'text' as const,    column: 'q_sa_event_type' },
  { name: 'severity',   kind: 'scalar' as const, type: 'text' as const,    column: 'q_sa_severity' },
  { name: 'userId',     kind: 'scalar' as const, type: 'text' as const,    column: 'q_sa_user_id' },
  { name: 'email',      kind: 'scalar' as const, type: 'text' as const,    column: 'q_sa_email' },
  { name: 'ipAddress',  kind: 'scalar' as const, type: 'text' as const,    column: 'q_sa_ip_address' },
  { name: 'blocked',    kind: 'scalar' as const, type: 'integer' as const,  column: 'q_sa_blocked' },
]

const BASE = `type_id = '${SECURITY_EVENT_TYPE}' AND tenant_id = '${TENANT}' AND is_published = 1 AND deleted_at IS NULL`

export class SecurityAuditService {
  private docsService: DocumentsService

  constructor(
    private db: D1Database,
    private settings: SecurityAuditSettings = DEFAULT_SETTINGS
  ) {
    this.docsService = new DocumentsService(db, {
      queryableFields: QUERYABLE_FIELDS,
      maxVersionsPerRoot: 1,
      tenantId: TENANT,
    })
  }

  async logEvent(event: SecurityEventInsert): Promise<string> {
    const doc = await this.docsService.create({
      typeId: SECURITY_EVENT_TYPE,
      title: event.eventType,
      publishOnCreate: true,
      tenantId: TENANT,
      locale: 'default',
      parentRootId: '',
      sortOrder: 0,
      visible: true,
      metadata: {},
      data: {
        eventType: event.eventType,
        severity: event.severity ?? 'info',
        userId: event.userId ?? null,
        email: event.email ?? null,
        ipAddress: event.ipAddress ?? null,
        userAgent: event.userAgent ?? null,
        countryCode: event.countryCode ?? null,
        requestPath: event.requestPath ?? null,
        requestMethod: event.requestMethod ?? null,
        details: event.details ?? null,
        fingerprint: event.fingerprint ?? null,
        blocked: event.blocked ? 1 : 0,
      },
    })
    return doc.id
  }

  async getEvents(filters: SecurityEventFilters = {}): Promise<{ events: SecurityEvent[], total: number }> {
    const conditions: string[] = [
      `type_id = ?`, `tenant_id = ?`, `is_published = 1`, `deleted_at IS NULL`,
    ]
    const params: (string | number)[] = [SECURITY_EVENT_TYPE, TENANT]

    if (filters.eventType) {
      if (Array.isArray(filters.eventType)) {
        conditions.push(`q_sa_event_type IN (${filters.eventType.map(() => '?').join(',')})`)
        params.push(...filters.eventType)
      } else {
        conditions.push('q_sa_event_type = ?')
        params.push(filters.eventType)
      }
    }

    if (filters.severity) {
      if (Array.isArray(filters.severity)) {
        conditions.push(`q_sa_severity IN (${filters.severity.map(() => '?').join(',')})`)
        params.push(...filters.severity)
      } else {
        conditions.push('q_sa_severity = ?')
        params.push(filters.severity)
      }
    }

    if (filters.email) {
      conditions.push('q_sa_email LIKE ?')
      params.push(`%${filters.email}%`)
    }

    if (filters.ipAddress) {
      conditions.push('q_sa_ip_address LIKE ?')
      params.push(`%${filters.ipAddress}%`)
    }

    if (filters.search) {
      conditions.push('(q_sa_email LIKE ? OR q_sa_ip_address LIKE ? OR data LIKE ?)')
      params.push(`%${filters.search}%`, `%${filters.search}%`, `%${filters.search}%`)
    }

    if (filters.startDate) {
      // External dates are in ms; documents.created_at is in seconds.
      conditions.push('created_at >= ?')
      params.push(Math.floor(filters.startDate / 1000))
    }

    if (filters.endDate) {
      conditions.push('created_at <= ?')
      params.push(Math.floor(filters.endDate / 1000))
    }

    if (filters.blocked !== undefined) {
      conditions.push('q_sa_blocked = ?')
      params.push(filters.blocked ? 1 : 0)
    }

    const where = `WHERE ${conditions.join(' AND ')}`
    const sortCol = filters.sortBy === 'event_type' ? 'q_sa_event_type'
      : filters.sortBy === 'severity' ? 'q_sa_severity'
      : 'created_at'
    const sortDir = filters.sortOrder === 'asc' ? 'ASC' : 'DESC'
    const page = filters.page ?? 1
    const limit = filters.limit ?? 50
    const offset = (page - 1) * limit

    const [countResult, eventsResult] = await Promise.all([
      this.db.prepare(`SELECT COUNT(*) as count FROM documents ${where}`)
        .bind(...params).first() as Promise<{ count: number } | null>,
      this.db.prepare(`SELECT * FROM documents ${where} ORDER BY ${sortCol} ${sortDir} LIMIT ? OFFSET ?`)
        .bind(...params, limit, offset).all(),
    ])

    return {
      events: (eventsResult.results ?? []).map(rowToEvent),
      total: countResult?.count ?? 0,
    }
  }

  async getEvent(id: string): Promise<SecurityEvent | null> {
    const row = await this.db.prepare(
      `SELECT * FROM documents WHERE id = ? AND tenant_id = ? AND deleted_at IS NULL`
    ).bind(id, TENANT).first()

    if (!row) return null
    return rowToEvent(row)
  }

  async getStats(): Promise<SecurityStats> {
    const nowSec = Math.floor(Date.now() / 1000)
    const h24 = nowSec - 24 * 3600
    const h48 = nowSec - 48 * 3600
    const lockoutWindowStart = nowSec - this.settings.bruteForce.lockoutDurationMinutes * 60
    const bruteWindowStart = nowSec - this.settings.bruteForce.windowMinutes * 60

    const [
      totalResult,
      failed24hResult,
      failedPrior24hResult,
      lockoutsResult,
      flaggedResult,
      typeResults,
      severityResults,
    ] = await Promise.all([
      this.db.prepare(`SELECT COUNT(*) as count FROM documents WHERE ${BASE}`).first() as Promise<{ count: number } | null>,
      this.db.prepare(`SELECT COUNT(*) as count FROM documents WHERE ${BASE} AND q_sa_event_type = 'login_failure' AND created_at >= ?`).bind(h24).first() as Promise<{ count: number } | null>,
      this.db.prepare(`SELECT COUNT(*) as count FROM documents WHERE ${BASE} AND q_sa_event_type = 'login_failure' AND created_at >= ? AND created_at < ?`).bind(h48, h24).first() as Promise<{ count: number } | null>,
      this.db.prepare(`SELECT COUNT(DISTINCT q_sa_ip_address) as count FROM documents WHERE ${BASE} AND q_sa_event_type = 'account_lockout' AND created_at >= ?`).bind(lockoutWindowStart).first() as Promise<{ count: number } | null>,
      this.db.prepare(`SELECT COUNT(*) as count FROM (SELECT q_sa_ip_address FROM documents WHERE ${BASE} AND q_sa_event_type = 'login_failure' AND created_at >= ? GROUP BY q_sa_ip_address HAVING COUNT(*) >= ?)`).bind(bruteWindowStart, this.settings.bruteForce.maxFailedAttemptsPerIP).first() as Promise<{ count: number } | null>,
      this.db.prepare(`SELECT q_sa_event_type as event_type, COUNT(*) as count FROM documents WHERE ${BASE} AND created_at >= ? GROUP BY q_sa_event_type`).bind(h24).all(),
      this.db.prepare(`SELECT q_sa_severity as severity, COUNT(*) as count FROM documents WHERE ${BASE} AND created_at >= ? GROUP BY q_sa_severity`).bind(h24).all(),
    ])

    const failed24h = failed24hResult?.count ?? 0
    const failedPrior24h = failedPrior24hResult?.count ?? 0
    const trend = failedPrior24h > 0
      ? Math.round(((failed24h - failedPrior24h) / failedPrior24h) * 100)
      : (failed24h > 0 ? 100 : 0)

    const eventsByType: Record<string, number> = {}
    for (const row of (typeResults.results ?? []) as any[]) {
      eventsByType[row.event_type] = row.count
    }

    const eventsBySeverity: Record<string, number> = {}
    for (const row of (severityResults.results ?? []) as any[]) {
      eventsBySeverity[row.severity] = row.count
    }

    return {
      totalEvents: totalResult?.count ?? 0,
      failedLogins24h: failed24h,
      failedLoginsTrend: trend,
      activeLockouts: lockoutsResult?.count ?? 0,
      flaggedIPs: flaggedResult?.count ?? 0,
      eventsByType,
      eventsBySeverity,
    }
  }

  async getTopIPs(limit: number = 10): Promise<TopIP[]> {
    const nowSec = Math.floor(Date.now() / 1000)
    const h24 = nowSec - 24 * 3600
    const lockoutWindowStart = nowSec - this.settings.bruteForce.lockoutDurationMinutes * 60

    const [results, lockoutResults] = await Promise.all([
      this.db.prepare(`
        SELECT
          q_sa_ip_address as ip_address,
          json_extract(data, '$.countryCode') as country_code,
          COUNT(*) as failed_attempts,
          MAX(created_at) as last_seen
        FROM documents
        WHERE ${BASE} AND q_sa_event_type = 'login_failure' AND created_at >= ?
        GROUP BY q_sa_ip_address
        ORDER BY failed_attempts DESC
        LIMIT ?
      `).bind(h24, limit).all(),
      this.db.prepare(
        `SELECT DISTINCT q_sa_ip_address as ip_address FROM documents WHERE ${BASE} AND q_sa_event_type = 'account_lockout' AND created_at >= ?`
      ).bind(lockoutWindowStart).all(),
    ])

    const lockedIPs = new Set((lockoutResults.results ?? []).map((r: any) => r.ip_address))

    return (results.results ?? []).map((row: any) => ({
      ipAddress: row.ip_address,
      countryCode: row.country_code,
      failedAttempts: row.failed_attempts,
      lastSeen: (row.last_seen ?? 0) * 1000, // seconds → ms
      locked: lockedIPs.has(row.ip_address),
    }))
  }

  async getHourlyTrend(hours: number = 24): Promise<HourlyBucket[]> {
    const nowSec = Math.floor(Date.now() / 1000)
    const startSec = nowSec - hours * 3600

    const buckets: HourlyBucket[] = []
    for (let i = 0; i < hours; i++) {
      const bucketStartSec = startSec + i * 3600
      const date = new Date(bucketStartSec * 1000)
      buckets.push({
        hour: `${date.getUTCHours().toString().padStart(2, '0')}:00`,
        count: 0,
      })
    }

    const results = await this.db.prepare(`
      SELECT CAST((created_at - ?) / 3600 AS INTEGER) as bucket, COUNT(*) as count
      FROM documents
      WHERE ${BASE} AND q_sa_event_type = 'login_failure' AND created_at >= ?
      GROUP BY bucket
      ORDER BY bucket
    `).bind(startSec, startSec).all()

    for (const row of (results.results ?? []) as any[]) {
      const idx = row.bucket
      if (idx >= 0 && idx < buckets.length) {
        buckets[idx]!.count = row.count
      }
    }

    return buckets
  }

  async purgeOldEvents(daysToKeep?: number): Promise<number> {
    const days = daysToKeep ?? this.settings.retention.daysToKeep
    const cutoffSec = Math.floor(Date.now() / 1000) - days * 24 * 3600

    const result = await this.db.prepare(
      `DELETE FROM documents WHERE type_id = ? AND tenant_id = ? AND created_at < ?`
    ).bind(SECURITY_EVENT_TYPE, TENANT, cutoffSec).run()

    return (result.meta as any)?.changes ?? 0
  }

  async getRecentCriticalEvents(limit: number = 20): Promise<SecurityEvent[]> {
    const results = await this.db.prepare(
      `SELECT * FROM documents WHERE ${BASE} AND q_sa_severity = 'critical' ORDER BY created_at DESC LIMIT ?`
    ).bind(limit).all()

    return (results.results ?? []).map(rowToEvent)
  }
}

function rowToEvent(row: any): SecurityEvent {
  const data: Record<string, any> = row.data
    ? (typeof row.data === 'string' ? JSON.parse(row.data) : row.data)
    : {}
  return {
    id: row.id,
    eventType: data.eventType,
    severity: data.severity,
    userId: data.userId ?? null,
    email: data.email ?? null,
    ipAddress: data.ipAddress ?? null,
    userAgent: data.userAgent ?? null,
    countryCode: data.countryCode ?? null,
    requestPath: data.requestPath ?? null,
    requestMethod: data.requestMethod ?? null,
    details: data.details ?? null,
    fingerprint: data.fingerprint ?? null,
    blocked: !!data.blocked,
    createdAt: (row.created_at ?? 0) * 1000, // seconds → ms
  }
}
