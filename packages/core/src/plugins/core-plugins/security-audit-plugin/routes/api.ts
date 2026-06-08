import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
import { RbacService } from '../../../../services/rbac'
import { SecurityAuditService } from '../services/security-audit-service'
import { BruteForceDetector } from '../services/brute-force-detector'
import { PluginService } from '../../../../services'
import type { Bindings, Variables } from '../../../../app'
import type { SecurityAuditSettings, SecurityEventFilters, SecurityEventType, SecuritySeverity } from '../types'
import { DEFAULT_SETTINGS } from '../types'

const apiRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

apiRoutes.use('*', requireAuth())

// Check admin role
apiRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
    return c.json({ error: 'Access denied' }, 403)
  }
  return next()
})

async function getSettings(db: any): Promise<SecurityAuditSettings> {
  try {
    const pluginService = new PluginService(db)
    const plugin = await pluginService.getPlugin('security-audit')
    if (plugin?.settings) {
      const settings = typeof plugin.settings === 'string' ? JSON.parse(plugin.settings) : plugin.settings
      return { ...DEFAULT_SETTINGS, ...settings }
    }
  } catch { /* ignore */ }
  return DEFAULT_SETTINGS
}

// GET /api/security-audit/events
apiRoutes.get('/events', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)

  const filters: SecurityEventFilters = {
    eventType: c.req.query('type') as SecurityEventType | undefined,
    severity: c.req.query('severity') as SecuritySeverity | undefined,
    email: c.req.query('email') || undefined,
    ipAddress: c.req.query('ip') || undefined,
    search: c.req.query('search') || undefined,
    startDate: c.req.query('start') ? parseInt(c.req.query('start')!) : undefined,
    endDate: c.req.query('end') ? parseInt(c.req.query('end')!) : undefined,
    page: c.req.query('page') ? parseInt(c.req.query('page')!) : 1,
    limit: c.req.query('limit') ? Math.min(parseInt(c.req.query('limit')!), 100) : 50,
    sortBy: (c.req.query('sortBy') as any) || 'created_at',
    sortOrder: (c.req.query('sortOrder') as any) || 'desc'
  }

  const result = await service.getEvents(filters)
  return c.json(result)
})

// GET /api/security-audit/events/:id
apiRoutes.get('/events/:id', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)
  const event = await service.getEvent(c.req.param('id'))

  if (!event) {
    return c.json({ error: 'Event not found' }, 404)
  }

  return c.json(event)
})

// GET /api/security-audit/stats
apiRoutes.get('/stats', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)
  const stats = await service.getStats()
  return c.json(stats)
})

// GET /api/security-audit/stats/ips
apiRoutes.get('/stats/ips', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)
  const limit = c.req.query('limit') ? parseInt(c.req.query('limit')!) : 10
  const ips = await service.getTopIPs(limit)
  return c.json(ips)
})

// GET /api/security-audit/stats/trend
apiRoutes.get('/stats/trend', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)
  const hours = c.req.query('hours') ? parseInt(c.req.query('hours')!) : 24
  const trend = await service.getHourlyTrend(hours)
  return c.json(trend)
})

// GET /api/security-audit/lockouts
apiRoutes.get('/lockouts', async (c) => {
  const kv = c.env.CACHE_KV
  const db = c.env.DB
  const settings = await getSettings(db)
  const detector = new BruteForceDetector(kv, settings.bruteForce)
  const lockouts = await detector.getActiveLockouts()
  return c.json(lockouts)
})

// DELETE /api/security-audit/lockouts/:key
apiRoutes.delete('/lockouts/:key', async (c) => {
  const kv = c.env.CACHE_KV
  const key = decodeURIComponent(c.req.param('key'))
  const db = c.env.DB
  const settings = await getSettings(db)
  const detector = new BruteForceDetector(kv, settings.bruteForce)
  await detector.releaseLockout(key)
  return c.json({ success: true })
})

// POST /api/security-audit/events/purge
apiRoutes.post('/events/purge', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)
  const body = await c.req.json().catch(() => ({})) as { daysToKeep?: number }
  const deleted = await service.purgeOldEvents(body.daysToKeep)
  return c.json({ success: true, deleted })
})

// GET /api/security-audit/export
apiRoutes.get('/export', async (c) => {
  const db = c.env.DB
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)
  const format = c.req.query('format') || 'json'

  const filters: SecurityEventFilters = {
    eventType: c.req.query('type') as SecurityEventType | undefined,
    severity: c.req.query('severity') as SecuritySeverity | undefined,
    startDate: c.req.query('start') ? parseInt(c.req.query('start')!) : undefined,
    endDate: c.req.query('end') ? parseInt(c.req.query('end')!) : undefined,
    limit: 10000,
    page: 1
  }

  const { events } = await service.getEvents(filters)

  if (format === 'csv') {
    const headers = ['id', 'event_type', 'severity', 'email', 'ip_address', 'country_code', 'blocked', 'created_at']
    const csvRows = [headers.join(',')]
    for (const event of events) {
      csvRows.push([
        event.id,
        event.eventType,
        event.severity,
        event.email || '',
        event.ipAddress || '',
        event.countryCode || '',
        event.blocked ? '1' : '0',
        new Date(event.createdAt).toISOString()
      ].map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
    }

    return new Response(csvRows.join('\n'), {
      headers: {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="security-events-${Date.now()}.csv"`
      }
    })
  }

  return c.json(events)
})

export { apiRoutes as securityAuditApiRoutes }
