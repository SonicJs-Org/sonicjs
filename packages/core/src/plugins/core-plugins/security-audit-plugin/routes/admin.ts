import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
import { RbacService } from '../../../../services/rbac'
import { SecurityAuditService } from '../services/security-audit-service'
import { PluginService } from '../../../../services'
import { renderSecurityDashboard, SecurityDashboardData } from '../components/dashboard-page'
import { renderEventLogPage, EventLogPageData } from '../components/event-log-page'
import { renderSecuritySettingsPage, SecuritySettingsPageData } from '../components/settings-page'
import type { Bindings, Variables } from '../../../../app'
import type { SecurityAuditSettings, SecurityEventType, SecuritySeverity } from '../types'
import { DEFAULT_SETTINGS } from '../types'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminRoutes.use('*', requireAuth())

// Check admin role
adminRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
    return c.text('Access denied', 403)
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

// Dashboard
adminRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)

  const [stats, topIPs, hourlyTrend, recentCritical] = await Promise.all([
    service.getStats(),
    service.getTopIPs(10),
    service.getHourlyTrend(24),
    service.getRecentCriticalEvents(20)
  ])

  const pageData: SecurityDashboardData = {
    stats,
    topIPs,
    hourlyTrend,
    recentCritical,
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems')
  }

  return c.html(renderSecurityDashboard(pageData))
})

// Event log
adminRoutes.get('/events', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const settings = await getSettings(db)
  const service = new SecurityAuditService(db, settings)

  const page = parseInt(c.req.query('page') || '1')
  const limit = 50

  const filters = {
    eventType: (c.req.query('type') as SecurityEventType) || undefined,
    severity: (c.req.query('severity') as SecuritySeverity) || undefined,
    email: c.req.query('email') || undefined,
    ipAddress: c.req.query('ip') || undefined,
    search: c.req.query('search') || undefined,
    page,
    limit
  }

  const { events, total } = await service.getEvents(filters)
  const totalPages = Math.ceil(total / limit)

  const pageData: EventLogPageData = {
    events,
    pagination: {
      currentPage: page,
      totalPages,
      totalItems: total,
      itemsPerPage: limit,
      startItem: total === 0 ? 0 : (page - 1) * limit + 1,
      endItem: Math.min(page * limit, total)
    },
    filters,
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion'),
    dynamicMenuItems: c.get('pluginMenuItems')
  }

  return c.html(renderEventLogPage(pageData))
})

// Settings page
adminRoutes.get('/settings', async (c) => {
  const db = c.env.DB
  const user = c.get('user')
  const settings = await getSettings(db)

  const pageData: SecuritySettingsPageData = {
    settings,
    user: user ? { name: user.email, email: user.email, role: user.role } : undefined,
    version: c.get('appVersion'),
    message: c.req.query('message') || undefined,
    dynamicMenuItems: c.get('pluginMenuItems')
  }

  return c.html(renderSecuritySettingsPage(pageData))
})

// Save settings
adminRoutes.post('/settings', async (c) => {
  const db = c.env.DB
  const body = await c.req.parseBody()

  const settings: SecurityAuditSettings = {
    bruteForce: {
      enabled: body['bruteForce.enabled'] === 'true',
      maxFailedAttemptsPerIP: parseInt(body['bruteForce.maxFailedAttemptsPerIP'] as string) || 10,
      maxFailedAttemptsPerEmail: parseInt(body['bruteForce.maxFailedAttemptsPerEmail'] as string) || 5,
      windowMinutes: parseInt(body['bruteForce.windowMinutes'] as string) || 15,
      lockoutDurationMinutes: parseInt(body['bruteForce.lockoutDurationMinutes'] as string) || 30,
      alertThreshold: parseInt(body['bruteForce.alertThreshold'] as string) || 20
    },
    logging: {
      logSuccessfulLogins: body['logging.logSuccessfulLogins'] === 'true',
      logLogouts: body['logging.logLogouts'] === 'true',
      logRegistrations: body['logging.logRegistrations'] === 'true',
      logPasswordResets: body['logging.logPasswordResets'] === 'true',
      logPermissionDenied: body['logging.logPermissionDenied'] === 'true'
    },
    retention: {
      daysToKeep: parseInt(body['retention.daysToKeep'] as string) || 90,
      maxEvents: parseInt(body['retention.maxEvents'] as string) || 100000,
      autoPurge: body['retention.autoPurge'] === 'true'
    }
  }

  const pluginService = new PluginService(db)
  await pluginService.updatePluginSettings('security-audit', settings)

  // For HTMX requests, return 200
  if (c.req.header('HX-Request')) {
    return c.json({ success: true })
  }

  return c.redirect('/admin/plugins/security-audit/settings?message=Settings saved successfully')
})

export { adminRoutes as securityAuditAdminRoutes }
