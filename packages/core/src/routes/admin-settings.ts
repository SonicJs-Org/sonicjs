import { Hono } from 'hono'
// import { html } from 'hono/html'
import { requireAuth } from '../middleware'
import { renderSettingsPage, SettingsPageData } from '../templates/pages/admin-settings.template'
import { MigrationService } from '../services/migrations'
import { SettingsService } from '../services/settings'

type Bindings = {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  ASSETS: Fetcher
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  IMAGES_ACCOUNT_ID?: string
  IMAGES_API_TOKEN?: string
  ENVIRONMENT?: string
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
  requestId?: string
  startTime?: number
  appVersion?: string
}

export const adminSettingsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminSettingsRoutes.use('*', requireAuth())

// Helper function to get mock settings data
function getMockSettings(user: any) {
  return {
    general: {
      siteName: 'SonicJS AI',
      siteDescription: 'A modern headless CMS powered by AI',
      adminEmail: user?.email || 'admin@example.com',
      timezone: 'UTC',
      language: 'en',
      maintenanceMode: false
    },
    security: {},
    migrations: {
      totalMigrations: 0,
      appliedMigrations: 0,
      pendingMigrations: 0,
      lastApplied: undefined,
      migrations: []
    },
    databaseTools: {
      totalTables: 0,
      totalRows: 0,
      lastBackup: undefined,
      databaseSize: '0 MB',
      tables: []
    }
  }
}

// Settings page (redirects to general settings)
adminSettingsRoutes.get('/', (c) => {
  return c.redirect('/admin/settings/general')
})

// General settings
adminSettingsRoutes.get('/general', async (c) => {
  const user = c.get('user')
  const db = c.env.DB
  const settingsService = new SettingsService(db)

  // Get real general settings from database
  const generalSettings = await settingsService.getGeneralSettings(user?.email)

  const mockSettings = getMockSettings(user)
  mockSettings.general = generalSettings

  const pageData: SettingsPageData = {
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : undefined,
    settings: mockSettings,
    activeTab: 'general',
    version: c.get('appVersion')
  }
  return c.html(renderSettingsPage(pageData))
})

// Security settings
adminSettingsRoutes.get('/security', async (c) => {
  const user = c.get('user')
  const db = c.env.DB
  const settingsService = new SettingsService(db)

  const persisted = await settingsService.getSecuritySettings()

  const mockSettings = getMockSettings(user)
  mockSettings.security = {
    jwtExpiresIn: persisted.jwtExpiresIn,
    jwtRefreshGraceSeconds: persisted.jwtRefreshGraceSeconds
  }

  const pageData: SettingsPageData = {
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : undefined,
    settings: mockSettings,
    activeTab: 'security',
    version: c.get('appVersion')
  }
  return c.html(renderSettingsPage(pageData))
})

// Migrations settings
adminSettingsRoutes.get('/migrations', (c) => {
  const user = c.get('user')
  const pageData: SettingsPageData = {
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : undefined,
    settings: getMockSettings(user),
    activeTab: 'migrations',
    version: c.get('appVersion')
  }
  return c.html(renderSettingsPage(pageData))
})

// Database tools settings
adminSettingsRoutes.get('/database-tools', (c) => {
  const user = c.get('user')
  const pageData: SettingsPageData = {
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : undefined,
    settings: getMockSettings(user),
    activeTab: 'database-tools',
    version: c.get('appVersion')
  }
  return c.html(renderSettingsPage(pageData))
})

// Get migration status
adminSettingsRoutes.get('/api/migrations/status', async (c) => {
  try {
    const db = c.env.DB
    const migrationService = new MigrationService(db)
    const status = await migrationService.getMigrationStatus()

    return c.json({
      success: true,
      data: status
    })
  } catch (error) {
    console.error('Error fetching migration status:', error)
    return c.json({
      success: false,
      error: 'Failed to fetch migration status'
    }, 500)
  }
})

// Migration execution is managed by Wrangler/D1, not by the running app.
adminSettingsRoutes.post('/api/migrations/run', async (c) => {
  try {
    const user = c.get('user')

    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    return c.json({
      success: false,
      message: 'Migrations are managed by Cloudflare D1. Run `wrangler d1 migrations apply DB --local` or `wrangler d1 migrations apply DB --remote`.',
      applied: [],
      errors: []
    }, 409)
  } catch (error) {
    console.error('Error running migrations:', error)
    return c.json({
      success: false,
      error: 'Failed to run migrations'
    }, 500)
  }
})

// Validate database schema
adminSettingsRoutes.get('/api/migrations/validate', async (c) => {
  try {
    const db = c.env.DB
    const migrationService = new MigrationService(db)
    const validation = await migrationService.validateSchema()

    return c.json({
      success: true,
      data: validation
    })
  } catch (error) {
    console.error('Error validating schema:', error)
    return c.json({
      success: false,
      error: 'Failed to validate schema'
    }, 500)
  }
})

// Get database tools stats
adminSettingsRoutes.get('/api/database-tools/stats', async (c) => {
  try {
    const db = c.env.DB

    // Get list of all tables
    const tablesQuery = await db.prepare(`
      SELECT name FROM sqlite_master
      WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
      AND name NOT LIKE '_cf_%'
      ORDER BY name
    `).all()

    const tables = tablesQuery.results || []
    let totalRows = 0

    // Get row count for each table
    const tableStats = await Promise.all(
      tables.map(async (table: any) => {
        try {
          const countResult = await db.prepare(`SELECT COUNT(*) as count FROM ${table.name}`).first()
          const rowCount = (countResult as any)?.count || 0
          totalRows += rowCount
          return {
            name: table.name,
            rowCount
          }
        } catch (error) {
          console.error(`Error counting rows in ${table.name}:`, error)
          return {
            name: table.name,
            rowCount: 0
          }
        }
      })
    )

    // D1 doesn't expose database size directly, so we'll estimate based on row counts
    // Average row size estimate: 1KB per row (rough approximation)
    const estimatedSizeBytes = totalRows * 1024
    const databaseSizeMB = (estimatedSizeBytes / (1024 * 1024)).toFixed(2)

    return c.json({
      success: true,
      data: {
        totalTables: tables.length,
        totalRows,
        databaseSize: `${databaseSizeMB} MB (estimated)`,
        tables: tableStats
      }
    })
  } catch (error) {
    console.error('Error fetching database stats:', error)
    return c.json({
      success: false,
      error: 'Failed to fetch database statistics'
    }, 500)
  }
})

// Validate database
adminSettingsRoutes.get('/api/database-tools/validate', async (c) => {
  try {
    const db = c.env.DB

    // Run PRAGMA integrity_check
    const integrityResult = await db.prepare('PRAGMA integrity_check').first()
    const isValid = (integrityResult as any)?.integrity_check === 'ok'

    return c.json({
      success: true,
      data: {
        valid: isValid,
        message: isValid ? 'Database integrity check passed' : 'Database integrity check failed'
      }
    })
  } catch (error) {
    console.error('Error validating database:', error)
    return c.json({
      success: false,
      error: 'Failed to validate database'
    }, 500)
  }
})

// Backup database
adminSettingsRoutes.post('/api/database-tools/backup', async (c) => {
  try {
    const user = c.get('user')

    // Only allow admin users
    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    // TODO: Implement actual backup functionality
    // For now, return success message
    return c.json({
      success: true,
      message: 'Database backup feature coming soon. Use Cloudflare Dashboard for backups.'
    })
  } catch (error) {
    console.error('Error creating backup:', error)
    return c.json({
      success: false,
      error: 'Failed to create backup'
    }, 500)
  }
})

// Truncate tables
adminSettingsRoutes.post('/api/database-tools/truncate', async (c) => {
  try {
    const user = c.get('user')

    // Only allow admin users
    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    const body = await c.req.json()
    const tablesToTruncate = body.tables || []

    if (!Array.isArray(tablesToTruncate) || tablesToTruncate.length === 0) {
      return c.json({
        success: false,
        error: 'No tables specified for truncation'
      }, 400)
    }

    const db = c.env.DB
    const results = []

    // Validate table names against actual database tables (prevents SQL injection)
    const tablesResult = await db.prepare(`
      SELECT name FROM sqlite_master
      WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
    `).all()
    const validTables = new Set(
      (tablesResult.results || []).map((row: any) => row.name)
    )

    for (const tableName of tablesToTruncate) {
      if (!validTables.has(tableName)) {
        results.push({ table: tableName, success: false, error: 'Table not found' })
        continue
      }
      try {
        await db.prepare(`DELETE FROM ${tableName}`).run()
        results.push({ table: tableName, success: true })
      } catch (error) {
        console.error(`Error truncating ${tableName}:`, error)
        results.push({ table: tableName, success: false, error: String(error) })
      }
    }

    return c.json({
      success: true,
      message: `Truncated ${results.filter(r => r.success).length} of ${tablesToTruncate.length} tables`,
      results
    })
  } catch (error) {
    console.error('Error truncating tables:', error)
    return c.json({
      success: false,
      error: 'Failed to truncate tables'
    }, 500)
  }
})

// Save general settings
adminSettingsRoutes.post('/general', async (c) => {
  try {
    const user = c.get('user')

    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    const formData = await c.req.formData()
    const db = c.env.DB
    const settingsService = new SettingsService(db)

    // Extract general settings from form data
    const settings = {
      siteName: formData.get('siteName') as string,
      siteDescription: formData.get('siteDescription') as string,
      adminEmail: formData.get('adminEmail') as string,
      timezone: formData.get('timezone') as string,
      language: formData.get('language') as string,
      maintenanceMode: formData.get('maintenanceMode') === 'true'
    }

    // Validate required fields
    if (!settings.siteName || !settings.siteDescription) {
      return c.json({
        success: false,
        error: 'Site name and description are required'
      }, 400)
    }

    // Save settings to database
    const success = await settingsService.saveGeneralSettings(settings)

    if (success) {
      return c.json({
        success: true,
        message: 'General settings saved successfully!'
      })
    } else {
      return c.json({
        success: false,
        error: 'Failed to save settings'
      }, 500)
    }
  } catch (error) {
    console.error('Error saving general settings:', error)
    return c.json({
      success: false,
      error: 'Failed to save settings. Please try again.'
    }, 500)
  }
})

// Save security settings (JWT TTL + refresh grace)
adminSettingsRoutes.post('/security', async (c) => {
  try {
    const user = c.get('user')

    if (!user || user.role !== 'admin') {
      return c.json({
        success: false,
        error: 'Unauthorized. Admin access required.'
      }, 403)
    }

    const formData = await c.req.formData()
    const db = c.env.DB
    const settingsService = new SettingsService(db)

    const jwtExpiresInRaw = (formData.get('jwtExpiresIn') as string | null)?.trim() || ''
    const graceRaw = (formData.get('jwtRefreshGraceSeconds') as string | null)?.trim() || ''

    // Validate jwtExpiresIn: bare seconds or <num><s|m|h|d>
    if (!/^\d+(?:s|m|h|d)?$/i.test(jwtExpiresInRaw)) {
      return c.json({
        success: false,
        error: 'JWT expiration must be a number optionally suffixed with s/m/h/d (e.g. 30d, 12h, 3600).'
      }, 400)
    }

    const graceSeconds = Number.parseInt(graceRaw, 10)
    if (!Number.isFinite(graceSeconds) || graceSeconds < 0 || graceSeconds > 60 * 60 * 24 * 90) {
      return c.json({
        success: false,
        error: 'Refresh grace must be an integer between 0 and 7776000 seconds (90 days).'
      }, 400)
    }

    const success = await settingsService.saveSecuritySettings({
      jwtExpiresIn: jwtExpiresInRaw,
      jwtRefreshGraceSeconds: graceSeconds
    })

    if (success) {
      return c.json({
        success: true,
        message: 'Security settings saved successfully!'
      })
    }
    return c.json({
      success: false,
      error: 'Failed to save settings'
    }, 500)
  } catch (error) {
    console.error('Error saving security settings:', error)
    return c.json({
      success: false,
      error: 'Failed to save settings. Please try again.'
    }, 500)
  }
})

// Save settings (legacy endpoint - redirect to general)
adminSettingsRoutes.post('/', async (c) => {
  return c.redirect('/admin/settings/general')
})

// ── email_log browser (T4.4) ─────────────────────────────────────────────────

/** GET /admin/settings/email-log — HTML browser for core email_log table. */
adminSettingsRoutes.get('/email-log', async (c) => {
  const db = c.env.DB
  const page = Math.max(1, parseInt(c.req.query('page') ?? '1', 10))
  const pageSize = 50
  const offset = (page - 1) * pageSize

  let rows: any[] = []
  let total = 0

  try {
    const countRow = await db.prepare('SELECT COUNT(*) as n FROM email_log').first() as any
    total = countRow?.n ?? 0
    const result = await db
      .prepare(
        `SELECT id, flow, status, provider, recipient, subject, provider_id,
                delivery_state, delivery_synced_at, user_id, created_at
         FROM email_log
         ORDER BY created_at DESC
         LIMIT ? OFFSET ?`
      )
      .bind(pageSize, offset)
      .all()
    rows = (result.results ?? []) as any[]
  } catch {
    // Table may not exist yet (pre-migration) — render empty state.
  }

  const totalPages = Math.ceil(total / pageSize)

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Email Log — SonicJS Admin</title>
  <link rel="stylesheet" href="/admin/assets/css/admin.css">
  <style>
    .email-log-table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .email-log-table th, .email-log-table td { padding: 8px 10px; border-bottom: 1px solid #e5e7eb; text-align: left; }
    .email-log-table th { background: #f9fafb; font-weight: 600; }
    .badge { padding: 2px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; }
    .badge-sent { background: #dcfce7; color: #166534; }
    .badge-failed { background: #fee2e2; color: #991b1b; }
    .badge-pending { background: #fef9c3; color: #854d0e; }
    .delivery-ok { color: #16a34a; }
    .delivery-fail { color: #dc2626; }
    .pagination { display: flex; gap: 8px; padding: 16px 0; }
    .pagination a { padding: 4px 12px; border: 1px solid #d1d5db; border-radius: 4px; text-decoration: none; color: #374151; }
    .pagination a.active { background: #2563eb; color: #fff; border-color: #2563eb; }
    .empty-state { padding: 40px; text-align: center; color: #6b7280; }
  </style>
</head>
<body>
  <div style="padding: 24px; max-width: 1200px; margin: 0 auto;">
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">
      <a href="/admin/settings" style="color: #6b7280; text-decoration: none;">← Settings</a>
      <h1 style="margin: 0; font-size: 20px; font-weight: 700;">Email Log</h1>
      <span style="color: #6b7280; font-size: 14px;">${total.toLocaleString()} total sends</span>
    </div>

    ${rows.length === 0 ? `
      <div class="empty-state">
        <p>No emails logged yet. Email sends are recorded here once the email_log table is migrated.</p>
        <p style="margin-top: 8px; font-size: 12px; color: #9ca3af;">Run migration 037 (and 038 for delivery columns) if the table is missing.</p>
      </div>
    ` : `
      <table class="email-log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Flow</th>
            <th>Recipient</th>
            <th>Subject</th>
            <th>Provider</th>
            <th>Status</th>
            <th>Delivery</th>
            <th>User</th>
          </tr>
        </thead>
        <tbody>
          ${rows.map((r: any) => {
            const ts = r.created_at ? new Date(r.created_at).toLocaleString() : '—'
            const deliveryBadge = r.delivery_state
              ? `<span class="${r.delivery_state === 'delivered' ? 'delivery-ok' : 'delivery-fail'}">${r.delivery_state}</span>`
              : '<span style="color:#9ca3af">—</span>'
            const statusClass = r.status === 'sent' ? 'badge-sent' : r.status === 'failed' ? 'badge-failed' : 'badge-pending'
            return `<tr>
              <td style="white-space:nowrap;color:#6b7280;font-size:12px">${ts}</td>
              <td>${r.flow ?? '—'}</td>
              <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.recipient ?? '—'}</td>
              <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${r.subject ?? '—'}</td>
              <td>${r.provider ?? '—'}</td>
              <td><span class="badge ${statusClass}">${r.status ?? '—'}</span></td>
              <td>${deliveryBadge}</td>
              <td style="font-size:12px;color:#6b7280">${r.user_id ?? '—'}</td>
            </tr>`
          }).join('')}
        </tbody>
      </table>

      ${totalPages > 1 ? `
        <div class="pagination">
          ${Array.from({ length: totalPages }, (_, i) => i + 1).map((p) =>
            `<a href="?page=${p}" class="${p === page ? 'active' : ''}">${p}</a>`
          ).join('')}
        </div>
      ` : ''}
    `}
  </div>
</body>
</html>`

  return c.html(html)
})

/** GET /admin/settings/email-log/api — JSON data for the email_log table. */
adminSettingsRoutes.get('/email-log/api', async (c) => {
  const db = c.env.DB
  const limit = Math.min(200, parseInt(c.req.query('limit') ?? '50', 10))
  const offset = Math.max(0, parseInt(c.req.query('offset') ?? '0', 10))
  const flow = c.req.query('flow')
  const status = c.req.query('status')

  try {
    const conditions: string[] = []
    const params: unknown[] = []
    if (flow) { conditions.push('flow = ?'); params.push(flow) }
    if (status) { conditions.push('status = ?'); params.push(status) }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : ''

    const rows = await db
      .prepare(`SELECT * FROM email_log ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`)
      .bind(...params, limit, offset)
      .all()

    return c.json({ data: rows.results ?? [], limit, offset })
  } catch (err) {
    return c.json({ error: 'email_log not available', details: String(err) }, 503)
  }
})
