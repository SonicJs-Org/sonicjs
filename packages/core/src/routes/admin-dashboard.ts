import { Hono } from 'hono'
import type { D1Database, KVNamespace, R2Bucket } from '@cloudflare/workers-types'
import { requireAuth } from '../middleware'
import {
  renderDashboardPage,
  type DashboardPageData,
  renderStatsCards,
  renderStorageUsage,
  renderRecentActivity,
  type ActivityItem
} from '../templates/pages/admin-dashboard.template'
import { getCoreVersion } from '../utils/version'
import { metricsTracker } from '../utils/metrics'

const VERSION = getCoreVersion()

type Bindings = {
  DB: D1Database
  CACHE_KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
  }
}

const router = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
router.use('*', requireAuth())

/**
 * GET /admin - Admin Dashboard
 */
router.get('/', async (c) => {
  const user = c.get('user')

  try {
    const pageData: DashboardPageData = {
      user: {
        name: user!.email.split('@')[0] || user!.email,
        email: user!.email,
        role: user!.role
      },
      version: VERSION
    }

    return c.html(renderDashboardPage(pageData))
  } catch (error) {
    console.error('Dashboard error:', error)

    // Return dashboard with error state
    const pageData: DashboardPageData = {
      user: {
        name: user!.email,
        email: user!.email,
        role: user!.role
      },
      version: VERSION
    }

    return c.html(renderDashboardPage(pageData))
  }
})

/**
 * GET /admin/dashboard/stats - Dashboard stats HTML fragment (HTMX endpoint)
 */
router.get('/stats', async (c) => {
  try {
    const db = c.env.DB

    // Get collections count
    let collectionsCount = 0
    try {
      const collectionsStmt = db.prepare("SELECT COUNT(*) as count FROM collections WHERE is_active = 1 AND (source_type IS NULL OR source_type = 'user')")
      const collectionsResult = await collectionsStmt.first()
      collectionsCount = (collectionsResult as any)?.count || 0
    } catch (error) {
      console.error('Error fetching collections count:', error)
    }

    // Get content count
    let contentCount = 0
    try {
      const contentStmt = db.prepare("SELECT COUNT(*) as count FROM content c JOIN collections col ON c.collection_id = col.id WHERE (col.source_type IS NULL OR col.source_type = 'user')")
      const contentResult = await contentStmt.first()
      contentCount = (contentResult as any)?.count || 0
    } catch (error) {
      console.error('Error fetching content count:', error)
    }

    // Get media count and total size
    let mediaCount = 0
    let mediaSize = 0
    try {
      const mediaStmt = db.prepare('SELECT COUNT(*) as count, COALESCE(SUM(size), 0) as total_size FROM media WHERE deleted_at IS NULL')
      const mediaResult = await mediaStmt.first()
      mediaCount = (mediaResult as any)?.count || 0
      mediaSize = (mediaResult as any)?.total_size || 0
    } catch (error) {
      console.error('Error fetching media count:', error)
    }

    // Get users count
    let usersCount = 0
    try {
      const usersStmt = db.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1')
      const usersResult = await usersStmt.first()
      usersCount = (usersResult as any)?.count || 0
    } catch (error) {
      console.error('Error fetching users count:', error)
    }

    const html = renderStatsCards({
      collections: collectionsCount,
      contentItems: contentCount,
      mediaFiles: mediaCount,
      users: usersCount,
      mediaSize: mediaSize
    })

    return c.html(html)
  } catch (error) {
    console.error('Error fetching stats:', error)
    return c.html('<div class="text-red-500">Failed to load statistics</div>')
  }
})

/**
 * GET /admin/dashboard/storage - Storage usage HTML fragment (HTMX endpoint)
 */
router.get('/storage', async (c) => {
  try {
    const db = c.env.DB

    // Get database size from D1 metadata
    let databaseSize = 0
    try {
      const result = await db.prepare('SELECT 1').run()
      databaseSize = (result as any)?.meta?.size_after || 0
    } catch (error) {
      console.error('Error fetching database size:', error)
    }

    // Get media total size
    let mediaSize = 0
    try {
      const mediaStmt = db.prepare('SELECT COALESCE(SUM(size), 0) as total_size FROM media WHERE deleted_at IS NULL')
      const mediaResult = await mediaStmt.first()
      mediaSize = (mediaResult as any)?.total_size || 0
    } catch (error) {
      console.error('Error fetching media size:', error)
    }

    const html = renderStorageUsage(databaseSize, mediaSize)
    return c.html(html)
  } catch (error) {
    console.error('Error fetching storage usage:', error)
    return c.html('<div class="text-red-500">Failed to load storage information</div>')
  }
})

/**
 * GET /admin/dashboard/recent-activity - Recent activity HTML fragment (HTMX endpoint)
 */
router.get('/recent-activity', async (c) => {
  try {
    const db = c.env.DB
    const limit = parseInt(c.req.query('limit') || '5')

    // Get recent activities from activity_logs table
    const activityStmt = db.prepare(`
      SELECT
        a.id,
        a.action,
        a.resource_type,
        a.resource_id,
        a.details,
        a.created_at,
        u.email,
        u.first_name,
        u.last_name
      FROM activity_logs a
      LEFT JOIN users u ON a.user_id = u.id
      WHERE a.resource_type IN ('content', 'collections', 'users', 'media')
      ORDER BY a.created_at DESC
      LIMIT ?
    `)

    const { results } = await activityStmt.bind(limit).all()

    const activities: ActivityItem[] = (results || []).map((row: any) => {
      const userName = row.first_name && row.last_name
        ? `${row.first_name} ${row.last_name}`
        : row.email || 'System'

      // Format description based on action and resource type
      let description = ''
      if (row.action === 'create') {
        description = `Created new ${row.resource_type}`
      } else if (row.action === 'update') {
        description = `Updated ${row.resource_type}`
      } else if (row.action === 'delete') {
        description = `Deleted ${row.resource_type}`
      } else {
        description = `${row.action} ${row.resource_type}`
      }

      return {
        id: row.id,
        type: row.resource_type,
        action: row.action,
        description,
        timestamp: new Date(Number(row.created_at)).toISOString(),
        user: userName
      }
    })

    const html = renderRecentActivity(activities)
    return c.html(html)
  } catch (error) {
    console.error('Error fetching recent activity:', error)
    const html = renderRecentActivity([])
    return c.html(html)
  }
})

/**
 * GET /admin/api/metrics - Real-time metrics for analytics chart
 * Returns JSON with current requests per second from the metrics tracker
 */
router.get('/api/metrics', async (c) => {
  return c.json({
    requestsPerSecond: metricsTracker.getRequestsPerSecond(),
    totalRequests: metricsTracker.getTotalRequests(),
    averageRPS: Number(metricsTracker.getAverageRPS().toFixed(2)),
    timestamp: new Date().toISOString()
  })
})

/**
 * GET /admin/dashboard/system-status - System status HTML fragment (HTMX endpoint)
 */
router.get('/system-status', async (c) => {
  try {
    const html = `
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div class="relative group">
          <div class="absolute inset-0 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 dark:from-blue-500/10 dark:to-cyan-500/10 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          <div class="relative bg-zinc-50 dark:bg-zinc-800/50 rounded-xl p-5 border border-zinc-200/50 dark:border-zinc-700/50">
            <div class="flex items-center justify-between mb-3">
              <span class="text-sm font-medium text-zinc-600 dark:text-zinc-400">API Status</span>
              <svg class="w-6 h-6 text-lime-500" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
              </svg>
            </div>
            <p class="text-xs text-zinc-500 dark:text-zinc-400">Operational</p>
          </div>
        </div>

        <div class="relative group">
          <div class="absolute inset-0 bg-gradient-to-br from-purple-500/20 to-pink-500/20 dark:from-purple-500/10 dark:to-pink-500/10 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          <div class="relative bg-zinc-50 dark:bg-zinc-800/50 rounded-xl p-5 border border-zinc-200/50 dark:border-zinc-700/50">
            <div class="flex items-center justify-between mb-3">
              <span class="text-sm font-medium text-zinc-600 dark:text-zinc-400">Database</span>
              <svg class="w-6 h-6 text-lime-500" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
              </svg>
            </div>
            <p class="text-xs text-zinc-500 dark:text-zinc-400">Connected</p>
          </div>
        </div>

        <div class="relative group">
          <div class="absolute inset-0 bg-gradient-to-br from-amber-500/20 to-orange-500/20 dark:from-amber-500/10 dark:to-orange-500/10 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          <div class="relative bg-zinc-50 dark:bg-zinc-800/50 rounded-xl p-5 border border-zinc-200/50 dark:border-zinc-700/50">
            <div class="flex items-center justify-between mb-3">
              <span class="text-sm font-medium text-zinc-600 dark:text-zinc-400">R2 Storage</span>
              <svg class="w-6 h-6 text-lime-500" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
              </svg>
            </div>
            <p class="text-xs text-zinc-500 dark:text-zinc-400">Available</p>
          </div>
        </div>

        <div class="relative group">
          <div class="absolute inset-0 bg-gradient-to-br from-lime-500/20 to-emerald-500/20 dark:from-lime-500/10 dark:to-emerald-500/10 rounded-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
          <div class="relative bg-zinc-50 dark:bg-zinc-800/50 rounded-xl p-5 border border-zinc-200/50 dark:border-zinc-700/50">
            <div class="flex items-center justify-between mb-3">
              <span class="text-sm font-medium text-zinc-600 dark:text-zinc-400">KV Cache</span>
              <svg class="w-6 h-6 text-lime-500" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
              </svg>
            </div>
            <p class="text-xs text-zinc-500 dark:text-zinc-400">Ready</p>
          </div>
        </div>
      </div>
    `
    return c.html(html)
  } catch (error) {
    console.error('Error fetching system status:', error)
    return c.html('<div class="text-red-500">Failed to load system status</div>')
  }
})

export { router as adminDashboardRoutes }
