import { Hono } from 'hono'
import { requireAuth } from '../../../../middleware'
import { renderAdminLayoutCatalyst } from '../../../../templates/layouts/admin-layout-catalyst.template'
import type { Bindings, Variables } from '../../../../app'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminRoutes.use('*', requireAuth())

adminRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (user?.role !== 'admin') {
    return c.text('Access denied', 403)
  }
  return next()
})

// Analytics Dashboard
adminRoutes.get('/', async (c) => {
  const user = c.get('user')
  const db = c.env.DB

  // Query real metrics from system_logs
  let totalRequests = 0
  let uniqueIPs = 0
  let avgDuration = 0
  let errorCount = 0
  let topPages: Array<{ path: string; views: number }> = []
  let recentActivity: Array<{ url: string; method: string; status_code: number; duration: number; created_at: number }> = []

  try {
    const now = Math.floor(Date.now() / 1000)
    const dayAgo = now - 86400

    const [requestsResult, ipsResult, durationResult, errorsResult, pagesResult, activityResult] = await Promise.all([
      db.prepare('SELECT COUNT(*) as count FROM system_logs WHERE category = ? AND created_at > ?')
        .bind('api', dayAgo).first() as Promise<{ count: number } | null>,
      db.prepare('SELECT COUNT(DISTINCT ip_address) as count FROM system_logs WHERE category = ? AND created_at > ?')
        .bind('api', dayAgo).first() as Promise<{ count: number } | null>,
      db.prepare('SELECT AVG(duration) as avg FROM system_logs WHERE category = ? AND created_at > ? AND duration IS NOT NULL')
        .bind('api', dayAgo).first() as Promise<{ avg: number } | null>,
      db.prepare('SELECT COUNT(*) as count FROM system_logs WHERE level IN (?, ?) AND created_at > ?')
        .bind('error', 'fatal', dayAgo).first() as Promise<{ count: number } | null>,
      db.prepare('SELECT url, COUNT(*) as views FROM system_logs WHERE category = ? AND created_at > ? AND url IS NOT NULL GROUP BY url ORDER BY views DESC LIMIT 10')
        .bind('api', dayAgo).all(),
      db.prepare('SELECT url, method, status_code, duration, created_at FROM system_logs WHERE category = ? ORDER BY created_at DESC LIMIT 20')
        .bind('api').all(),
    ])

    totalRequests = requestsResult?.count || 0
    uniqueIPs = ipsResult?.count || 0
    avgDuration = Math.round(durationResult?.avg || 0)
    errorCount = errorsResult?.count || 0
    topPages = (pagesResult.results || []).map((r: any) => ({ path: r.url, views: r.views }))
    recentActivity = (activityResult.results || []) as any[]
  } catch {
    // Tables may not exist yet
  }

  const content = `
    <div class="space-y-8">
      <div>
        <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Analytics Dashboard</h1>
        <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Last 24 hours overview from system logs</p>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
          <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Total Requests</p>
          <p class="mt-2 text-3xl font-semibold text-zinc-950 dark:text-white">${totalRequests.toLocaleString()}</p>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
          <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Unique Visitors</p>
          <p class="mt-2 text-3xl font-semibold text-zinc-950 dark:text-white">${uniqueIPs.toLocaleString()}</p>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
          <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Avg Response Time</p>
          <p class="mt-2 text-3xl font-semibold text-zinc-950 dark:text-white">${avgDuration}ms</p>
        </div>
        <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
          <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Errors</p>
          <p class="mt-2 text-3xl font-semibold ${errorCount > 0 ? 'text-red-600 dark:text-red-400' : 'text-zinc-950 dark:text-white'}">${errorCount.toLocaleString()}</p>
        </div>
      </div>

      <!-- Top Pages -->
      <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
        <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
          <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Top Pages</h2>
        </div>
        <div class="divide-y divide-zinc-950/5 dark:divide-white/10">
          ${topPages.length > 0 ? topPages.map(p => `
            <div class="flex items-center justify-between px-6 py-3">
              <span class="text-sm text-zinc-700 dark:text-zinc-300 font-mono truncate">${escapeHtml(p.path)}</span>
              <span class="text-sm font-medium text-zinc-500 dark:text-zinc-400">${p.views}</span>
            </div>
          `).join('') : `
            <div class="px-6 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">
              No page views recorded yet. Analytics data will appear once requests are logged.
            </div>
          `}
        </div>
      </div>

      <!-- Recent Activity -->
      <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
        <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
          <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Recent Activity</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead class="bg-zinc-50 dark:bg-zinc-800/50">
              <tr>
                <th class="px-6 py-2 text-left font-medium text-zinc-500 dark:text-zinc-400">Path</th>
                <th class="px-6 py-2 text-left font-medium text-zinc-500 dark:text-zinc-400">Method</th>
                <th class="px-6 py-2 text-left font-medium text-zinc-500 dark:text-zinc-400">Status</th>
                <th class="px-6 py-2 text-left font-medium text-zinc-500 dark:text-zinc-400">Duration</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/5 dark:divide-white/10">
              ${recentActivity.length > 0 ? recentActivity.map(a => `
                <tr>
                  <td class="px-6 py-2 font-mono text-zinc-700 dark:text-zinc-300 truncate max-w-xs">${escapeHtml(a.url || '')}</td>
                  <td class="px-6 py-2"><span class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${a.method === 'GET' ? 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400'}">${a.method || ''}</span></td>
                  <td class="px-6 py-2"><span class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${(a.status_code || 0) >= 400 ? 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400' : 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-400'}">${a.status_code || ''}</span></td>
                  <td class="px-6 py-2 text-zinc-500 dark:text-zinc-400">${a.duration || 0}ms</td>
                </tr>
              `).join('') : `
                <tr>
                  <td colspan="4" class="px-6 py-8 text-center text-zinc-500 dark:text-zinc-400">No activity recorded yet.</td>
                </tr>
              `}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `

  return c.html(renderAdminLayoutCatalyst({
    title: 'Analytics',
    pageTitle: 'Analytics Dashboard',
    currentPath: '/admin/analytics',
    version: c.get('appVersion'),
    user: user ? {
      name: user.email.split('@')[0] || 'Admin',
      email: user.email,
      role: user.role
    } : undefined,
    content,
    dynamicMenuItems: c.get('pluginMenuItems')
  }))
})

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export { adminRoutes as analyticsAdminRoutes }
