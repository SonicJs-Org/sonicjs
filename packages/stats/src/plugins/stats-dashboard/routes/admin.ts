import { Hono } from 'hono'
import { requireAuth } from '@sonicjs-cms/core'
import { renderAdminLayoutCatalyst } from '@sonicjs-cms/core'
import type { Bindings, Variables } from '@sonicjs-cms/core'

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

adminRoutes.use('*', requireAuth())
adminRoutes.use('*', async (c, next) => {
  const user = c.get('user')
  if (user?.role !== 'admin') return c.text('Access denied', 403)
  return next()
})

interface WeekRow {
  week: string
  event_type: string
  count: number
}

interface TotalsRow {
  total_events: number
  unique_installs: number
}

adminRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  // Last 13 weeks of weekly counts grouped by event_type
  const [weeklyResult, totalsResult] = await Promise.all([
    db
      .prepare(
        `SELECT
           strftime('%Y-%W', datetime(created_at, 'unixepoch')) AS week,
           json_extract(data, '$.event_type') AS event_type,
           COUNT(*) AS count
         FROM documents
         WHERE type_id = 'events'
           AND tenant_id = 'default'
           AND is_published = 1
           AND deleted_at IS NULL
         GROUP BY week, event_type
         ORDER BY week DESC
         LIMIT 78`
      )
      .all(),
    db
      .prepare(
        `SELECT
           COUNT(*) AS total_events,
           COUNT(DISTINCT json_extract(data, '$.installation_id')) AS unique_installs
         FROM documents
         WHERE type_id = 'events'
           AND tenant_id = 'default'
           AND is_published = 1
           AND deleted_at IS NULL`
      )
      .first() as Promise<TotalsRow | null>,
  ])

  const rows = (weeklyResult.results ?? []) as unknown as WeekRow[]
  const totals = totalsResult ?? { total_events: 0, unique_installs: 0 }

  // Build sorted list of unique weeks (ascending)
  const weekSet = new Set(rows.map((r) => r.week))
  const weeks = Array.from(weekSet).sort()

  // Index by week → event_type → count
  const byWeek = new Map<string, Map<string, number>>()
  for (const row of rows) {
    if (!byWeek.has(row.week)) byWeek.set(row.week, new Map())
    byWeek.get(row.week)!.set(row.event_type, row.count)
  }

  // Compute overall completion rate
  let totalStarted = 0
  let totalCompleted = 0
  for (const [, types] of byWeek) {
    totalStarted += types.get('installation_started') ?? 0
    totalCompleted += types.get('installation_completed') ?? 0
  }
  const completionRate = totalStarted > 0 ? Math.round((totalCompleted / totalStarted) * 100) : 0

  // Max value across all weeks for bar scaling
  const maxWeekStarted = Math.max(1, ...weeks.map((w) => byWeek.get(w)?.get('installation_started') ?? 0))

  const weekRows = weeks
    .slice()
    .reverse()
    .map((week) => {
      const types = byWeek.get(week) ?? new Map()
      const started = types.get('installation_started') ?? 0
      const completed = types.get('installation_completed') ?? 0
      const failed = types.get('installation_failed') ?? 0
      const rate = started > 0 ? Math.round((completed / started) * 100) : 0
      const barPct = Math.round((started / maxWeekStarted) * 100)
      return { week, started, completed, failed, rate, barPct }
    })

  const content = `
<div class="space-y-8">
  <div>
    <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Installation Stats</h1>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Weekly install funnel — started vs completed</p>
  </div>

  <!-- Summary cards -->
  <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
    <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Total Events</p>
      <p class="mt-2 text-3xl font-semibold text-zinc-950 dark:text-white">${totals.total_events.toLocaleString()}</p>
    </div>
    <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Unique Installations</p>
      <p class="mt-2 text-3xl font-semibold text-zinc-950 dark:text-white">${totals.unique_installs.toLocaleString()}</p>
    </div>
    <div class="rounded-lg bg-white dark:bg-zinc-800 p-6 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Overall Completion Rate</p>
      <p class="mt-2 text-3xl font-semibold ${completionRate >= 50 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}">${completionRate}%</p>
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">${totalStarted.toLocaleString()} started → ${totalCompleted.toLocaleString()} completed</p>
    </div>
  </div>

  <!-- Weekly table -->
  <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
    <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
      <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Weekly Breakdown</h2>
    </div>
    ${weekRows.length === 0 ? `
      <div class="px-6 py-12 text-center text-sm text-zinc-500 dark:text-zinc-400">No event data yet.</div>
    ` : `
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="bg-zinc-50 dark:bg-zinc-800/50 text-xs uppercase tracking-wide">
          <tr>
            <th class="px-6 py-3 text-left font-medium text-zinc-500 dark:text-zinc-400">Week</th>
            <th class="px-6 py-3 text-right font-medium text-zinc-500 dark:text-zinc-400">Started</th>
            <th class="px-6 py-3 text-right font-medium text-zinc-500 dark:text-zinc-400">Completed</th>
            <th class="px-6 py-3 text-right font-medium text-zinc-500 dark:text-zinc-400">Failed</th>
            <th class="px-6 py-3 text-right font-medium text-zinc-500 dark:text-zinc-400">Completion %</th>
            <th class="px-6 py-3 text-left font-medium text-zinc-500 dark:text-zinc-400 w-48">Volume</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${weekRows
            .map(
              (r) => `
          <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
            <td class="px-6 py-3 font-mono text-zinc-700 dark:text-zinc-300">${r.week}</td>
            <td class="px-6 py-3 text-right text-zinc-700 dark:text-zinc-300">${r.started.toLocaleString()}</td>
            <td class="px-6 py-3 text-right text-emerald-600 dark:text-emerald-400 font-medium">${r.completed.toLocaleString()}</td>
            <td class="px-6 py-3 text-right ${r.failed > 0 ? 'text-red-600 dark:text-red-400' : 'text-zinc-400 dark:text-zinc-600'}">${r.failed.toLocaleString()}</td>
            <td class="px-6 py-3 text-right">
              <span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium
                ${r.rate >= 70 ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' :
                  r.rate >= 40 ? 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' :
                  'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400'}">
                ${r.rate}%
              </span>
            </td>
            <td class="px-6 py-3">
              <div class="flex items-center gap-2">
                <div class="flex-1 h-2 rounded-full bg-zinc-100 dark:bg-zinc-700 overflow-hidden">
                  <div class="h-full rounded-full bg-indigo-500 dark:bg-indigo-400" style="width:${r.barPct}%"></div>
                </div>
              </div>
            </td>
          </tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>
    `}
  </div>
</div>`

  return c.html(
    renderAdminLayoutCatalyst({
      title: 'Dashboard',
      pageTitle: 'Stats Dashboard',
      currentPath: '/admin/dashboard',
      version: c.get('appVersion'),
      user: user
        ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role }
        : undefined,
      content,
      dynamicMenuItems: c.get('pluginMenuItems'),
    })
  )
})

export { adminRoutes as statsDashboardAdminRoutes }
