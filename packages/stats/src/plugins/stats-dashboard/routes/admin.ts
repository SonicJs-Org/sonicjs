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

// ── Helpers ─────────────────────────────────────────────────────────────────

const EVENTS_WHERE = `type_id = 'events' AND tenant_id = 'default' AND is_published = 1 AND deleted_at IS NULL`
const INSTALLS_WHERE = `type_id = 'installs' AND tenant_id = 'default' AND is_published = 1 AND deleted_at IS NULL`

/** Escape text rendered into HTML table cells. */
function esc(v: unknown): string {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

/** Serialize data for embedding in an inline <script> — neutralizes </script> + quotes. */
function jsonForScript(v: unknown): string {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
}

interface Row { [k: string]: any }
const rowsOf = (r: { results?: unknown[] } | null): Row[] => (r?.results ?? []) as Row[]

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
function fmtWeekDate(iso: string): string {
  const m = iso?.match(/^(\d{4})-(\d{2})-(\d{2})$/)
  if (!m) return iso
  return `${MONTHS[parseInt(m[2], 10) - 1]} ${parseInt(m[3], 10)}`
}

// Shared chart palette
const PALETTE = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16', '#f97316', '#14b8a6', '#a855f7', '#64748b']

adminRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  const [
    weeklyFunnelR,
    eventTotalsR,
    installTotalsR,
    newInstallsR,
    lifespanR,
    osR,
    nodeR,
    templateR,
    installFailR,
    runtimeErrR,
    snapshotCollectionsR,
    snapshotPluginsR,
    snapshotFieldTypesR,
    snapshotVersionR,
    snapshotDocVolumeR,
    snapshotCountR,
    countryR,
    demoLoginDailyR,
    demoLoginTotalR,
  ] = await Promise.all([
    // 1. Weekly funnel: started/completed/failed counts per week (keyed to Monday date)
    db.prepare(
      `SELECT date(datetime(created_at, 'unixepoch'), '-' || CAST((strftime('%w', datetime(created_at, 'unixepoch')) + 6) % 7 AS TEXT) || ' days') AS week,
              json_extract(data, '$.event_type') AS event_type,
              COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE}
         AND json_extract(data,'$.event_type') IN ('installation_started','installation_completed','installation_failed')
       GROUP BY week, event_type ORDER BY week DESC LIMIT 156`
    ).all(),
    // 2. Event totals
    db.prepare(
      `SELECT COUNT(*) AS total_events,
              COUNT(DISTINCT json_extract(data,'$.installation_id')) AS unique_installs,
              SUM(CASE WHEN json_extract(data,'$.event_type')='installation_failed' THEN 1 ELSE 0 END) AS failures,
              SUM(CASE WHEN json_extract(data,'$.event_type')='error_occurred' THEN 1 ELSE 0 END) AS runtime_errors
       FROM documents WHERE ${EVENTS_WHERE}`
    ).first(),
    // 3. Install totals + active/churned (last_seen recency) + multi-session
    db.prepare(
      `SELECT COUNT(*) AS total_installs,
              SUM(CASE WHEN julianday('now') - julianday(json_extract(data,'$.last_seen')) <= 30 THEN 1 ELSE 0 END) AS active_30d,
              SUM(CASE WHEN julianday('now') - julianday(json_extract(data,'$.last_seen')) <= 7 THEN 1 ELSE 0 END) AS active_7d,
              SUM(CASE WHEN json_extract(data,'$.last_seen') > json_extract(data,'$.first_seen') THEN 1 ELSE 0 END) AS multi_session
       FROM documents WHERE ${INSTALLS_WHERE}`
    ).first(),
    // 4. New installs per week (cohort by first_seen, keyed to Monday date)
    db.prepare(
      `SELECT date(json_extract(data,'$.first_seen'), '-' || CAST((strftime('%w', json_extract(data,'$.first_seen')) + 6) % 7 AS TEXT) || ' days') AS week, COUNT(*) AS count
       FROM documents WHERE ${INSTALLS_WHERE} AND json_extract(data,'$.first_seen') IS NOT NULL
       GROUP BY week ORDER BY week ASC`
    ).all(),
    // 5. Lifespan distribution (engagement window)
    db.prepare(
      `SELECT bucket, COUNT(*) AS count FROM (
         SELECT CASE
           WHEN d IS NULL THEN 'unknown'
           WHEN d < 0.0014 THEN 'instant'
           WHEN d < 1 THEN 'under_1d'
           WHEN d < 7 THEN '1_7d'
           WHEN d < 30 THEN '7_30d'
           ELSE 'over_30d' END AS bucket
         FROM (SELECT julianday(json_extract(data,'$.last_seen')) - julianday(json_extract(data,'$.first_seen')) AS d
               FROM documents WHERE ${INSTALLS_WHERE})
       ) GROUP BY bucket`
    ).all(),
    // 6. OS breakdown (installs)
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.os'),'unknown') AS os, COUNT(*) AS count
       FROM documents WHERE ${INSTALLS_WHERE} GROUP BY os ORDER BY count DESC`
    ).all(),
    // 7. Node version (installs, top 12)
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.node_version'),'unknown') AS v, COUNT(*) AS count
       FROM documents WHERE ${INSTALLS_WHERE} GROUP BY v ORDER BY count DESC LIMIT 12`
    ).all(),
    // 8. Template (installation_started events)
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.properties.template'),'unknown') AS t, COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='installation_started'
       GROUP BY t ORDER BY count DESC`
    ).all(),
    // 9. Install failures by errorType + step + version
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.properties.errorType'), json_extract(data,'$.error_code'),'unknown') AS err,
              COALESCE(json_extract(data,'$.properties.step'),'-') AS step,
              COALESCE(json_extract(data,'$.properties.version'),'-') AS version,
              COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='installation_failed'
       GROUP BY err, step, version ORDER BY count DESC LIMIT 25`
    ).all(),
    // 10. Runtime errors (error_occurred) by errorType + version
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.properties.errorType'),'unknown') AS err,
              COALESCE(json_extract(data,'$.properties.version'),'-') AS version,
              COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='error_occurred'
       GROUP BY err, version ORDER BY count DESC LIMIT 25`
    ).all(),
    // 11. Top collections from project_snapshot — latest snapshot per installation to avoid boot-count inflation
    db.prepare(
      `WITH latest AS (
         SELECT json_extract(data,'$.properties.installation_id') AS installation_id,
                json_extract(data,'$.properties.collection_counts') AS counts_json
         FROM documents
         WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='project_snapshot'
         GROUP BY json_extract(data,'$.properties.installation_id')
         HAVING created_at = MAX(created_at)
       )
       SELECT key AS collection,
              SUM(CAST(value AS INTEGER)) AS total_docs,
              COUNT(DISTINCT installation_id) AS installations
       FROM latest, json_each(json(counts_json))
       GROUP BY key ORDER BY installations DESC, total_docs DESC`
    ).all(),
    // 12. Top plugins from project_snapshot — latest snapshot per installation
    db.prepare(
      `WITH latest AS (
         SELECT json_extract(data,'$.properties.installation_id') AS installation_id,
                json_extract(data,'$.properties.active_plugins') AS plugins_json
         FROM documents
         WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='project_snapshot'
         GROUP BY json_extract(data,'$.properties.installation_id')
         HAVING created_at = MAX(created_at)
       )
       SELECT value AS plugin, COUNT(DISTINCT installation_id) AS installations
       FROM latest, json_each(json(plugins_json))
       GROUP BY value ORDER BY installations DESC LIMIT 20`
    ).all(),
    // 13. Field type histogram aggregated across all snapshots
    db.prepare(
      `SELECT key AS field_type, SUM(CAST(value AS INTEGER)) AS total_fields
       FROM documents, json_each(json(json_extract(data,'$.properties.field_type_histogram')))
       WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='project_snapshot'
       GROUP BY key ORDER BY total_fields DESC`
    ).all(),
    // 14. SonicJS version distribution across reporting installations
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.properties.sonicjs_version'),'unknown') AS version,
              COUNT(DISTINCT json_extract(data,'$.properties.installation_id')) AS installations
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='project_snapshot'
       GROUP BY version ORDER BY installations DESC LIMIT 15`
    ).all(),
    // 15. Doc volume distribution (latest snapshot per installation, bucketed)
    db.prepare(
      `SELECT bucket, COUNT(*) AS count FROM (
         SELECT CASE
           WHEN n IS NULL OR n = 0 THEN 'Empty'
           WHEN n <= 10 THEN '1–10'
           WHEN n <= 100 THEN '11–100'
           WHEN n <= 1000 THEN '101–1k'
           ELSE '1k+' END AS bucket
         FROM (
           SELECT CAST(json_extract(data,'$.properties.doc_total') AS INTEGER) AS n
           FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='project_snapshot'
           GROUP BY json_extract(data,'$.properties.installation_id')
           HAVING created_at = MAX(created_at)
         )
       ) GROUP BY bucket ORDER BY CASE bucket WHEN 'Empty' THEN 1 WHEN '1–10' THEN 2 WHEN '11–100' THEN 3 WHEN '101–1k' THEN 4 ELSE 5 END`
    ).all(),
    // 16. Distinct installations reporting via project_snapshot
    db.prepare(
      `SELECT COUNT(DISTINCT json_extract(data,'$.properties.installation_id')) AS count
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='project_snapshot'`
    ).first(),
    // 17. Country distribution (CF-IPCountry) across all events
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.country'),'unknown') AS country, COUNT(DISTINCT json_extract(data,'$.installation_id')) AS installs
       FROM documents WHERE ${EVENTS_WHERE}
       GROUP BY country ORDER BY installs DESC LIMIT 30`
    ).all(),
    // 18. Daily demo login counts (last 30 days)
    db.prepare(
      `SELECT date(datetime(created_at, 'unixepoch')) AS day, COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE}
         AND json_extract(data,'$.event_type') = 'demo_login'
         AND created_at >= unixepoch('now', '-30 days')
       GROUP BY day ORDER BY day ASC`
    ).all(),
    // 19. Total demo logins all time
    db.prepare(
      `SELECT COUNT(*) AS total FROM documents WHERE ${EVENTS_WHERE}
         AND json_extract(data,'$.event_type') = 'demo_login'`
    ).first(),
  ])

  // ── Funnel aggregation ──────────────────────────────────────────────────
  const funnelRows = rowsOf(weeklyFunnelR) as { week: string; event_type: string; count: number }[]
  const byWeek = new Map<string, Map<string, number>>()
  for (const r of funnelRows) {
    if (!byWeek.has(r.week)) byWeek.set(r.week, new Map())
    byWeek.get(r.week)!.set(r.event_type, r.count)
  }
  const weeks = Array.from(byWeek.keys()).sort()
  let totStarted = 0, totCompleted = 0, totFailed = 0
  for (const [, t] of byWeek) {
    totStarted += t.get('installation_started') ?? 0
    totCompleted += t.get('installation_completed') ?? 0
    totFailed += t.get('installation_failed') ?? 0
  }
  const completionRate = totStarted > 0 ? Math.round((totCompleted / totStarted) * 100) : 0
  // Last 16 weeks for the funnel chart + table (chronological)
  const recentWeeks = weeks.slice(-16)
  const funnelStarted = recentWeeks.map((w) => byWeek.get(w)?.get('installation_started') ?? 0)
  const funnelCompleted = recentWeeks.map((w) => byWeek.get(w)?.get('installation_completed') ?? 0)
  const funnelFailed = recentWeeks.map((w) => byWeek.get(w)?.get('installation_failed') ?? 0)
  const tableWeeks = recentWeeks.slice().reverse().map((w) => {
    const t = byWeek.get(w)!
    const s = t.get('installation_started') ?? 0
    const comp = t.get('installation_completed') ?? 0
    const f = t.get('installation_failed') ?? 0
    return { week: w, started: s, completed: comp, failed: f, rate: s > 0 ? Math.round((comp / s) * 100) : 0, avgPerDay: (comp / 7).toFixed(1) }
  })

  // ── Totals / KPIs ──────────────────────────────────────────────────────
  const et = (eventTotalsR ?? {}) as Row
  const it = (installTotalsR ?? {}) as Row
  const totalInstalls = Number(it.total_installs ?? 0)
  const active30 = Number(it.active_30d ?? 0)
  const active7 = Number(it.active_7d ?? 0)
  const multiSession = Number(it.multi_session ?? 0)
  const churned = totalInstalls - active30
  const churnRate = totalInstalls > 0 ? Math.round((churned / totalInstalls) * 100) : 0
  const failures = Number(et.failures ?? 0)
  const runtimeErrors = Number(et.runtime_errors ?? 0)

  // ── New installs trend (last 26 weeks) ──────────────────────────────────
  const newInstallRows = rowsOf(newInstallsR) as { week: string; count: number }[]
  const trend = newInstallRows.slice(-26)
  const trendLabels = trend.map((r) => r.week)
  const trendCounts = trend.map((r) => r.count)
  // cumulative
  let run = 0
  const trendCumulative = trend.map((r) => (run += r.count))

  // ── Lifespan ────────────────────────────────────────────────────────────
  const lifespanMap = new Map(rowsOf(lifespanR).map((r) => [r.bucket as string, Number(r.count)]))
  const lifeOrder = ['instant', 'under_1d', '1_7d', '7_30d', 'over_30d', 'unknown']
  const lifeLabels: Record<string, string> = { instant: 'Single ping', under_1d: '< 1 day', '1_7d': '1–7 days', '7_30d': '7–30 days', over_30d: '30+ days', unknown: 'Unknown' }
  const lifespanData = lifeOrder.map((k) => lifespanMap.get(k) ?? 0)

  // ── Breakdowns ──────────────────────────────────────────────────────────
  const osRows = rowsOf(osR) as { os: string; count: number }[]
  const nodeRows = (rowsOf(nodeR) as { v: string; count: number }[]).map((r) => ({
    v: r.v === 'unknown' ? 'unknown' : String(r.v).replace(/^v/, 'v'),
    count: Number(r.count),
  }))
  const templateRows = rowsOf(templateR) as { t: string; count: number }[]
  const installFailRows = rowsOf(installFailR) as { err: string; step: string; version: string; count: number }[]
  const runtimeErrRows = rowsOf(runtimeErrR) as { err: string; version: string; count: number }[]

  // ── Project snapshot breakdowns ─────────────────────────────────────────
  const snapshotCollectionRows = rowsOf(snapshotCollectionsR) as { collection: string; total_docs: number; installations: number }[]
  const snapshotPluginRows = rowsOf(snapshotPluginsR) as { plugin: string; installations: number }[]
  const snapshotFieldTypeRows = rowsOf(snapshotFieldTypesR) as { field_type: string; total_fields: number }[]
  const snapshotVersionRows = rowsOf(snapshotVersionR) as { version: string; installations: number }[]
  const snapshotDocVolumeRows = rowsOf(snapshotDocVolumeR) as { bucket: string; count: number }[]
  const snapshotInstallations = Number((snapshotCountR as Row | null)?.count ?? 0)
  const hasSnapshotData = snapshotInstallations > 0

  // ── Country breakdown ────────────────────────────────────────────────────
  const countryRows = (rowsOf(countryR) as { country: string; installs: number }[]).filter((r) => r.country !== 'unknown')

  // ── Demo logins ──────────────────────────────────────────────────────────
  const demoLoginDailyRows = rowsOf(demoLoginDailyR) as { day: string; count: number }[]
  const demoLoginTotal = Number((demoLoginTotalR as Row | null)?.total ?? 0)
  const demoLogin30d = demoLoginDailyRows.reduce((s, r) => s + Number(r.count), 0)

  // ── Chart datasets (serialized) ─────────────────────────────────────────
  const charts = {
    trend: { labels: trendLabels.map(fmtWeekDate), weekly: trendCounts, cumulative: trendCumulative },
    funnel: { labels: recentWeeks.map(fmtWeekDate), started: funnelStarted, completed: funnelCompleted, failed: funnelFailed },
    churn: { active7, active30minus7: Math.max(0, active30 - active7), churned },
    lifespan: { labels: lifeOrder.map((k) => lifeLabels[k]), data: lifespanData },
    os: { labels: osRows.map((r) => r.os), data: osRows.map((r) => Number(r.count)) },
    node: { labels: nodeRows.map((r) => r.v), data: nodeRows.map((r) => r.count) },
    template: { labels: templateRows.map((r) => r.t), data: templateRows.map((r) => Number(r.count)) },
    collections: { labels: snapshotCollectionRows.slice(0, 20).map((r) => r.collection), docs: snapshotCollectionRows.slice(0, 20).map((r) => Number(r.total_docs)), installs: snapshotCollectionRows.slice(0, 20).map((r) => Number(r.installations)) },
    plugins: { labels: snapshotPluginRows.map((r) => r.plugin), data: snapshotPluginRows.map((r) => Number(r.installations)) },
    fieldTypes: { labels: snapshotFieldTypeRows.map((r) => r.field_type), data: snapshotFieldTypeRows.map((r) => Number(r.total_fields)) },
    versions: { labels: snapshotVersionRows.map((r) => r.version), data: snapshotVersionRows.map((r) => Number(r.installations)) },
    docVolume: { labels: snapshotDocVolumeRows.map((r) => r.bucket), data: snapshotDocVolumeRows.map((r) => Number(r.count)) },
    country: { labels: countryRows.map((r) => r.country), data: countryRows.map((r) => Number(r.installs)) },
    demoLogin: { labels: demoLoginDailyRows.map((r) => r.day), data: demoLoginDailyRows.map((r) => Number(r.count)) },
  }

  // ── KPI card markup ─────────────────────────────────────────────────────
  const kpi = (label: string, value: string, sub: string, color = 'text-zinc-950 dark:text-white') => `
    <div class="rounded-lg bg-white dark:bg-zinc-800 p-5 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <p class="text-xs font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400">${label}</p>
      <p class="mt-2 text-2xl font-semibold ${color}">${value}</p>
      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">${sub}</p>
    </div>`

  const card = (title: string, sub: string, body: string) => `
    <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">${title}</h2>
        ${sub ? `<p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">${sub}</p>` : ''}
      </div>
      <div class="p-6">${body}</div>
    </div>`

  const errTable = (rows: { err: string; sub: string; count: number }[], subHead: string, empty: string) =>
    rows.length === 0
      ? `<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">${empty}</div>`
      : `<div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            <tr><th class="py-2 text-left font-medium">Error</th><th class="py-2 text-left font-medium">${subHead}</th><th class="py-2 text-right font-medium">Count</th></tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${rows.map((r) => `<tr>
            <td class="py-2 pr-4 text-zinc-700 dark:text-zinc-300">${esc(r.err)}</td>
            <td class="py-2 pr-4 font-mono text-xs text-zinc-500 dark:text-zinc-400">${esc(r.sub)}</td>
            <td class="py-2 text-right font-semibold text-zinc-900 dark:text-white">${r.count.toLocaleString()}</td>
          </tr>`).join('')}
          </tbody></table></div>`

  const content = `
<div class="space-y-8">
  <div>
    <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Stats &amp; Usage</h1>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Installation growth, retention, environment, and errors</p>
  </div>

  <!-- KPI row -->
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
    ${kpi('Total Installs', totalInstalls.toLocaleString(), `${Number(et.unique_installs ?? 0).toLocaleString()} unique IDs`)}
    ${kpi('Active (30d)', active30.toLocaleString(), `${active7.toLocaleString()} in last 7d`, 'text-emerald-600 dark:text-emerald-400')}
    ${kpi('Churned', churned.toLocaleString(), `${churnRate}% inactive >30d`, 'text-amber-600 dark:text-amber-400')}
    ${kpi('Completion', completionRate + '%', `${totCompleted.toLocaleString()} / ${totStarted.toLocaleString()} started`, completionRate >= 50 ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400')}
    ${kpi('Install Failures', failures.toLocaleString(), `${totStarted > 0 ? Math.round((totFailed / totStarted) * 100) : 0}% of started`, 'text-red-600 dark:text-red-400')}
    ${kpi('Runtime Errors', runtimeErrors.toLocaleString(), 'error_occurred events', 'text-red-600 dark:text-red-400')}
  </div>

  <!-- Growth + funnel -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('Installation Growth', 'New installs per week + cumulative', '<canvas id="chartTrend" height="240"></canvas>')}
    ${card('Install Funnel', 'Started vs completed vs failed (last 16 weeks)', '<canvas id="chartFunnel" height="240"></canvas>')}
  </div>

  <!-- Retention / churn -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('Retention', `${active30.toLocaleString()} active / ${churned.toLocaleString()} churned · ${multiSession.toLocaleString()} multi-session`, '<canvas id="chartChurn" height="240"></canvas>')}
    ${card('Engagement Lifespan', 'Time between first and last activity', '<canvas id="chartLifespan" height="240"></canvas>')}
  </div>

  <!-- Environment -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
    ${card('Operating System', '', '<canvas id="chartOs" height="220"></canvas>')}
    ${card('Template', '', '<canvas id="chartTemplate" height="220"></canvas>')}
    ${card('Node Version', 'Top 12', '<canvas id="chartNode" height="220"></canvas>')}
  </div>

  <!-- Geography -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('Country', 'Unique installs by country (CF-IPCountry, no PII)', countryRows.length > 0 ? '<canvas id="chartCountry" height="280"></canvas>' : '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No country data yet — will populate for new events.</div>')}
  </div>

  <!-- Demo Site Logins -->
  <div>
    <h2 class="text-xl font-semibold text-zinc-950 dark:text-white">Demo Site Logins</h2>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Logins with demo credentials (admin@sonicjs.com) on the live demo site</p>
  </div>
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
    ${kpi('Total Logins', demoLoginTotal.toLocaleString(), 'all time', 'text-indigo-600 dark:text-indigo-400')}
    ${kpi('Last 30 Days', demoLogin30d.toLocaleString(), 'daily breakdown below', 'text-emerald-600 dark:text-emerald-400')}
  </div>
  <div class="grid grid-cols-1 gap-6">
    ${card('Daily Demo Logins', 'Last 30 days', demoLoginDailyRows.length > 0 ? '<canvas id="chartDemoLogin" height="200"></canvas>' : '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No demo login events yet.</div>')}
  </div>

  <!-- Weekly table -->
  ${card('Weekly Breakdown', 'Detailed funnel by week', tableWeeks.length === 0 ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No data yet.</div>' : `
    <div class="overflow-x-auto"><table class="w-full text-sm">
      <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
        <tr>
          <th class="py-2 text-left font-medium">Week</th>
          <th class="py-2 text-right font-medium">Started</th>
          <th class="py-2 text-right font-medium">Completed</th>
          <th class="py-2 text-right font-medium">Avg/day</th>
          <th class="py-2 text-right font-medium">Failed</th>
          <th class="py-2 text-right font-medium">Completion %</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
      ${tableWeeks.map((r) => `<tr>
        <td class="py-2 font-mono text-zinc-700 dark:text-zinc-300">${fmtWeekDate(r.week)}</td>
        <td class="py-2 text-right text-zinc-700 dark:text-zinc-300">${r.started.toLocaleString()}</td>
        <td class="py-2 text-right text-emerald-600 dark:text-emerald-400 font-medium">${r.completed.toLocaleString()}</td>
        <td class="py-2 text-right text-zinc-500 dark:text-zinc-400">${r.avgPerDay}</td>
        <td class="py-2 text-right ${r.failed > 0 ? 'text-red-600 dark:text-red-400' : 'text-zinc-400'}">${r.failed.toLocaleString()}</td>
        <td class="py-2 text-right"><span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${r.rate >= 70 ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' : r.rate >= 40 ? 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' : 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400'}">${r.rate}%</span></td>
      </tr>`).join('')}
      </tbody></table></div>`)}

  <!-- Errors -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('Install Failures', 'installation_failed grouped by error + step + version', installFailRows.length === 0
      ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No failures recorded.</div>'
      : `<div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            <tr><th class="py-2 text-left font-medium">Error</th><th class="py-2 text-left font-medium">Step</th><th class="py-2 text-left font-medium">Version</th><th class="py-2 text-right font-medium">Count</th></tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${installFailRows.map((r) => `<tr>
            <td class="py-2 pr-4 text-zinc-700 dark:text-zinc-300 max-w-xs break-words">${esc(r.err)}</td>
            <td class="py-2 pr-4 font-mono text-xs text-zinc-500 dark:text-zinc-400">${esc(r.step)}</td>
            <td class="py-2 pr-4 font-mono text-xs text-zinc-500 dark:text-zinc-400">${esc(r.version)}</td>
            <td class="py-2 text-right font-semibold text-red-600 dark:text-red-400">${Number(r.count).toLocaleString()}</td>
          </tr>`).join('')}
          </tbody></table></div>`)}
    ${card('Runtime Errors', 'error_occurred grouped by error + version', errTable(runtimeErrRows.map((r) => ({ err: r.err, sub: r.version, count: Number(r.count) })), 'Version', 'No runtime errors recorded.'))}
  </div>

  <!-- What people build (project_snapshot data) -->
  <div class="flex items-center justify-between">
    <div>
      <h2 class="text-xl font-semibold text-zinc-950 dark:text-white">What People Build</h2>
      <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">From <code>project_snapshot</code> heartbeats — emitted on every SonicJS cold start (v3.0.0-beta.8+)</p>
    </div>
    <div class="text-right">
      <p class="text-2xl font-semibold text-indigo-600 dark:text-indigo-400">${snapshotInstallations.toLocaleString()}</p>
      <p class="text-xs text-zinc-500 dark:text-zinc-400">reporting installations</p>
    </div>
  </div>

  ${!hasSnapshotData ? `
  <div class="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-4 text-sm text-amber-800 dark:text-amber-300">
    Waiting for first <code>project_snapshot</code> — charts will populate once installations running v3.0.0-beta.8+ report in.
  </div>` : ''}

  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('Top Collections', `Total docs across all ${snapshotInstallations} reporting installations`, hasSnapshotData ? '<canvas id="chartCollections" height="300"></canvas>' : '<div class="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">No data yet</div>')}
    ${card('Active Plugins', `Plugin adoption rate across ${snapshotInstallations} installations`, hasSnapshotData ? '<canvas id="chartPlugins" height="300"></canvas>' : '<div class="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">No data yet</div>')}
  </div>

  <div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
    ${card('Field Types Used', 'Aggregate field type count across all schemas', hasSnapshotData ? '<canvas id="chartFieldTypes" height="240"></canvas>' : '<div class="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">No data yet</div>')}
    ${card('SonicJS Versions', 'Which version are installations running', hasSnapshotData ? '<canvas id="chartVersions" height="240"></canvas>' : '<div class="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">No data yet</div>')}
    ${card('Content Volume', 'Distribution of total doc counts per installation', hasSnapshotData ? '<canvas id="chartDocVolume" height="240"></canvas>' : '<div class="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">No data yet</div>')}
  </div>

  ${hasSnapshotData ? (() => {
    const customCollections = snapshotCollectionRows.filter((r) => Number(r.installations) === 1)
    const sharedCollections = snapshotCollectionRows.filter((r) => Number(r.installations) > 1)
    return `
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('All Collections', `${snapshotCollectionRows.length} unique collections across ${snapshotInstallations} reporting installations`, `
      <div class="overflow-x-auto max-h-96 overflow-y-auto"><table class="w-full text-sm">
        <thead class="sticky top-0 bg-white dark:bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          <tr>
            <th class="py-2 text-left font-medium">Collection</th>
            <th class="py-2 text-right font-medium">Installs</th>
            <th class="py-2 text-right font-medium">Total Docs</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
        ${sharedCollections.map((r) => `<tr>
          <td class="py-1.5 font-mono text-sm text-zinc-700 dark:text-zinc-300">${esc(r.collection)}</td>
          <td class="py-1.5 text-right font-semibold text-indigo-600 dark:text-indigo-400">${Number(r.installations).toLocaleString()}</td>
          <td class="py-1.5 text-right text-zinc-500 dark:text-zinc-400">${Number(r.total_docs).toLocaleString()}</td>
        </tr>`).join('')}
        </tbody>
      </table></div>
    `)}
    ${card(`Custom Collections <span class="ml-2 text-xs font-normal text-zinc-400">${customCollections.length} unique</span>`, 'Collections seen in exactly one installation — user-defined', customCollections.length === 0
      ? '<div class="py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">None yet</div>'
      : `<div class="overflow-x-auto max-h-96 overflow-y-auto"><table class="w-full text-sm">
        <thead class="sticky top-0 bg-white dark:bg-zinc-900 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          <tr>
            <th class="py-2 text-left font-medium">Collection</th>
            <th class="py-2 text-right font-medium">Docs</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
        ${customCollections.sort((a, b) => Number(b.total_docs) - Number(a.total_docs)).map((r) => `<tr>
          <td class="py-1.5 font-mono text-sm text-emerald-700 dark:text-emerald-400">${esc(r.collection)}</td>
          <td class="py-1.5 text-right text-zinc-500 dark:text-zinc-400">${Number(r.total_docs).toLocaleString()}</td>
        </tr>`).join('')}
        </tbody>
      </table></div>`
    )}
  </div>`
  })() : ''}
</div>

<script>
(function () {
  if (typeof Chart === 'undefined') return
  var D = ${jsonForScript(charts)};
  var P = ${jsonForScript(PALETTE)};
  var dark = document.documentElement.classList.contains('dark');
  var grid = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
  var tick = dark ? '#a1a1aa' : '#52525b';
  Chart.defaults.color = tick;
  Chart.defaults.font.size = 11;
  var noGridX = { grid: { display: false }, ticks: { color: tick, maxRotation: 60, minRotation: 0 } };
  var gridY = { grid: { color: grid }, ticks: { color: tick }, beginAtZero: true };

  function line(id, labels, datasets) {
    var el = document.getElementById(id); if (!el) return;
    new Chart(el, { type: 'line', data: { labels: labels, datasets: datasets },
      options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
        plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } },
        scales: { x: noGridX, y: gridY } } });
  }
  function bar(id, labels, datasets, opts) {
    var el = document.getElementById(id); if (!el) return;
    opts = opts || {};
    new Chart(el, { type: 'bar', data: { labels: labels, datasets: datasets },
      options: { responsive: true, maintainAspectRatio: false, indexAxis: opts.horizontal ? 'y' : 'x',
        plugins: { legend: { display: opts.legend !== false, position: 'top', labels: { boxWidth: 12 } } },
        scales: opts.horizontal ? { x: gridY, y: { grid: { display: false }, ticks: { color: tick } } }
                                 : { x: noGridX, y: gridY }, stacked: opts.stacked } });
  }
  function doughnut(id, labels, data) {
    var el = document.getElementById(id); if (!el) return;
    new Chart(el, { type: 'doughnut', data: { labels: labels, datasets: [{ data: data, backgroundColor: P, borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, cutout: '60%',
        plugins: { legend: { position: 'right', labels: { boxWidth: 12 } } } } });
  }

  // Growth
  line('chartTrend', D.trend.labels, [
    { label: 'New / week', data: D.trend.weekly, borderColor: P[0], backgroundColor: 'rgba(99,102,241,0.15)', fill: true, tension: 0.3, yAxisID: 'y' },
    { label: 'Cumulative', data: D.trend.cumulative, borderColor: P[1], backgroundColor: 'transparent', tension: 0.3, yAxisID: 'y1', borderDash: [4,3] }
  ]);
  // add second axis after creation? simpler: rebuild with y1 — patch options:
  (function(){ var ch = Chart.getChart('chartTrend'); if (ch){ ch.options.scales.y1 = { position:'right', grid:{display:false}, ticks:{color:tick}, beginAtZero:true }; ch.update(); } })();

  // Funnel (stacked-ish grouped bars + failed)
  bar('chartFunnel', D.funnel.labels, [
    { label: 'Started', data: D.funnel.started, backgroundColor: P[0] },
    { label: 'Completed', data: D.funnel.completed, backgroundColor: P[1] },
    { label: 'Failed', data: D.funnel.failed, backgroundColor: P[3] }
  ]);

  // Churn doughnut
  doughnut('chartChurn', ['Active (≤7d)', 'Active (8–30d)', 'Churned (>30d)'], [D.churn.active7, D.churn.active30minus7, D.churn.churned]);

  // Lifespan bar
  bar('chartLifespan', D.lifespan.labels, [{ label: 'Installs', data: D.lifespan.data, backgroundColor: P[4] }], { legend: false });

  // OS + template doughnuts
  doughnut('chartOs', D.os.labels, D.os.data);
  doughnut('chartTemplate', D.template.labels, D.template.data);

  // Node version horizontal bar
  bar('chartNode', D.node.labels, [{ label: 'Installs', data: D.node.data, backgroundColor: P[5] }], { horizontal: true, legend: false });

  // Country
  if (D.country && D.country.labels.length) {
    bar('chartCountry', D.country.labels, [{ label: 'Installs', data: D.country.data, backgroundColor: P[0] }], { horizontal: true, legend: false });
  }

  // What people build — project_snapshot charts
  if (D.collections && D.collections.labels.length) {
    bar('chartCollections', D.collections.labels, [
      { label: 'Total Docs', data: D.collections.docs, backgroundColor: P[0] },
      { label: 'Installations', data: D.collections.installs, backgroundColor: P[1] }
    ], { horizontal: true });
  }
  if (D.plugins && D.plugins.labels.length) {
    bar('chartPlugins', D.plugins.labels, [
      { label: 'Installations', data: D.plugins.data, backgroundColor: P[4] }
    ], { horizontal: true, legend: false });
  }
  if (D.fieldTypes && D.fieldTypes.labels.length) {
    doughnut('chartFieldTypes', D.fieldTypes.labels, D.fieldTypes.data);
  }
  if (D.versions && D.versions.labels.length) {
    doughnut('chartVersions', D.versions.labels, D.versions.data);
  }
  if (D.docVolume && D.docVolume.labels.length) {
    bar('chartDocVolume', D.docVolume.labels, [
      { label: 'Installations', data: D.docVolume.data, backgroundColor: P[2] }
    ], { legend: false });
  }

  // Demo logins
  if (D.demoLogin && D.demoLogin.labels.length) {
    bar('chartDemoLogin', D.demoLogin.labels, [
      { label: 'Logins', data: D.demoLogin.data, backgroundColor: P[0] }
    ], { legend: false });
  }
})();
</script>`

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
