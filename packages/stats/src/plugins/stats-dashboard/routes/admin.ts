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
    // 9. Install failures by errorType
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.properties.errorType'), json_extract(data,'$.error_code'),'unknown') AS err,
              COALESCE(json_extract(data,'$.step'),'-') AS step,
              COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='installation_failed'
       GROUP BY err, step ORDER BY count DESC LIMIT 25`
    ).all(),
    // 10. Runtime errors (error_occurred) by errorType + version
    db.prepare(
      `SELECT COALESCE(json_extract(data,'$.properties.errorType'),'unknown') AS err,
              COALESCE(json_extract(data,'$.properties.version'),'-') AS version,
              COUNT(*) AS count
       FROM documents WHERE ${EVENTS_WHERE} AND json_extract(data,'$.event_type')='error_occurred'
       GROUP BY err, version ORDER BY count DESC LIMIT 25`
    ).all(),
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
    return { week: w, started: s, completed: comp, failed: f, rate: s > 0 ? Math.round((comp / s) * 100) : 0 }
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
  const installFailRows = rowsOf(installFailR) as { err: string; step: string; count: number }[]
  const runtimeErrRows = rowsOf(runtimeErrR) as { err: string; version: string; count: number }[]

  // ── Chart datasets (serialized) ─────────────────────────────────────────
  const charts = {
    trend: { labels: trendLabels.map(fmtWeekDate), weekly: trendCounts, cumulative: trendCumulative },
    funnel: { labels: recentWeeks.map(fmtWeekDate), started: funnelStarted, completed: funnelCompleted, failed: funnelFailed },
    churn: { active7, active30minus7: Math.max(0, active30 - active7), churned },
    lifespan: { labels: lifeOrder.map((k) => lifeLabels[k]), data: lifespanData },
    os: { labels: osRows.map((r) => r.os), data: osRows.map((r) => Number(r.count)) },
    node: { labels: nodeRows.map((r) => r.v), data: nodeRows.map((r) => r.count) },
    template: { labels: templateRows.map((r) => r.t), data: templateRows.map((r) => Number(r.count)) },
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

  <!-- Weekly table -->
  ${card('Weekly Breakdown', 'Detailed funnel by week', tableWeeks.length === 0 ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No data yet.</div>' : `
    <div class="overflow-x-auto"><table class="w-full text-sm">
      <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
        <tr>
          <th class="py-2 text-left font-medium">Week</th>
          <th class="py-2 text-right font-medium">Started</th>
          <th class="py-2 text-right font-medium">Completed</th>
          <th class="py-2 text-right font-medium">Failed</th>
          <th class="py-2 text-right font-medium">Completion %</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
      ${tableWeeks.map((r) => `<tr>
        <td class="py-2 font-mono text-zinc-700 dark:text-zinc-300">${fmtWeekDate(r.week)}</td>
        <td class="py-2 text-right text-zinc-700 dark:text-zinc-300">${r.started.toLocaleString()}</td>
        <td class="py-2 text-right text-emerald-600 dark:text-emerald-400 font-medium">${r.completed.toLocaleString()}</td>
        <td class="py-2 text-right ${r.failed > 0 ? 'text-red-600 dark:text-red-400' : 'text-zinc-400'}">${r.failed.toLocaleString()}</td>
        <td class="py-2 text-right"><span class="inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${r.rate >= 70 ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' : r.rate >= 40 ? 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' : 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400'}">${r.rate}%</span></td>
      </tr>`).join('')}
      </tbody></table></div>`)}

  <!-- Errors -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('Install Failures', 'installation_failed grouped by error + step', errTable(installFailRows.map((r) => ({ err: r.err, sub: r.step, count: Number(r.count) })), 'Step', 'No failures recorded.'))}
    ${card('Runtime Errors', 'error_occurred grouped by error + version', errTable(runtimeErrRows.map((r) => ({ err: r.err, sub: r.version, count: Number(r.count) })), 'Version', 'No runtime errors recorded.'))}
  </div>
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
