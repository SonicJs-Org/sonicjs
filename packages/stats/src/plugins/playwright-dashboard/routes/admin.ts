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

// ── Helpers ──────────────────────────────────────────────────────────────
const RUNS_WHERE = `type_id = 'playwright_runs' AND is_published = 1 AND deleted_at IS NULL`
const TESTS_WHERE = `type_id = 'playwright_tests' AND is_published = 1 AND deleted_at IS NULL`

function esc(v: unknown): string {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function jsonForScript(v: unknown): string {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
}

interface Row { [k: string]: any }
const rowsOf = (r: { results?: unknown[] } | null): Row[] => (r?.results ?? []) as Row[]

const PALETTE = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#ec4899', '#84cc16']

// ── Main dashboard (GET /) ───────────────────────────────────────────────
adminRoutes.get('/', async (c) => {
  const db = c.env.DB
  const user = c.get('user')

  const [
    recentRunsR,
    totalRunsR,
    passRateR,
    flakyTotalR,
    avgDurationR,
    dailyRunsR,
    topFlakyR,
    topFailingR,
  ] = await Promise.all([
    // 1. Recent runs (last 50)
    db.prepare(
      `SELECT json_extract(data, '$.run_id') AS run_id,
              json_extract(data, '$.branch') AS branch,
              json_extract(data, '$.commit_sha') AS commit_sha,
              json_extract(data, '$.commit_message') AS commit_message,
              json_extract(data, '$.ci_run_url') AS ci_run_url,
              json_extract(data, '$.triggered_by') AS triggered_by,
              json_extract(data, '$.total') AS total,
              json_extract(data, '$.passed') AS passed,
              json_extract(data, '$.failed') AS failed,
              json_extract(data, '$.skipped') AS skipped,
              json_extract(data, '$.flaky') AS flaky,
              json_extract(data, '$.duration_ms') AS duration_ms,
              json_extract(data, '$.started_at') AS started_at,
              json_extract(data, '$.finished_at') AS finished_at
       FROM documents WHERE ${RUNS_WHERE}
       ORDER BY created_at DESC LIMIT 50`
    ).all(),

    // 2. Total run count
    db.prepare(
      `SELECT COUNT(*) AS count FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 3. Overall pass rate (across all runs)
    db.prepare(
      `SELECT
         SUM(CAST(json_extract(data, '$.passed') AS INTEGER)) AS total_passed,
         SUM(CAST(json_extract(data, '$.total') AS INTEGER)) AS total_tests
       FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 4. Total flaky test occurrences
    db.prepare(
      `SELECT SUM(CAST(json_extract(data, '$.flaky') AS INTEGER)) AS total_flaky
       FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 5. Average run duration
    db.prepare(
      `SELECT AVG(CAST(json_extract(data, '$.duration_ms') AS REAL)) AS avg_ms
       FROM documents WHERE ${RUNS_WHERE}`
    ).first(),

    // 6. Runs per day (last 30 days) — for the trend chart
    db.prepare(
      `SELECT date(datetime(created_at, 'unixepoch')) AS day,
              COUNT(*) AS runs,
              SUM(CASE WHEN CAST(json_extract(data, '$.failed') AS INTEGER) = 0 AND CAST(json_extract(data, '$.passed') AS INTEGER) > 0 THEN 1 ELSE 0 END) AS green_runs,
              SUM(CASE WHEN CAST(json_extract(data, '$.failed') AS INTEGER) > 0 THEN 1 ELSE 0 END) AS red_runs,
              AVG(CAST(json_extract(data, '$.passed') AS REAL) / MAX(CAST(json_extract(data, '$.total') AS REAL), 1) * 100) AS avg_pass_rate
       FROM documents WHERE ${RUNS_WHERE}
         AND created_at >= unixepoch('now', '-30 days')
       GROUP BY day ORDER BY day ASC`
    ).all(),

    // 7. Top 10 flakiest tests (most is_flaky=true occurrences, last 30 days)
    db.prepare(
      `SELECT json_extract(data, '$.test_title') AS test_title,
              json_extract(data, '$.test_file') AS test_file,
              COUNT(*) AS flaky_count,
              COUNT(DISTINCT json_extract(data, '$.run_id')) AS affected_runs
       FROM documents WHERE ${TESTS_WHERE}
         AND json_extract(data, '$.is_flaky') = 1
         AND created_at >= unixepoch('now', '-30 days')
       GROUP BY json_extract(data, '$.test_id')
       ORDER BY flaky_count DESC LIMIT 10`
    ).all(),

    // 8. Top 10 most-failing tests — final attempt only (last 30 days)
    // Only count the highest retry per (run_id, test_id, project_name) to avoid
    // double-counting retried tests. Includes failed, timedOut, interrupted.
    db.prepare(
      `SELECT json_extract(t1.data, '$.test_title') AS test_title,
              json_extract(t1.data, '$.test_file') AS test_file,
              json_extract(t1.data, '$.error_message') AS error_message,
              COUNT(*) AS fail_count
       FROM documents t1
       WHERE t1.type_id = 'playwright_tests' AND t1.is_published = 1 AND t1.deleted_at IS NULL
         AND json_extract(t1.data, '$.status') IN ('failed', 'timedOut', 'interrupted')
         AND t1.created_at >= unixepoch('now', '-30 days')
         AND NOT EXISTS (
           SELECT 1 FROM documents t2
           WHERE t2.type_id = 'playwright_tests' AND t2.is_published = 1 AND t2.deleted_at IS NULL
             AND json_extract(t2.data, '$.run_id') = json_extract(t1.data, '$.run_id')
             AND json_extract(t2.data, '$.test_id') = json_extract(t1.data, '$.test_id')
             AND json_extract(t2.data, '$.project_name') = json_extract(t1.data, '$.project_name')
             AND CAST(json_extract(t2.data, '$.retry') AS INTEGER) > CAST(json_extract(t1.data, '$.retry') AS INTEGER)
         )
       GROUP BY json_extract(t1.data, '$.test_id')
       ORDER BY fail_count DESC LIMIT 10`
    ).all(),
  ])

  // ── Aggregate data ──────────────────────────────────────────────────
  const recentRuns = rowsOf(recentRunsR)
  const totalRuns = Number((totalRunsR as Row | null)?.count ?? 0)
  const pr = (passRateR ?? {}) as Row
  const overallPassRate = Number(pr.total_tests) > 0
    ? Math.round((Number(pr.total_passed) / Number(pr.total_tests)) * 100)
    : 0
  const totalFlaky = Number((flakyTotalR as Row | null)?.total_flaky ?? 0)
  const avgDuration = Math.round(Number((avgDurationR as Row | null)?.avg_ms ?? 0) / 1000)

  const dailyRuns = rowsOf(dailyRunsR) as { day: string; runs: number; green_runs: number; red_runs: number; avg_pass_rate: number }[]
  const topFlaky = rowsOf(topFlakyR) as { test_title: string; test_file: string; flaky_count: number; affected_runs: number }[]
  const topFailing = rowsOf(topFailingR) as { test_title: string; test_file: string; error_message: string; fail_count: number }[]

  // ── Chart data ──────────────────────────────────────────────────────
  const charts = {
    daily: {
      labels: dailyRuns.map(r => r.day),
      green: dailyRuns.map(r => Number(r.green_runs)),
      red: dailyRuns.map(r => Number(r.red_runs)),
      passRate: dailyRuns.map(r => Math.round(Number(r.avg_pass_rate))),
    },
  }

  // ── KPI helper (copy from stats-dashboard) ─────────────────────────
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

  // ── Format duration ────────────────────────────────────────────────
  function fmtDuration(ms: number): string {
    const s = Math.round(ms / 1000)
    if (s < 60) return `${s}s`
    const m = Math.floor(s / 60)
    return `${m}m ${s % 60}s`
  }

  // ── Render ─────────────────────────────────────────────────────────
  const content = `
<div class="space-y-8">
  <div>
    <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Playwright CI/CD</h1>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Test run history, flaky detection, and failure trends</p>
  </div>

  <!-- KPI row -->
  <div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
    ${kpi('Total Runs', totalRuns.toLocaleString(), 'all time')}
    ${kpi('Pass Rate', overallPassRate + '%', 'across all runs', overallPassRate >= 90 ? 'text-emerald-600 dark:text-emerald-400' : overallPassRate >= 70 ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400')}
    ${kpi('Flaky Tests', totalFlaky.toLocaleString(), 'total flaky occurrences', totalFlaky > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-emerald-600 dark:text-emerald-400')}
    ${kpi('Avg Duration', avgDuration > 0 ? fmtDuration(avgDuration * 1000) : '—', 'per run')}
  </div>

  <!-- Daily trend chart -->
  ${card('Run Trend (Last 30 Days)', 'Green (all pass) vs red (has failures) runs per day',
    dailyRuns.length > 0
      ? '<canvas id="chartDaily" height="240"></canvas>'
      : '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No runs yet. Send your first Playwright run to see the trend.</div>'
  )}

  <!-- Flaky + Failing side by side -->
  <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
    ${card('🔄 Top Flaky Tests', 'Tests that fail then pass on retry — sorted by frequency', topFlaky.length === 0
      ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No flaky tests detected yet.</div>'
      : `<div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            <tr><th class="py-2 text-left font-medium">Test</th><th class="py-2 text-right font-medium">Flaky Count</th><th class="py-2 text-right font-medium">Runs Affected</th></tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${topFlaky.map(r => `<tr>
            <td class="py-2 pr-4"><div class="text-zinc-700 dark:text-zinc-300">${esc(r.test_title)}</div><div class="text-xs text-zinc-400 font-mono">${esc(r.test_file)}</div></td>
            <td class="py-2 text-right font-semibold text-amber-600 dark:text-amber-400">${Number(r.flaky_count)}</td>
            <td class="py-2 text-right text-zinc-500">${Number(r.affected_runs)}</td>
          </tr>`).join('')}
          </tbody></table></div>`
    )}

    ${card('❌ Top Failing Tests', 'Most frequently failing tests (final attempt)', topFailing.length === 0
      ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No failures recorded yet.</div>'
      : `<div class="overflow-x-auto"><table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            <tr><th class="py-2 text-left font-medium">Test</th><th class="py-2 text-left font-medium">Error</th><th class="py-2 text-right font-medium">Fails</th></tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${topFailing.map(r => `<tr>
            <td class="py-2 pr-4"><div class="text-zinc-700 dark:text-zinc-300">${esc(r.test_title)}</div><div class="text-xs text-zinc-400 font-mono">${esc(r.test_file)}</div></td>
            <td class="py-2 pr-4 text-xs text-zinc-500 dark:text-zinc-400 max-w-xs truncate">${esc(r.error_message)}</td>
            <td class="py-2 text-right font-semibold text-red-600 dark:text-red-400">${Number(r.fail_count)}</td>
          </tr>`).join('')}
          </tbody></table></div>`
    )}
  </div>

  <!-- Recent Runs table -->
  ${card('Recent Runs', 'Last 50 CI/CD runs', recentRuns.length === 0
    ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No runs yet.</div>'
    : `<div class="overflow-x-auto"><table class="w-full text-sm">
        <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          <tr>
            <th class="py-2 text-left font-medium">Status</th>
            <th class="py-2 text-left font-medium">Branch</th>
            <th class="py-2 text-left font-medium">Commit</th>
            <th class="py-2 text-right font-medium">Passed</th>
            <th class="py-2 text-right font-medium">Failed</th>
            <th class="py-2 text-right font-medium">Flaky</th>
            <th class="py-2 text-right font-medium">Duration</th>
            <th class="py-2 text-left font-medium">When</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
        ${recentRuns.map(r => {
          const failed = Number(r.failed)
          const flakyN = Number(r.flaky)
          const statusDot = failed > 0
            ? '<span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500" title="Has failures"></span>'
            : Number(r.passed) === 0
              ? '<span class="inline-block w-2.5 h-2.5 rounded-full bg-zinc-400" title="No passing tests"></span>'
              : flakyN > 0
                ? '<span class="inline-block w-2.5 h-2.5 rounded-full bg-amber-500" title="Flaky"></span>'
                : '<span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500" title="All passed"></span>'
          const commitLink = r.ci_run_url
            ? `<a href="${esc(r.ci_run_url)}" target="_blank" rel="noopener" class="hover:text-indigo-600 dark:hover:text-indigo-400">${esc(String(r.commit_sha).slice(0,7))}</a>`
            : esc(String(r.commit_sha).slice(0,7))
          return `<tr>
            <td class="py-2 pr-2">${statusDot}</td>
            <td class="py-2 pr-4 font-mono text-xs text-zinc-700 dark:text-zinc-300">${esc(r.branch)}</td>
            <td class="py-2 pr-4 font-mono text-xs">${commitLink}${r.commit_message ? ` <span class="text-zinc-400">${esc(String(r.commit_message).slice(0, 50))}</span>` : ''}</td>
            <td class="py-2 text-right text-emerald-600 dark:text-emerald-400">${r.passed}/${r.total}</td>
            <td class="py-2 text-right ${failed > 0 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-zinc-400'}">${r.failed}</td>
            <td class="py-2 text-right ${flakyN > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-zinc-400'}">${r.flaky}</td>
            <td class="py-2 text-right text-zinc-500">${fmtDuration(Number(r.duration_ms))}</td>
            <td class="py-2 text-xs text-zinc-400">${r.started_at ? new Date(r.started_at).toLocaleDateString() : '—'}</td>
          </tr>`
        }).join('')}
        </tbody></table></div>`
  )}
</div>

<script>
(function () {
  if (typeof Chart === 'undefined') return;
  var D = ${jsonForScript(charts)};
  var P = ${jsonForScript(PALETTE)};
  var dark = document.documentElement.classList.contains('dark');
  var grid = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
  var tick = dark ? '#a1a1aa' : '#52525b';
  Chart.defaults.color = tick;
  Chart.defaults.font.size = 11;

  // Daily stacked bar (green/red runs) + pass rate line
  var el = document.getElementById('chartDaily');
  if (el && D.daily.labels.length) {
    new Chart(el, {
      type: 'bar',
      data: {
        labels: D.daily.labels,
        datasets: [
          { label: 'Green runs', data: D.daily.green, backgroundColor: '#10b981', stack: 'runs' },
          { label: 'Red runs', data: D.daily.red, backgroundColor: '#ef4444', stack: 'runs' },
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } },
        scales: {
          x: { grid: { display: false }, ticks: { color: tick, maxRotation: 60 }, stacked: true },
          y: { grid: { color: grid }, ticks: { color: tick }, beginAtZero: true, stacked: true },
        }
      }
    });
  }
})();
</script>`

  return c.html(
    renderAdminLayoutCatalyst({
      title: 'Playwright',
      pageTitle: 'Playwright CI/CD',
      currentPath: '/admin/playwright',
      version: c.get('appVersion'),
      user: user
        ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role }
        : undefined,
      scripts: ['https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js'],
      content,
      dynamicMenuItems: c.get('pluginMenuItems'),
    })
  )
})

export { adminRoutes as playwrightAdminRoutes }
