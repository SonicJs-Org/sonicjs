import { Hono } from 'hono'
import { requireAuth } from '@sonicjs-cms/core'
import { renderAdminLayoutCatalyst } from '@sonicjs-cms/core'
import type { Bindings, Variables } from '@sonicjs-cms/core'
import { STATS_ADMIN_MENU } from '../../../admin-menu'

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

// ── Main dashboard (GET /) or run detail (GET /?run=<run_id>) ───────────────
adminRoutes.get('/', async (c) => {
  const runId = c.req.query('run')
  if (runId) return showRunDetail(c, runId)
  const testId = c.req.query('test')
  if (testId) return showTestHistory(c, testId)
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
              json_extract(data, '$.finished_at') AS finished_at,
              json_extract(data, '$.source') AS source,
              json_extract(data, '$.run_status') AS run_status
       FROM documents WHERE ${RUNS_WHERE}
       ORDER BY
         CASE WHEN json_extract(data, '$.run_status') = 'running' THEN 0 ELSE 1 END,
         created_at DESC
       LIMIT 50`
    ).all(),
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

    // 8. Top 10 most-failing tests (last 30 days)
    // Counts all failed/timedOut/interrupted rows per test_id — includes retries,
    // which slightly over-counts but avoids an O(n²) correlated subquery on D1.
    db.prepare(
      `SELECT json_extract(data, '$.test_title') AS test_title,
              json_extract(data, '$.test_file') AS test_file,
              json_extract(data, '$.error_message') AS error_message,
              COUNT(*) AS fail_count
       FROM documents WHERE ${TESTS_WHERE}
         AND json_extract(data, '$.status') IN ('failed', 'timedOut', 'interrupted')
         AND created_at >= unixepoch('now', '-30 days')
       GROUP BY json_extract(data, '$.test_id')
       ORDER BY fail_count DESC LIMIT 10`
    ).all(),
  ])

  // ── Aggregate data ──────────────────────────────────────────────────
  const recentRuns = rowsOf(recentRunsR)
  // A run is "live" only if its run_status is 'running' AND it started within
  // the last 180 min (longer than the 150-min CI timeout) to avoid showing
  // abandoned runs as indefinitely live.
  const LIVE_STALE_MS = 180 * 60 * 1000
  const hasLiveRuns = recentRuns.some(r => {
    if (String(r.run_status ?? '') !== 'running') return false
    const startedAt = r.started_at ? new Date(String(r.started_at)).getTime() : 0
    return Date.now() - startedAt < LIVE_STALE_MS
  })
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
<div class="space-y-6">
  <!-- Page header -->
  <div>
    <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Playwright CI/CD</h1>
    <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Test run history, flaky detection, and failure trends</p>
  </div>

  <!-- Tab nav -->
  <div class="border-b border-zinc-950/10 dark:border-white/10">
    <nav class="-mb-px flex gap-x-6" aria-label="Tabs">
      <button id="tab-runs" onclick="pwTab('runs')"
        class="whitespace-nowrap border-b-2 pb-3 text-sm font-medium transition-colors"
        aria-selected="true">
        Runs
      </button>
      <button id="tab-stats" onclick="pwTab('stats')"
        class="whitespace-nowrap border-b-2 pb-3 text-sm font-medium transition-colors"
        aria-selected="false">
        Stats
      </button>
    </nav>
  </div>

  <!-- ── Runs panel ───────────────────────────────────────────────── -->
  <div id="panel-runs">
    ${recentRuns.length === 0
      ? '<div class="py-16 text-center text-sm text-zinc-500 dark:text-zinc-400">No runs yet.</div>'
      : `<div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-x-auto">
        <table class="w-full text-sm">
          <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-zinc-950/5 dark:border-white/5">
            <tr>
              <th class="px-4 py-3 text-left font-medium">Status</th>
              <th class="px-4 py-3 text-left font-medium">Source</th>
              <th class="px-4 py-3 text-left font-medium">Branch</th>
              <th class="px-4 py-3 text-left font-medium">Commit</th>
              <th class="px-4 py-3 text-right font-medium">Passed</th>
              <th class="px-4 py-3 text-right font-medium">Failed</th>
              <th class="px-4 py-3 text-right font-medium">Flaky</th>
              <th class="px-4 py-3 text-right font-medium">Duration</th>
              <th class="px-4 py-3 text-left font-medium">When</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
          ${recentRuns.map(r => {
            const failed = Number(r.failed)
            const flakyN = Number(r.flaky)
            const src = String(r.source ?? 'ci')
            const sourceBadge = src === 'local'
              ? '<span class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400">local</span>'
              : '<span class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400">CI</span>'
            const isLive = String(r.run_status ?? '') === 'running' &&
              (r.started_at ? Date.now() - new Date(String(r.started_at)).getTime() < LIVE_STALE_MS : false)
            const liveBadge = isLive
              ? '<span class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs font-semibold bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400 animate-pulse">● live</span>'
              : ''
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
            return `<tr class="cursor-pointer hover:bg-zinc-950/[0.02] dark:hover:bg-white/[0.02]" onclick="window.location='/admin/playwright?run=${encodeURIComponent(String(r.run_id))}'">
              <td class="px-4 py-2.5">${statusDot}${liveBadge ? ' ' + liveBadge : ''}</td>
              <td class="px-4 py-2.5">${sourceBadge}</td>
              <td class="px-4 py-2.5 font-mono text-xs text-zinc-700 dark:text-zinc-300">${esc(r.branch)}</td>
              <td class="px-4 py-2.5 font-mono text-xs">${commitLink}${r.commit_message ? ` <span class="text-zinc-400">${esc(String(r.commit_message).slice(0, 50))}</span>` : ''}</td>
              <td class="px-4 py-2.5 text-right text-emerald-600 dark:text-emerald-400">${r.passed}/${r.total}</td>
              <td class="px-4 py-2.5 text-right ${failed > 0 ? 'text-red-600 dark:text-red-400 font-semibold' : 'text-zinc-400'}">${r.failed}</td>
              <td class="px-4 py-2.5 text-right ${flakyN > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-zinc-400'}">${r.flaky}</td>
              <td class="px-4 py-2.5 text-right text-zinc-500">${fmtDuration(Number(r.duration_ms))}</td>
              <td class="px-4 py-2.5 text-xs text-zinc-400">${r.started_at ? new Date(r.started_at).toLocaleDateString() : '—'}</td>
            </tr>`
          }).join('')}
          </tbody>
        </table>
      </div>`
    }
  </div>

  <!-- ── Stats panel (hidden by default) ──────────────────────────── -->
  <div id="panel-stats" class="hidden space-y-8">
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
        : '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No runs yet.</div>'
    )}

    <!-- Flaky + Failing side by side -->
    <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      ${card('🔄 Top Flaky Tests', 'Tests that fail then pass on retry — sorted by frequency', topFlaky.length === 0
        ? '<div class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No flaky tests detected yet.</div>'
        : `<div class="overflow-x-auto"><table class="w-full text-sm">
            <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              <tr><th class="py-2 text-left font-medium">Test</th><th class="py-2 text-right font-medium">Flaky</th><th class="py-2 text-right font-medium">Runs</th></tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
            ${topFlaky.map(r => `<tr>
              <td class="py-2 pr-4"><div class="text-zinc-700 dark:text-zinc-300">${esc(r.test_title)}</div><div class="text-xs text-zinc-400 font-mono">${esc(r.test_file)}</div></td>
              <td class="py-2 text-right font-semibold text-amber-600 dark:text-amber-400">${Number(r.flaky_count)}</td>
              <td class="py-2 text-right text-zinc-500">${Number(r.affected_runs)}</td>
            </tr>`).join('')}
            </tbody></table></div>`
      )}
      ${card('❌ Top Failing Tests', 'Most frequently failing tests (last 30 days)', topFailing.length === 0
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
  </div>
</div>

<script>
(function () {
  var ACTIVE   = 'border-zinc-950 dark:border-white text-zinc-950 dark:text-white';
  var INACTIVE = 'border-transparent text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-300';
  var chartInited = false;

  function pwTab(name) {
    ['runs', 'stats'].forEach(function(t) {
      var btn   = document.getElementById('tab-'   + t);
      var panel = document.getElementById('panel-' + t);
      var active = (t === name);
      if (btn)   { btn.className = btn.className.replace(/(border-zinc-950 dark:border-white text-zinc-950 dark:text-white|border-transparent text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-300)/g, '').trim() + ' ' + (active ? ACTIVE : INACTIVE); btn.setAttribute('aria-selected', active); }
      if (panel) { panel.classList.toggle('hidden', !active); }
    });
    // Lazy-init chart the first time the stats tab is shown
    if (name === 'stats' && !chartInited) { initChart(); chartInited = true; }
    try { history.replaceState(null, '', '#' + name); } catch(e) {}
  }

  function initChart() {
    if (typeof Chart === 'undefined') return;
    var D = ${jsonForScript(charts)};
    var P = ${jsonForScript(PALETTE)};
    var dark = document.documentElement.classList.contains('dark');
    var grid = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
    var tick = dark ? '#a1a1aa' : '#52525b';
    Chart.defaults.color = tick;
    Chart.defaults.font.size = 11;
    var el = document.getElementById('chartDaily');
    if (el && D.daily.labels.length) {
      new Chart(el, {
        type: 'bar',
        data: {
          labels: D.daily.labels,
          datasets: [
            { label: 'Green runs', data: D.daily.green, backgroundColor: '#10b981', stack: 'runs' },
            { label: 'Red runs',   data: D.daily.red,   backgroundColor: '#ef4444', stack: 'runs' },
          ]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } },
          scales: {
            x: { grid: { display: false }, ticks: { color: tick, maxRotation: 60 }, stacked: true },
            y: { grid: { color: grid },    ticks: { color: tick }, beginAtZero: true, stacked: true },
          }
        }
      });
    }
  }

  // Init on load — restore from hash or default to 'runs'
  var init = (location.hash.slice(1) === 'stats') ? 'stats' : 'runs';
  pwTab(init);
  // Expose for inline onclick
  window.pwTab = pwTab;
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
      content: (hasLiveRuns
        ? `<script>setTimeout(()=>location.reload(),8000)</script>\n` : '')
        + content,
      dynamicMenuItems: STATS_ADMIN_MENU,
    })
  )
})

export { adminRoutes as playwrightAdminRoutes }

// ── Run detail view ──────────────────────────────────────────────────────────
async function showRunDetail(c: import('hono').Context<{ Bindings: Bindings; Variables: Variables }>, runId: string): Promise<Response> {
  const db = c.env.DB
  const user = c.get('user')

  const [runR, testsR] = await Promise.all([
    // Run metadata
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
              json_extract(data, '$.finished_at') AS finished_at,
              json_extract(data, '$.run_status') AS run_status
       FROM documents
       WHERE type_id = 'playwright_runs' AND is_published = 1 AND deleted_at IS NULL
         AND json_extract(data, '$.run_id') = ?
       LIMIT 1`
    ).bind(runId).first(),

    // All test results for this run, sorted by file then title then retry
    db.prepare(
      `SELECT json_extract(data, '$.test_id') AS test_id,
              json_extract(data, '$.test_title') AS test_title,
              json_extract(data, '$.test_file') AS test_file,
              json_extract(data, '$.project_name') AS project_name,
              json_extract(data, '$.status') AS status,
              json_extract(data, '$.duration_ms') AS duration_ms,
              CAST(json_extract(data, '$.retry') AS INTEGER) AS retry,
              json_extract(data, '$.is_flaky') AS is_flaky,
              json_extract(data, '$.error_message') AS error_message,
              json_extract(data, '$.error_snippet') AS error_snippet
       FROM documents
       WHERE type_id = 'playwright_tests' AND is_published = 1 AND deleted_at IS NULL
         AND json_extract(data, '$.run_id') = ?
       ORDER BY json_extract(data, '$.test_file'),
                json_extract(data, '$.test_title'),
                CAST(json_extract(data, '$.retry') AS INTEGER)`
    ).bind(runId).all(),
  ])

  if (!runR) {
    return c.html(
      renderAdminLayoutCatalyst({
        title: 'Run not found',
        pageTitle: 'Run not found',
        currentPath: '/admin/playwright',
        version: c.get('appVersion'),
        user: user ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role } : undefined,
        content: `<div class="py-16 text-center text-sm text-zinc-500">Run <code>${esc(runId)}</code> not found.</div>`,
        dynamicMenuItems: STATS_ADMIN_MENU,
      })
    )
  }

  type TestRow = { test_id: string; test_title: string; test_file: string; project_name: string; status: string; duration_ms: number; retry: number; is_flaky: boolean | number; error_message: string | null; error_snippet: string | null }
  const run = runR as Record<string, unknown>
  const tests = (testsR?.results ?? []) as TestRow[]

  const failed = Number(run.failed)
  const flakyN = Number(run.flaky)
  const passed = Number(run.passed)
  const total = Number(run.total)

  function fmtDuration(ms: number): string {
    const s = Math.round(ms / 1000)
    if (s < 60) return `${s}s`
    const m = Math.floor(s / 60)
    return `${m}m ${s % 60}s`
  }

  const statusBadge = (status: string) => {
    const map: Record<string, string> = {
      passed: 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400',
      failed: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      timedOut: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      interrupted: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
      skipped: 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400',
    }
    return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${map[status] ?? map.skipped}">${esc(status)}</span>`
  }

  // Group tests by file for display
  let lastFile = ''
  const testRows = tests.map(t => {
    const isNewFile = t.test_file !== lastFile
    lastFile = t.test_file
    const fileRow = isNewFile
      ? `<tr><td colspan="6" class="pt-4 pb-1 text-xs font-mono font-semibold text-zinc-400 dark:text-zinc-500 select-all">${esc(t.test_file)}</td></tr>`
      : ''
    const isFlaky = t.is_flaky === 1 || t.is_flaky === true
    return `${fileRow}<tr class="border-t border-zinc-950/5 dark:border-white/5 cursor-pointer hover:bg-zinc-950/[0.02] dark:hover:bg-white/[0.02]" onclick="window.location='/admin/playwright?test=${encodeURIComponent(String(t.test_id))}'">
      <td class="py-2 pr-3">${statusBadge(t.status)}${isFlaky ? ' <span class="ml-1 inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">flaky</span>' : ''}</td>
      <td class="py-2 pr-4 text-sm text-zinc-700 dark:text-zinc-300 max-w-sm">${esc(t.test_title)}${t.retry > 0 ? ` <span class="text-xs text-zinc-400">(retry ${t.retry})</span>` : ''}</td>
      <td class="py-2 pr-3 text-xs text-zinc-400 font-mono">${t.project_name ? esc(t.project_name) : ''}</td>
      <td class="py-2 pr-3 text-right text-xs text-zinc-500">${fmtDuration(Number(t.duration_ms))}</td>
      <td class="py-2 text-xs text-red-500 dark:text-red-400 max-w-xs">${t.error_message ? `<span title="${esc(t.error_message)}">${esc(String(t.error_message).slice(0, 80))}${String(t.error_message).length > 80 ? '…' : ''}</span>` : ''}</td>
    </tr>`
  }).join('')

  const headerStatusDot = failed > 0
    ? '<span class="inline-block w-3 h-3 rounded-full bg-red-500 mr-2"></span>'
    : passed === 0
      ? '<span class="inline-block w-3 h-3 rounded-full bg-zinc-400 mr-2"></span>'
      : flakyN > 0
        ? '<span class="inline-block w-3 h-3 rounded-full bg-amber-500 mr-2"></span>'
        : '<span class="inline-block w-3 h-3 rounded-full bg-emerald-500 mr-2"></span>'

  const ciLink = run.ci_run_url
    ? `<a href="${esc(String(run.ci_run_url))}" target="_blank" rel="noopener" class="text-indigo-600 dark:text-indigo-400 hover:underline text-sm">${esc(String(run.commit_sha).slice(0,7))}</a>`
    : `<span class="font-mono text-sm">${esc(String(run.commit_sha).slice(0,7))}</span>`

  const isRunLive = String((run as any).run_status ?? '') === 'running' &&
    ((run as any).started_at
      ? Date.now() - new Date(String((run as any).started_at)).getTime() < 180 * 60 * 1000
      : false)
  const liveRefreshScript = isRunLive
    ? `<script>setTimeout(()=>location.reload(),5000)</script>\n`
    : ''
  const liveBanner = isRunLive
    ? `<div class="rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800 px-4 py-2 flex items-center gap-2 text-sm text-emerald-700 dark:text-emerald-400">
        <span class="animate-pulse">●</span>
        <span>Run in progress — page auto-refreshes every 5 s as tests complete</span>
       </div>`
    : ''

  const content = `${liveRefreshScript}
<div class="space-y-6">
  <!-- Back link -->
  <div>
    <a href="/admin/playwright" class="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300">
      <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg>
      All runs
    </a>
  </div>
  ${liveBanner}

  <!-- Run header -->
  <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
    <div class="flex items-start justify-between gap-4 flex-wrap">
      <div>
        <h1 class="text-xl font-semibold text-zinc-950 dark:text-white flex items-center">
          ${headerStatusDot}${esc(String(run.branch))}
        </h1>
        <div class="mt-1 text-sm text-zinc-500 dark:text-zinc-400 flex flex-wrap gap-x-4 gap-y-1">
          <span>Commit: ${ciLink}${run.commit_message ? ` — <span class="text-zinc-400">${esc(String(run.commit_message).slice(0,80))}</span>` : ''}</span>
          ${run.triggered_by ? `<span>Trigger: <span class="font-medium">${esc(String(run.triggered_by))}</span></span>` : ''}
          ${run.started_at ? `<span>${new Date(String(run.started_at)).toLocaleString()}</span>` : ''}
          <span>Duration: <span class="font-medium">${fmtDuration(Number(run.duration_ms))}</span></span>
        </div>
      </div>
    </div>

    <!-- KPI bar -->
    <div class="mt-4 grid grid-cols-4 gap-4">
      <div class="text-center">
        <div class="text-2xl font-bold text-emerald-600 dark:text-emerald-400">${passed}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Passed</div>
      </div>
      <div class="text-center">
        <div class="text-2xl font-bold ${failed > 0 ? 'text-red-600 dark:text-red-400' : 'text-zinc-400'}">${failed}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Failed</div>
      </div>
      <div class="text-center">
        <div class="text-2xl font-bold ${flakyN > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-zinc-400'}">${flakyN}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Flaky</div>
      </div>
      <div class="text-center">
        <div class="text-2xl font-bold text-zinc-400">${total}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Total</div>
      </div>
    </div>
  </div>

  <!-- Test results -->
  <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
    <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
      <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Test Results</h2>
      <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">${tests.length} result${tests.length !== 1 ? 's' : ''} — grouped by file</p>
    </div>
    <div class="p-6 overflow-x-auto">
      ${tests.length === 0
        ? '<div class="py-8 text-center text-sm text-zinc-500">No test results stored for this run.</div>'
        : `<table class="w-full text-sm">
            <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              <tr>
                <th class="pb-2 text-left font-medium">Status</th>
                <th class="pb-2 text-left font-medium">Test</th>
                <th class="pb-2 text-left font-medium">Project</th>
                <th class="pb-2 text-right font-medium pr-3">Duration</th>
                <th class="pb-2 text-left font-medium">Error</th>
              </tr>
            </thead>
            <tbody>${testRows}</tbody>
          </table>`
      }
    </div>
  </div>
</div>`

  return c.html(
    renderAdminLayoutCatalyst({
      title: `Run: ${esc(runId)}`,
      pageTitle: 'Playwright CI/CD',
      currentPath: '/admin/playwright',
      version: c.get('appVersion'),
      user: user ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role } : undefined,
      content,
      dynamicMenuItems: STATS_ADMIN_MENU,
    })
  )
}

// ── Test history view ─────────────────────────────────────────────────────────
async function showTestHistory(c: import('hono').Context<{ Bindings: Bindings; Variables: Variables }>, testId: string): Promise<Response> {
  const db = c.env.DB
  const user = c.get('user')

  const resultsR = await db.prepare(
    `SELECT
       json_extract(t.data, '$.test_title')    AS test_title,
       json_extract(t.data, '$.test_file')     AS test_file,
       json_extract(t.data, '$.project_name')  AS project_name,
       json_extract(t.data, '$.status')        AS status,
       json_extract(t.data, '$.duration_ms')   AS duration_ms,
       CAST(json_extract(t.data, '$.retry') AS INTEGER) AS retry,
       json_extract(t.data, '$.is_flaky')      AS is_flaky,
       json_extract(t.data, '$.error_message') AS error_message,
       json_extract(t.data, '$.run_id')        AS run_id,
       json_extract(r.data, '$.branch')        AS branch,
       json_extract(r.data, '$.commit_sha')    AS commit_sha,
       json_extract(r.data, '$.ci_run_url')    AS ci_run_url,
       json_extract(r.data, '$.started_at')    AS started_at
     FROM documents t
     LEFT JOIN documents r
       ON r.type_id = 'playwright_runs'
       AND r.is_published = 1
       AND r.deleted_at IS NULL
       AND json_extract(r.data, '$.run_id') = json_extract(t.data, '$.run_id')
     WHERE t.type_id = 'playwright_tests'
       AND t.is_published = 1
       AND t.deleted_at IS NULL
       AND json_extract(t.data, '$.test_id') = ?
     ORDER BY t.created_at DESC
     LIMIT 200`
  ).bind(testId).all()

  type HistRow = {
    test_title: string; test_file: string; project_name: string
    status: string; duration_ms: number; retry: number
    is_flaky: boolean | number; error_message: string | null
    run_id: string; branch: string | null; commit_sha: string | null
    ci_run_url: string | null; started_at: string | null
  }
  const rows = (resultsR?.results ?? []) as HistRow[]

  if (rows.length === 0) {
    return c.html(
      renderAdminLayoutCatalyst({
        title: 'Test not found',
        pageTitle: 'Playwright CI/CD',
        currentPath: '/admin/playwright',
        version: c.get('appVersion'),
        user: user ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role } : undefined,
        content: `<div class="py-16 text-center text-sm text-zinc-500">No results found for test ID <code>${esc(testId)}</code>.</div>`,
        dynamicMenuItems: STATS_ADMIN_MENU,
      })
    )
  }

  const testTitle = rows[0].test_title
  const testFile  = rows[0].test_file

  function fmtDuration(ms: number): string {
    const s = Math.round(ms / 1000)
    if (s < 60) return `${s}s`
    return `${Math.floor(s / 60)}m ${s % 60}s`
  }

  const statusBadge2 = (status: string, isFlaky: boolean) => {
    const map: Record<string, string> = {
      passed:      'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/30 dark:text-emerald-400',
      failed:      'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      timedOut:    'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      interrupted: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
      skipped:     'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400',
    }
    return `<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${map[status] ?? map.skipped}">${esc(status)}</span>`
      + (isFlaky ? ' <span class="ml-1 inline-flex items-center rounded-full px-1.5 py-0.5 text-xs font-medium bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400">flaky</span>' : '')
  }

  const trendDots = rows.slice(0, 30).reverse().map(r => {
    const isFlaky = r.is_flaky === 1 || r.is_flaky === true
    const color = r.status === 'passed' && !isFlaky ? '#10b981'
      : isFlaky ? '#f59e0b'
      : r.status === 'skipped' ? '#71717a'
      : '#ef4444'
    return `<span title="${esc(`${r.branch ?? ''} · ${r.status}${isFlaky ? ' (flaky)' : ''}`)}" style="display:inline-block;width:10px;height:10px;border-radius:50%;background:${color};flex-shrink:0"></span>`
  }).join('')

  const finalByRun = new Map<string, HistRow>()
  for (const r of rows) {
    const ex = finalByRun.get(r.run_id)
    if (!ex || r.retry > ex.retry) finalByRun.set(r.run_id, r)
  }
  const finals     = [...finalByRun.values()]
  const passCount  = finals.filter(r => r.status === 'passed').length
  const failCount  = finals.filter(r => r.status !== 'passed' && r.status !== 'skipped').length
  const flakyCount = finals.filter(r => r.is_flaky === 1 || r.is_flaky === true).length
  const passRate   = finals.length > 0 ? Math.round((passCount / finals.length) * 100) : 0

  const tableRows2 = rows.map(r => {
    const isFlaky = r.is_flaky === 1 || r.is_flaky === true
    const runLink = `<a href="/admin/playwright?run=${encodeURIComponent(r.run_id)}" onclick="event.stopPropagation()" class="font-mono text-xs text-indigo-600 dark:text-indigo-400 hover:underline">${esc(r.run_id.slice(0, 20))}</a>`
    const commitLink = r.ci_run_url
      ? `<a href="${esc(r.ci_run_url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()" class="font-mono text-xs hover:text-indigo-600 dark:hover:text-indigo-400">${esc(String(r.commit_sha ?? '').slice(0,7))}</a>`
      : `<span class="font-mono text-xs">${esc(String(r.commit_sha ?? '').slice(0,7))}</span>`
    return `<tr class="border-t border-zinc-950/5 dark:border-white/5">
      <td class="py-2 pr-3 text-xs text-zinc-400">${r.started_at ? new Date(r.started_at).toLocaleDateString() : '—'}</td>
      <td class="py-2 pr-3 font-mono text-xs text-zinc-600 dark:text-zinc-400">${esc(r.branch ?? '')}</td>
      <td class="py-2 pr-3">${commitLink}</td>
      <td class="py-2 pr-3">${statusBadge2(r.status, isFlaky)}</td>
      <td class="py-2 pr-3 text-right text-xs text-zinc-500">${fmtDuration(Number(r.duration_ms))}</td>
      <td class="py-2 pr-3 text-xs text-zinc-400 text-center">${r.retry > 0 ? `<span class="text-amber-500">#${r.retry}</span>` : '—'}</td>
      <td class="py-2 pr-3">${runLink}</td>
      <td class="py-2 text-xs text-red-500 dark:text-red-400 max-w-xs">${r.error_message ? `<span title="${esc(r.error_message)}">${esc(String(r.error_message).slice(0, 60))}${String(r.error_message).length > 60 ? '…' : ''}</span>` : ''}</td>
    </tr>`
  }).join('')

  const content = `
<div class="space-y-6">
  <nav class="flex items-center gap-2 text-sm text-zinc-500">
    <a href="/admin/playwright" class="hover:text-zinc-700 dark:hover:text-zinc-300">All runs</a>
    <svg class="h-4 w-4 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
    <span class="text-zinc-950 dark:text-white truncate max-w-xl">${esc(testTitle)}</span>
  </nav>

  <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
    <h1 class="text-xl font-semibold text-zinc-950 dark:text-white">${esc(testTitle)}</h1>
    <p class="mt-1 text-xs font-mono text-zinc-400">${esc(testFile)}</p>
    <div class="mt-4 flex items-center gap-1 flex-wrap">
      <span class="text-xs text-zinc-500 mr-1">Last ${Math.min(rows.length, 30)} runs (oldest → newest):</span>
      ${trendDots}
      <span class="ml-2 text-xs text-zinc-400">🟢 pass &nbsp;🟡 flaky &nbsp;🔴 fail &nbsp;⚫ skip</span>
    </div>
    <div class="mt-4 grid grid-cols-4 gap-4">
      <div class="text-center">
        <div class="text-2xl font-bold ${passRate >= 90 ? 'text-emerald-600 dark:text-emerald-400' : passRate >= 70 ? 'text-amber-600 dark:text-amber-400' : 'text-red-600 dark:text-red-400'}">${passRate}%</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Pass rate</div>
      </div>
      <div class="text-center">
        <div class="text-2xl font-bold ${failCount > 0 ? 'text-red-600 dark:text-red-400' : 'text-zinc-400'}">${failCount}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Failures</div>
      </div>
      <div class="text-center">
        <div class="text-2xl font-bold ${flakyCount > 0 ? 'text-amber-600 dark:text-amber-400' : 'text-zinc-400'}">${flakyCount}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Flaky</div>
      </div>
      <div class="text-center">
        <div class="text-2xl font-bold text-zinc-400">${finals.length}</div>
        <div class="text-xs text-zinc-500 uppercase tracking-wide">Runs seen</div>
      </div>
    </div>
  </div>

  <div class="rounded-lg bg-white dark:bg-zinc-800 ring-1 ring-zinc-950/5 dark:ring-white/10">
    <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
      <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Run History</h2>
      <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">${rows.length} result${rows.length !== 1 ? 's' : ''} including retries — newest first. Click Run to drill into that run.</p>
    </div>
    <div class="p-6 overflow-x-auto">
      <table class="w-full text-sm">
        <thead class="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          <tr>
            <th class="pb-2 text-left font-medium">When</th>
            <th class="pb-2 text-left font-medium">Branch</th>
            <th class="pb-2 text-left font-medium">Commit</th>
            <th class="pb-2 text-left font-medium">Status</th>
            <th class="pb-2 text-right font-medium pr-3">Duration</th>
            <th class="pb-2 text-center font-medium">Retry</th>
            <th class="pb-2 text-left font-medium">Run</th>
            <th class="pb-2 text-left font-medium">Error</th>
          </tr>
        </thead>
        <tbody>${tableRows2}</tbody>
      </table>
    </div>
  </div>
</div>`

  return c.html(
    renderAdminLayoutCatalyst({
      title: `Test: ${testTitle}`,
      pageTitle: 'Playwright CI/CD',
      currentPath: '/admin/playwright',
      version: c.get('appVersion'),
      user: user ? { name: user.email.split('@')[0] || 'Admin', email: user.email, role: user.role } : undefined,
      content,
      dynamicMenuItems: STATS_ADMIN_MENU,
    })
  )
}
