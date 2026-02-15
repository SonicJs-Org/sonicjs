/**
 * Admin Search Dashboard — Analytics Tab
 *
 * Chart.js charts (daily queries, mode distribution, CTR, facet clicks),
 * query tables, click analytics, and facet analytics.
 */

export function renderAnalyticsTab(): string {
  return `
      <div id="tab-analytics" class="tab-panel hidden">
        <div class="space-y-6">

          <!-- Stat Cards -->
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Total Queries (30d)</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-total-queries">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Avg Response Time</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-avg-time">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Zero-Result Rate</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-zero-rate">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Queries Today</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-today">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Click-Through Rate (30d)</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-ctr">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Avg Click Position</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-avg-pos">&mdash;</p>
              </div>
            </div>
          </div>

          <!-- Charts Row: two-column -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Queries Over Time -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Queries Over Time</h3>
              <div style="height: 260px; position: relative;">
                <canvas id="ana-daily-chart"></canvas>
              </div>
            </div>

            <!-- Mode Distribution -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Mode Distribution</h3>
              <div style="height: 260px; position: relative;" class="flex items-center justify-center">
                <canvas id="ana-mode-chart"></canvas>
              </div>
            </div>
          </div>

          <!-- CTR Over Time Chart -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Click-Through Rate Over Time</h3>
            <div style="height: 260px; position: relative;">
              <canvas id="ana-ctr-chart"></canvas>
            </div>
          </div>

          <!-- Facet Analytics Section -->
          <div class="pt-2">
            <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Facet Analytics</h3>

            <!-- Facet stat card -->
            <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 mb-6">
              <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
                <div class="p-5">
                  <p class="text-sm text-zinc-600 dark:text-zinc-400">Facet Clicks (30d)</p>
                  <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="ana-facet-clicks">&mdash;</p>
                </div>
              </div>
            </div>

            <!-- Facet clicks over time chart -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Facet Clicks Over Time</h3>
              <div style="height: 220px; position: relative;">
                <canvas id="ana-facet-chart"></canvas>
              </div>
            </div>

            <!-- Facet tables: two-column -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <!-- Top Facet Fields -->
              <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
                <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                  <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Most Used Facets</h3>
                  <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Which facet filters users click most (30 days)</p>
                </div>
                <div class="overflow-x-auto">
                  <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                    <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                      <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Facet Field</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Clicks</th>
                      </tr>
                    </thead>
                    <tbody id="ana-facet-fields-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                      <tr><td colspan="2" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <!-- Top Facet Values -->
              <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
                <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                  <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Top Facet Values</h3>
                  <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Most clicked filter values (30 days)</p>
                </div>
                <div class="overflow-x-auto">
                  <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                    <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                      <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Facet</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Value</th>
                        <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Clicks</th>
                      </tr>
                    </thead>
                    <tbody id="ana-facet-values-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                      <tr><td colspan="3" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>

          <!-- Tables Row: two-column -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Popular Queries -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Popular Queries</h3>
              </div>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                  <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                    <tr>
                      <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Query</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Count</th>
                    </tr>
                  </thead>
                  <tbody id="ana-popular-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                    <tr><td colspan="2" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Zero-Result Queries -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Zero-Result Queries</h3>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Content gaps — what users search for but can't find</p>
              </div>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                  <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                    <tr>
                      <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Query</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Count</th>
                    </tr>
                  </thead>
                  <tbody id="ana-zero-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                    <tr><td colspan="2" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- Click Analytics Tables -->
          <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <!-- Most Clicked Content -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Most Clicked Content</h3>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Top content by click count (30 days)</p>
              </div>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                  <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                    <tr>
                      <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Content</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Clicks</th>
                    </tr>
                  </thead>
                  <tbody id="ana-clicked-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                    <tr><td colspan="2" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Searches With No Clicks -->
            <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
                <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Searches With No Clicks</h3>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Queries that returned results but users didn't click</p>
              </div>
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                  <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                    <tr>
                      <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Query</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Searches</th>
                      <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Avg Results</th>
                    </tr>
                  </thead>
                  <tbody id="ana-noclick-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                    <tr><td colspan="3" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          <!-- Recent Queries: full-width -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Recent Queries</h3>
            </div>
            <div class="overflow-x-auto">
              <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                  <tr>
                    <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Query</th>
                    <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Mode</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Results</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Time</th>
                    <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">When</th>
                  </tr>
                </thead>
                <tbody id="ana-recent-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                  <tr><td colspan="5" class="px-6 py-4 text-sm text-zinc-400 dark:text-zinc-500">Loading...</td></tr>
                </tbody>
              </table>
            </div>
          </div>

        </div>
      </div>
  `
}

export function renderAnalyticsScript(): string {
  return `
      // =============================================
      // Analytics Tab
      // =============================================
      var analyticsLoaded = false;
      var dailyChart = null;
      var modeChart = null;
      var ctrChart = null;

      // Extend switchTab to trigger lazy loading
      var _origSwitchTab = switchTab;
      switchTab = function(tabId) {
        _origSwitchTab(tabId);
        if (tabId === 'analytics' && !analyticsLoaded) {
          loadAnalytics();
        }
        if (tabId === 'configuration') {
          loadFacetConfig();
        }
      };

      async function loadAnalytics() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/analytics/extended');
          if (!res.ok) throw new Error('Failed to fetch analytics');
          var json = await res.json();
          if (!json.success) throw new Error(json.error || 'Unknown error');
          var d = json.data;
          analyticsLoaded = true;

          // Stat cards
          document.getElementById('ana-total-queries').textContent = d.total_queries.toLocaleString();
          document.getElementById('ana-avg-time').textContent = d.avg_response_time_ms > 0 ? d.avg_response_time_ms + 'ms' : 'N/A';
          document.getElementById('ana-zero-rate').textContent = d.zero_result_rate + '%';
          document.getElementById('ana-today').textContent = d.queries_today.toLocaleString();

          // Daily chart
          renderDailyChart(d.daily_counts);

          // Mode chart
          renderModeChart(d);

          // Popular queries table
          renderQueryTable('ana-popular-tbody', d.popular_queries, false);

          // Zero-result queries table
          renderQueryTable('ana-zero-tbody', d.zero_result_queries, true);

          // Recent queries table
          renderRecentTable(d.recent_queries);

          // Click analytics
          document.getElementById('ana-ctr').textContent = d.total_clicks_30d > 0 ? d.ctr_30d + '%' : 'No data';
          document.getElementById('ana-avg-pos').textContent = d.avg_click_position_30d > 0 ? d.avg_click_position_30d.toFixed(1) : 'No data';

          // CTR over time chart
          renderCtrChart(d.ctr_over_time);

          // Most clicked content table
          renderClickedTable(d.most_clicked_content);

          // No-click searches table
          renderNoClickTable(d.no_click_searches);

          // Facet analytics
          document.getElementById('ana-facet-clicks').textContent =
            d.total_facet_clicks_30d > 0 ? d.total_facet_clicks_30d.toLocaleString() : 'No data';
          renderFacetClicksChart(d.facet_clicks_over_time || []);
          renderFacetFieldsTable(d.top_facet_fields || []);
          renderFacetValuesTable(d.top_facet_values || []);

        } catch (e) {
          console.error('Analytics load error:', e);
          document.getElementById('ana-total-queries').textContent = 'Error';
        }
      }

      function renderDailyChart(dailyCounts) {
        var canvas = document.getElementById('ana-daily-chart');
        if (!canvas || typeof Chart === 'undefined') return;

        // Fill in missing days with 0
        var labels = [];
        var data = [];
        var countMap = {};
        for (var i = 0; i < dailyCounts.length; i++) {
          countMap[dailyCounts[i].date] = dailyCounts[i].count;
        }
        var now = new Date();
        for (var d = 29; d >= 0; d--) {
          var dt = new Date(now);
          dt.setDate(dt.getDate() - d);
          var key = dt.toISOString().split('T')[0];
          labels.push(dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
          data.push(countMap[key] || 0);
        }

        var isDark = document.documentElement.classList.contains('dark');
        var gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        var textColor = isDark ? '#a1a1aa' : '#71717a';

        if (dailyChart) dailyChart.destroy();
        dailyChart = new Chart(canvas, {
          type: 'line',
          data: {
            labels: labels,
            datasets: [{
              label: 'Queries',
              data: data,
              borderColor: '#6366f1',
              backgroundColor: isDark ? 'rgba(99,102,241,0.15)' : 'rgba(99,102,241,0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              pointRadius: 0,
              pointHoverRadius: 5,
              pointHoverBackgroundColor: '#6366f1'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: isDark ? '#27272a' : '#fff',
                titleColor: isDark ? '#e4e4e7' : '#18181b',
                bodyColor: isDark ? '#a1a1aa' : '#52525b',
                borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                borderWidth: 1
              }
            },
            scales: {
              x: {
                grid: { color: gridColor },
                ticks: { color: textColor, maxTicksLimit: 8, font: { size: 11 } }
              },
              y: {
                beginAtZero: true,
                grid: { color: gridColor },
                ticks: { color: textColor, font: { size: 11 }, precision: 0 }
              }
            }
          }
        });
      }

      function renderModeChart(d) {
        var canvas = document.getElementById('ana-mode-chart');
        if (!canvas || typeof Chart === 'undefined') return;

        var total = d.fts5_queries + d.keyword_queries + d.ai_queries + d.hybrid_queries;
        if (total === 0) {
          canvas.parentElement.innerHTML = '<p class="text-sm text-zinc-400 dark:text-zinc-500">No search data yet</p>';
          return;
        }

        var isDark = document.documentElement.classList.contains('dark');

        if (modeChart) modeChart.destroy();
        modeChart = new Chart(canvas, {
          type: 'doughnut',
          data: {
            labels: ['FTS5', 'Keyword', 'AI', 'Hybrid'],
            datasets: [{
              data: [d.fts5_queries, d.keyword_queries, d.ai_queries, d.hybrid_queries],
              backgroundColor: ['#6366f1', '#71717a', '#06b6d4', '#a855f7'],
              borderColor: isDark ? '#18181b' : '#ffffff',
              borderWidth: 2
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: isDark ? '#a1a1aa' : '#52525b',
                  padding: 16,
                  usePointStyle: true,
                  pointStyleWidth: 10,
                  font: { size: 12 }
                }
              },
              tooltip: {
                backgroundColor: isDark ? '#27272a' : '#fff',
                titleColor: isDark ? '#e4e4e7' : '#18181b',
                bodyColor: isDark ? '#a1a1aa' : '#52525b',
                borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                borderWidth: 1,
                callbacks: {
                  label: function(ctx) {
                    var val = ctx.parsed;
                    var pct = total > 0 ? Math.round((val / total) * 100) : 0;
                    return ctx.label + ': ' + val + ' (' + pct + '%)';
                  }
                }
              }
            },
            cutout: '60%'
          }
        });
      }

      function escapeAnalyticsHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      }

      function renderQueryTable(tbodyId, queries, isZeroResult) {
        var tbody = document.getElementById(tbodyId);
        if (!tbody) return;

        if (!queries || queries.length === 0) {
          tbody.innerHTML = '<tr><td colspan="2" class="px-6 py-8 text-sm text-zinc-400 dark:text-zinc-500 text-center">' +
            (isZeroResult ? 'No zero-result queries found' : 'No search data yet') + '</td></tr>';
          return;
        }

        var html = '';
        for (var i = 0; i < queries.length; i++) {
          var q = queries[i];
          html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">' +
            '<td class="px-6 py-3 text-sm text-zinc-900 dark:text-zinc-100">' + escapeAnalyticsHtml(q.query) + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + q.count + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      }

      function renderRecentTable(queries) {
        var tbody = document.getElementById('ana-recent-tbody');
        if (!tbody) return;

        if (!queries || queries.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-8 text-sm text-zinc-400 dark:text-zinc-500 text-center">No recent queries</td></tr>';
          return;
        }

        var modeColors = {
          fts5: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300',
          keyword: 'bg-zinc-100 dark:bg-zinc-700/50 text-zinc-700 dark:text-zinc-300',
          ai: 'bg-cyan-100 dark:bg-cyan-900/30 text-cyan-700 dark:text-cyan-300',
          hybrid: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300'
        };

        var html = '';
        var now = Date.now();
        for (var i = 0; i < queries.length; i++) {
          var q = queries[i];
          var modeClass = modeColors[q.mode] || modeColors.keyword;
          var timeStr = q.response_time_ms != null ? q.response_time_ms + 'ms' : '—';
          var ago = formatTimeAgo(now - q.created_at);

          html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">' +
            '<td class="px-6 py-3 text-sm text-zinc-900 dark:text-zinc-100 max-w-xs truncate">' + escapeAnalyticsHtml(q.query) + '</td>' +
            '<td class="px-6 py-3"><span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ' + modeClass + '">' + q.mode + '</span></td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + q.results_count + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + timeStr + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-500 dark:text-zinc-400 text-right whitespace-nowrap">' + ago + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      }

      function renderCtrChart(ctrData) {
        var canvas = document.getElementById('ana-ctr-chart');
        if (!canvas || typeof Chart === 'undefined') return;

        if (!ctrData || ctrData.length === 0) {
          canvas.parentElement.innerHTML = '<p class="text-sm text-zinc-400 dark:text-zinc-500 text-center" style="padding-top:100px">No click data yet</p>';
          return;
        }

        // Fill in missing days with 0
        var labels = [];
        var data = [];
        var ctrMap = {};
        for (var i = 0; i < ctrData.length; i++) {
          ctrMap[ctrData[i].date] = ctrData[i].ctr;
        }
        var now = new Date();
        for (var d = 29; d >= 0; d--) {
          var dt = new Date(now);
          dt.setDate(dt.getDate() - d);
          var key = dt.toISOString().split('T')[0];
          labels.push(dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
          data.push(ctrMap[key] || 0);
        }

        var isDark = document.documentElement.classList.contains('dark');
        var gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        var textColor = isDark ? '#a1a1aa' : '#71717a';

        if (ctrChart) ctrChart.destroy();
        ctrChart = new Chart(canvas, {
          type: 'line',
          data: {
            labels: labels,
            datasets: [{
              label: 'CTR %',
              data: data,
              borderColor: '#10b981',
              backgroundColor: isDark ? 'rgba(16,185,129,0.15)' : 'rgba(16,185,129,0.1)',
              borderWidth: 2,
              fill: true,
              tension: 0.3,
              pointRadius: 0,
              pointHoverRadius: 5,
              pointHoverBackgroundColor: '#10b981'
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: isDark ? '#27272a' : '#fff',
                titleColor: isDark ? '#e4e4e7' : '#18181b',
                bodyColor: isDark ? '#a1a1aa' : '#52525b',
                borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                borderWidth: 1,
                callbacks: {
                  label: function(ctx) { return 'CTR: ' + ctx.parsed.y.toFixed(1) + '%'; }
                }
              }
            },
            scales: {
              x: {
                grid: { color: gridColor },
                ticks: { color: textColor, maxTicksLimit: 8, font: { size: 11 } }
              },
              y: {
                beginAtZero: true,
                grid: { color: gridColor },
                ticks: { color: textColor, font: { size: 11 }, callback: function(v) { return v + '%'; } }
              }
            }
          }
        });
      }

      function renderClickedTable(items) {
        var tbody = document.getElementById('ana-clicked-tbody');
        if (!tbody) return;

        if (!items || items.length === 0) {
          tbody.innerHTML = '<tr><td colspan="2" class="px-6 py-8 text-sm text-zinc-400 dark:text-zinc-500 text-center">No click data yet</td></tr>';
          return;
        }

        var html = '';
        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">' +
            '<td class="px-6 py-3 text-sm text-zinc-900 dark:text-zinc-100 max-w-xs truncate">' + escapeAnalyticsHtml(item.content_title) + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + item.click_count + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      }

      function renderNoClickTable(items) {
        var tbody = document.getElementById('ana-noclick-tbody');
        if (!tbody) return;

        if (!items || items.length === 0) {
          tbody.innerHTML = '<tr><td colspan="3" class="px-6 py-8 text-sm text-zinc-400 dark:text-zinc-500 text-center">No data yet — all searches got clicks!</td></tr>';
          return;
        }

        var html = '';
        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">' +
            '<td class="px-6 py-3 text-sm text-zinc-900 dark:text-zinc-100 max-w-xs truncate">' + escapeAnalyticsHtml(item.query) + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + item.search_count + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + item.results_count_avg + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      }

      var facetClicksChart = null;

      function renderFacetClicksChart(dailyCounts) {
        var canvas = document.getElementById('ana-facet-chart');
        if (!canvas || typeof Chart === 'undefined') return;

        if (!dailyCounts || dailyCounts.length === 0) {
          canvas.parentElement.innerHTML = '<p class="text-sm text-zinc-400 dark:text-zinc-500">No facet click data yet</p>';
          return;
        }

        var labels = [];
        var data = [];
        var countMap = {};
        for (var i = 0; i < dailyCounts.length; i++) {
          countMap[dailyCounts[i].date] = dailyCounts[i].count;
        }
        var now = new Date();
        for (var dd = 29; dd >= 0; dd--) {
          var dt = new Date(now);
          dt.setDate(dt.getDate() - dd);
          var key = dt.toISOString().split('T')[0];
          labels.push(dt.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
          data.push(countMap[key] || 0);
        }

        var isDark = document.documentElement.classList.contains('dark');
        var gridColor = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
        var textColor = isDark ? '#a1a1aa' : '#71717a';

        if (facetClicksChart) facetClicksChart.destroy();
        facetClicksChart = new Chart(canvas, {
          type: 'bar',
          data: {
            labels: labels,
            datasets: [{
              label: 'Facet Clicks',
              data: data,
              backgroundColor: isDark ? 'rgba(168,85,247,0.4)' : 'rgba(168,85,247,0.6)',
              borderColor: '#a855f7',
              borderWidth: 1,
              borderRadius: 3
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: {
                backgroundColor: isDark ? '#27272a' : '#fff',
                titleColor: isDark ? '#e4e4e7' : '#18181b',
                bodyColor: isDark ? '#a1a1aa' : '#52525b',
                borderColor: isDark ? '#3f3f46' : '#e4e4e7',
                borderWidth: 1
              }
            },
            scales: {
              x: { grid: { color: gridColor }, ticks: { color: textColor, maxTicksLimit: 8, font: { size: 11 } } },
              y: { beginAtZero: true, grid: { color: gridColor }, ticks: { color: textColor, font: { size: 11 }, precision: 0 } }
            }
          }
        });
      }

      function renderFacetFieldsTable(items) {
        var tbody = document.getElementById('ana-facet-fields-tbody');
        if (!tbody) return;

        if (!items || items.length === 0) {
          tbody.innerHTML = '<tr><td colspan="2" class="px-6 py-8 text-sm text-zinc-400 dark:text-zinc-500 text-center">No facet click data yet</td></tr>';
          return;
        }

        var html = '';
        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          var displayName = item.facet_field;
          if (displayName.startsWith('$.')) displayName = displayName.slice(2);
          displayName = displayName.charAt(0).toUpperCase() + displayName.slice(1);
          html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">' +
            '<td class="px-6 py-3 text-sm text-zinc-900 dark:text-zinc-100">' + escapeAnalyticsHtml(displayName) + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + item.click_count + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      }

      function renderFacetValuesTable(items) {
        var tbody = document.getElementById('ana-facet-values-tbody');
        if (!tbody) return;

        if (!items || items.length === 0) {
          tbody.innerHTML = '<tr><td colspan="3" class="px-6 py-8 text-sm text-zinc-400 dark:text-zinc-500 text-center">No facet click data yet</td></tr>';
          return;
        }

        var html = '';
        for (var i = 0; i < items.length; i++) {
          var item = items[i];
          var fieldDisplay = item.facet_field;
          if (fieldDisplay.startsWith('$.')) fieldDisplay = fieldDisplay.slice(2);
          fieldDisplay = fieldDisplay.charAt(0).toUpperCase() + fieldDisplay.slice(1);
          html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">' +
            '<td class="px-6 py-3 text-sm text-zinc-500 dark:text-zinc-400">' + escapeAnalyticsHtml(fieldDisplay) + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-900 dark:text-zinc-100">' + escapeAnalyticsHtml(item.facet_value) + '</td>' +
            '<td class="px-6 py-3 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + item.click_count + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
      }

      function formatTimeAgo(ms) {
        var sec = Math.floor(ms / 1000);
        if (sec < 60) return 'just now';
        var min = Math.floor(sec / 60);
        if (min < 60) return min + 'm ago';
        var hr = Math.floor(min / 60);
        if (hr < 24) return hr + 'h ago';
        var days = Math.floor(hr / 24);
        return days + 'd ago';
      }

      // Auto-load if we navigated directly to #analytics
      if (initTab === 'analytics') {
        loadAnalytics();
      }
  `
}
