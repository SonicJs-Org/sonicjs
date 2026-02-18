/**
 * Admin Search Dashboard — Agent Tab
 *
 * Search Quality Agent: on-demand analysis engine that generates recommendations
 * across 5 categories, with an approval queue stored in D1.
 */

export function renderAgentTab(): string {
  return `
      <div id="tab-agent" class="tab-panel hidden">
        <div class="space-y-6">

          <!-- Header -->
          <div class="flex items-center justify-between">
            <div>
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Search Quality Agent</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">Automated analysis of search analytics to surface actionable improvements</p>
            </div>
            <div class="flex items-center gap-3">
              <span id="agent-run-badge" class="hidden inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium"></span>
              <button onclick="runAgentAnalysis()" id="agent-run-btn" type="button"
                class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed">
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
                </svg>
                Run Analysis
              </button>
            </div>
          </div>

          <!-- Stat Cards -->
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Pending</p>
                <p class="mt-1 text-2xl font-semibold text-amber-600 dark:text-amber-400" id="agent-stat-pending">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Applied</p>
                <p class="mt-1 text-2xl font-semibold text-lime-600 dark:text-lime-400" id="agent-stat-applied">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Dismissed</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-500 dark:text-zinc-400" id="agent-stat-dismissed">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Last Run</p>
                <p class="mt-1 text-lg font-semibold text-zinc-950 dark:text-white" id="agent-stat-lastrun">&mdash;</p>
              </div>
            </div>
          </div>

          <!-- Filter Bar -->
          <div class="flex items-center gap-3 flex-wrap">
            <select id="agent-filter-category" onchange="loadRecommendations()"
              class="rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 px-3 py-2">
              <option value="">All Categories</option>
              <option value="synonym">Synonym</option>
              <option value="query_rule">Query Rule</option>
              <option value="low_ctr">Low CTR</option>
              <option value="unused_facet">Unused Facet</option>
              <option value="content_gap">Content Gap</option>
              <option value="related_search">Related Search</option>
            </select>
            <select id="agent-filter-status" onchange="loadRecommendations()"
              class="rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-sm text-zinc-900 dark:text-zinc-100 px-3 py-2">
              <option value="pending">Pending</option>
              <option value="">All Statuses</option>
              <option value="applied">Applied</option>
              <option value="dismissed">Dismissed</option>
            </select>
            <button onclick="dismissAllPending()" type="button"
              class="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 hover:bg-zinc-50 dark:hover:bg-zinc-700">
              Dismiss All
            </button>
          </div>

          <!-- Recommendations List -->
          <div id="agent-recommendations-list" class="space-y-4">
            <div class="text-sm text-zinc-400 dark:text-zinc-500 text-center py-8">Run analysis to generate recommendations</div>
          </div>

          <!-- Run History (Collapsible) -->
          <details class="rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
            <summary class="px-6 py-4 cursor-pointer text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-white">
              Run History
            </summary>
            <div class="px-6 pb-4">
              <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
                  <thead class="bg-zinc-50 dark:bg-zinc-800/50">
                    <tr>
                      <th class="px-4 py-2 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase">Status</th>
                      <th class="px-4 py-2 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase">Recommendations</th>
                      <th class="px-4 py-2 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase">Duration</th>
                      <th class="px-4 py-2 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase">When</th>
                    </tr>
                  </thead>
                  <tbody id="agent-run-history-tbody" class="divide-y divide-zinc-950/5 dark:divide-white/10">
                    <tr><td colspan="4" class="px-4 py-3 text-sm text-zinc-400 dark:text-zinc-500 text-center">No runs yet</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </details>

        </div>
      </div>
  `
}

export function renderAgentScript(): string {
  return `
      // =============================================
      // Agent Tab
      // =============================================
      var agentLoaded = false;
      var agentPollTimer = null;

      // Hook into switchTab for lazy loading
      var _agentOrigSwitchTab = switchTab;
      switchTab = function(tabId) {
        _agentOrigSwitchTab(tabId);
        if (tabId === 'agent' && !agentLoaded) {
          agentLoaded = true;
          loadAgentStatus();
          loadRecommendations();
          loadRunHistory();
        }
      };

      function agentBasePath() {
        return '/admin/plugins/ai-search/api/agent';
      }

      async function loadAgentStatus() {
        try {
          var res = await fetch(agentBasePath() + '/status');
          if (!res.ok) throw new Error('Failed');
          var json = await res.json();
          if (!json.success) throw new Error(json.error || 'Unknown');
          var d = json.data;

          document.getElementById('agent-stat-pending').textContent = d.stats.pending;
          document.getElementById('agent-stat-applied').textContent = d.stats.applied;
          document.getElementById('agent-stat-dismissed').textContent = d.stats.dismissed;

          if (d.latest_run) {
            var badge = document.getElementById('agent-run-badge');
            var statusColors = {
              running: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
              completed: 'bg-lime-100 dark:bg-lime-900/30 text-lime-700 dark:text-lime-300',
              failed: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'
            };
            badge.className = 'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ' + (statusColors[d.latest_run.status] || '');
            badge.textContent = d.latest_run.status;
            badge.classList.remove('hidden');

            var lastRunEl = document.getElementById('agent-stat-lastrun');
            if (d.latest_run.duration_ms) {
              lastRunEl.textContent = (d.latest_run.duration_ms / 1000).toFixed(1) + 's';
            } else if (d.latest_run.status === 'running') {
              lastRunEl.textContent = 'Running...';
            } else {
              lastRunEl.textContent = 'N/A';
            }

            // Enable/disable run button
            var btn = document.getElementById('agent-run-btn');
            btn.disabled = d.latest_run.status === 'running';
          }
        } catch (e) {
          console.error('Agent status error:', e);
        }
      }

      async function loadRecommendations() {
        var category = document.getElementById('agent-filter-category').value;
        var status = document.getElementById('agent-filter-status').value;
        var params = new URLSearchParams();
        if (category) params.set('category', category);
        if (status) params.set('status', status);

        var container = document.getElementById('agent-recommendations-list');
        try {
          var res = await fetch(agentBasePath() + '/recommendations?' + params.toString());
          if (!res.ok) throw new Error('Failed');
          var json = await res.json();
          if (!json.success) throw new Error(json.error || 'Unknown');

          var recs = json.data;
          if (!recs || recs.length === 0) {
            container.innerHTML = '<div class="text-sm text-zinc-400 dark:text-zinc-500 text-center py-8">No recommendations found</div>';
            return;
          }

          var categoryColors = {
            synonym: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
            query_rule: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
            low_ctr: 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300',
            unused_facet: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
            content_gap: 'bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300',
            related_search: 'bg-teal-100 dark:bg-teal-900/30 text-teal-700 dark:text-teal-300'
          };
          var categoryLabels = {
            synonym: 'Synonym',
            query_rule: 'Query Rule',
            low_ctr: 'Low CTR',
            unused_facet: 'Unused Facet',
            content_gap: 'Content Gap',
            related_search: 'Related Search'
          };

          var html = '';
          for (var i = 0; i < recs.length; i++) {
            var r = recs[i];
            var catColor = categoryColors[r.category] || '';
            var catLabel = categoryLabels[r.category] || r.category;
            var canApply = (r.status === 'pending');
            var isActionable = (r.category === 'synonym' || r.category === 'query_rule');

            html += '<div class="rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 p-5">';
            html += '<div class="flex items-start justify-between gap-4">';
            html += '<div class="flex-1 min-w-0">';

            // Category badge + status
            html += '<div class="flex items-center gap-2 mb-2">';
            html += '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ' + catColor + '">' + escapeAgentHtml(catLabel) + '</span>';
            if (r.status !== 'pending') {
              var statusColor = r.status === 'applied' ? 'text-lime-600 dark:text-lime-400' : 'text-zinc-400 dark:text-zinc-500';
              html += '<span class="text-xs ' + statusColor + '">' + r.status + '</span>';
            }
            html += '</div>';

            // Title + description
            html += '<h3 class="text-sm font-medium text-zinc-950 dark:text-white truncate">' + escapeAgentHtml(r.title) + '</h3>';
            html += '<p class="text-sm text-zinc-600 dark:text-zinc-400 mt-1">' + escapeAgentHtml(r.description) + '</p>';

            // Supporting data badges
            var sd = r.supporting_data || {};
            var sdKeys = Object.keys(sd);
            if (sdKeys.length > 0) {
              html += '<div class="flex flex-wrap gap-1.5 mt-2">';
              for (var k = 0; k < sdKeys.length; k++) {
                var key = sdKeys[k];
                var val = sd[key];
                html += '<span class="inline-flex items-center rounded px-1.5 py-0.5 text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">' + escapeAgentHtml(key.replace(/_/g, ' ')) + ': ' + escapeAgentHtml(String(val)) + '</span>';
              }
              html += '</div>';
            }

            html += '</div>'; // end flex-1

            // Action buttons
            if (canApply) {
              html += '<div class="flex items-center gap-2 flex-shrink-0">';
              if (isActionable) {
                html += '<button onclick="applyRecommendation(' + "'" + r.id + "'" + ')" class="inline-flex items-center rounded-lg px-3 py-1.5 text-xs font-medium text-white bg-lime-600 hover:bg-lime-700">Apply</button>';
              } else {
                html += '<button onclick="applyRecommendation(' + "'" + r.id + "'" + ')" class="inline-flex items-center rounded-lg px-3 py-1.5 text-xs font-medium text-white bg-lime-600 hover:bg-lime-700">Acknowledge</button>';
              }
              html += '<button onclick="dismissRecommendation(' + "'" + r.id + "'" + ')" class="inline-flex items-center rounded-lg px-3 py-1.5 text-xs font-medium text-zinc-600 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800 hover:bg-zinc-200 dark:hover:bg-zinc-700">Dismiss</button>';
              html += '</div>';
            }

            html += '</div>'; // end flex
            html += '</div>'; // end card
          }
          container.innerHTML = html;
        } catch (e) {
          console.error('Load recommendations error:', e);
          container.innerHTML = '<div class="text-sm text-red-500 text-center py-8">Failed to load recommendations</div>';
        }
      }

      async function runAgentAnalysis() {
        var btn = document.getElementById('agent-run-btn');
        btn.disabled = true;
        btn.textContent = 'Running...';

        try {
          var res = await fetch(agentBasePath() + '/run', { method: 'POST' });
          if (!res.ok) throw new Error('Failed to start analysis');
          var json = await res.json();
          if (!json.success) throw new Error(json.error || 'Unknown');

          // Poll until complete
          agentPollTimer = setInterval(async function() {
            try {
              var statusRes = await fetch(agentBasePath() + '/status');
              var statusJson = await statusRes.json();
              if (statusJson.success && statusJson.data.latest_run) {
                var run = statusJson.data.latest_run;
                if (run.status !== 'running') {
                  clearInterval(agentPollTimer);
                  agentPollTimer = null;
                  btn.disabled = false;
                  btn.innerHTML = '<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg> Run Analysis';

                  if (run.status === 'completed') {
                    showAgentToast('Analysis complete: ' + run.recommendations_count + ' recommendations');
                  } else {
                    showAgentToast('Analysis failed: ' + (run.error_message || 'Unknown error'), true);
                  }

                  loadAgentStatus();
                  loadRecommendations();
                  loadRunHistory();
                }
              }
            } catch (e) {
              console.error('Poll error:', e);
            }
          }, 2000);
        } catch (e) {
          btn.disabled = false;
          btn.innerHTML = '<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg> Run Analysis';
          showAgentToast('Failed to start analysis', true);
        }
      }

      async function applyRecommendation(id) {
        try {
          var res = await fetch(agentBasePath() + '/recommendations/' + id + '/apply', { method: 'POST' });
          var json = await res.json();
          if (json.success) {
            showAgentToast(json.message || 'Applied');
          } else {
            showAgentToast(json.error || 'Failed', true);
          }
          loadAgentStatus();
          loadRecommendations();
        } catch (e) {
          showAgentToast('Failed to apply', true);
        }
      }

      async function dismissRecommendation(id) {
        try {
          await fetch(agentBasePath() + '/recommendations/' + id + '/dismiss', { method: 'POST' });
          loadAgentStatus();
          loadRecommendations();
        } catch (e) {
          showAgentToast('Failed to dismiss', true);
        }
      }

      async function dismissAllPending() {
        try {
          var res = await fetch(agentBasePath() + '/recommendations/dismiss-all', { method: 'POST' });
          var json = await res.json();
          if (json.success) {
            showAgentToast('Dismissed ' + (json.data?.dismissed || 'all') + ' recommendations');
          }
          loadAgentStatus();
          loadRecommendations();
        } catch (e) {
          showAgentToast('Failed to dismiss all', true);
        }
      }

      async function loadRunHistory() {
        try {
          var res = await fetch(agentBasePath() + '/runs');
          if (!res.ok) return;
          var json = await res.json();
          if (!json.success || !json.data || json.data.length === 0) return;

          var tbody = document.getElementById('agent-run-history-tbody');
          var html = '';
          var now = Date.now();
          for (var i = 0; i < json.data.length; i++) {
            var run = json.data[i];
            var statusClass = run.status === 'completed' ? 'text-lime-600 dark:text-lime-400'
              : run.status === 'failed' ? 'text-red-600 dark:text-red-400'
              : 'text-blue-600 dark:text-blue-400';
            var duration = run.duration_ms ? (run.duration_ms / 1000).toFixed(1) + 's' : '—';
            var ago = formatAgentTimeAgo(now - (run.created_at * 1000));

            html += '<tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">';
            html += '<td class="px-4 py-2 text-sm ' + statusClass + ' font-medium">' + run.status + '</td>';
            html += '<td class="px-4 py-2 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + run.recommendations_count + '</td>';
            html += '<td class="px-4 py-2 text-sm text-zinc-600 dark:text-zinc-400 text-right font-mono">' + duration + '</td>';
            html += '<td class="px-4 py-2 text-sm text-zinc-500 dark:text-zinc-400 text-right whitespace-nowrap">' + ago + '</td>';
            html += '</tr>';
          }
          tbody.innerHTML = html;
        } catch (e) {
          console.error('Load run history error:', e);
        }
      }

      function showAgentToast(message, isError) {
        var el = document.getElementById('msg');
        if (!el) return;
        el.querySelector('.font-semibold').textContent = message;
        if (isError) {
          el.className = 'fixed bottom-4 right-4 p-4 rounded-lg bg-red-50 text-red-900 border border-red-200 dark:bg-red-900/20 dark:text-red-100 dark:border-red-800 shadow-lg z-50';
        } else {
          el.className = 'fixed bottom-4 right-4 p-4 rounded-lg bg-green-50 text-green-900 border border-green-200 dark:bg-green-900/20 dark:text-green-100 dark:border-green-800 shadow-lg z-50';
        }
        el.classList.remove('hidden');
        setTimeout(function() { el.classList.add('hidden'); }, 3000);
      }

      function escapeAgentHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      }

      function formatAgentTimeAgo(ms) {
        var sec = Math.floor(ms / 1000);
        if (sec < 60) return 'just now';
        var min = Math.floor(sec / 60);
        if (min < 60) return min + 'm ago';
        var hr = Math.floor(min / 60);
        if (hr < 24) return hr + 'h ago';
        var days = Math.floor(hr / 24);
        return days + 'd ago';
      }

      // Auto-load if we navigated directly to #agent
      if (initTab === 'agent') {
        agentLoaded = true;
        loadAgentStatus();
        loadRecommendations();
        loadRunHistory();
      }
  `
}
