/**
 * Admin Search Dashboard — Experiments Tab
 *
 * A/B testing and interleaving experiments: create, manage, and analyze
 * search experiments with live metrics and statistical significance.
 */

export function renderExperimentsTab(): string {
  return `
      <div id="tab-experiments" class="tab-panel hidden">
        <div class="space-y-6">

          <!-- Header -->
          <div class="flex items-center justify-between">
            <div>
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Search Experiments</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">A/B test and interleave search configurations to measure what works best</p>
            </div>
            <div class="flex items-center gap-3">
              <button onclick="openCreateExperiment()" type="button"
                class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700">
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                </svg>
                New Experiment
              </button>
            </div>
          </div>

          <!-- Active Experiment Banner -->
          <div id="exp-active-banner" class="hidden rounded-xl bg-indigo-50 dark:bg-indigo-950/30 ring-1 ring-indigo-200 dark:ring-indigo-800 p-5">
            <div class="flex items-center justify-between">
              <div>
                <div class="flex items-center gap-2">
                  <span class="relative flex h-2.5 w-2.5">
                    <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-indigo-400 opacity-75"></span>
                    <span class="relative inline-flex rounded-full h-2.5 w-2.5 bg-indigo-500"></span>
                  </span>
                  <span class="text-sm font-semibold text-indigo-700 dark:text-indigo-300" id="exp-active-name">—</span>
                  <span id="exp-active-mode-badge" class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-indigo-100 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">A/B</span>
                </div>
                <p class="mt-1 text-xs text-indigo-600 dark:text-indigo-400" id="exp-active-desc">—</p>
              </div>
              <div class="flex items-center gap-6">
                <!-- Live metrics summary -->
                <div class="text-right">
                  <div class="flex items-center gap-4 text-xs">
                    <div>
                      <span class="text-zinc-500 dark:text-zinc-400">Searches</span>
                      <span class="ml-1 font-semibold text-zinc-900 dark:text-white" id="exp-active-searches">0</span>
                    </div>
                    <div>
                      <span class="text-zinc-500 dark:text-zinc-400">Confidence</span>
                      <span class="ml-1 font-semibold text-zinc-900 dark:text-white" id="exp-active-confidence">0%</span>
                    </div>
                  </div>
                  <!-- Confidence progress bar -->
                  <div class="mt-1 h-1.5 w-40 rounded-full bg-zinc-200 dark:bg-zinc-700">
                    <div id="exp-active-confidence-bar" class="h-1.5 rounded-full bg-indigo-500 transition-all" style="width: 0%"></div>
                  </div>
                </div>
                <div class="flex items-center gap-2">
                  <button onclick="pauseExperiment()" type="button"
                    class="rounded-lg px-3 py-1.5 text-xs font-medium text-amber-700 bg-amber-100 hover:bg-amber-200 dark:text-amber-300 dark:bg-amber-900/30 dark:hover:bg-amber-900/50">
                    Pause
                  </button>
                  <button onclick="completeExperiment()" type="button"
                    class="rounded-lg px-3 py-1.5 text-xs font-medium text-red-700 bg-red-100 hover:bg-red-200 dark:text-red-300 dark:bg-red-900/30 dark:hover:bg-red-900/50">
                    Stop
                  </button>
                </div>
              </div>
            </div>

            <!-- Variant comparison -->
            <div id="exp-active-metrics" class="hidden mt-4 grid grid-cols-2 gap-4">
              <div class="rounded-lg bg-white dark:bg-zinc-900 p-3 ring-1 ring-zinc-200 dark:ring-zinc-700">
                <p class="text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-2">Control</p>
                <div class="grid grid-cols-3 gap-2 text-center">
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-ctrl-ctr">—</p>
                    <p class="text-[10px] text-zinc-500">CTR</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-ctrl-zero">—</p>
                    <p class="text-[10px] text-zinc-500">Zero-Result</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-ctrl-pos">—</p>
                    <p class="text-[10px] text-zinc-500">Avg Position</p>
                  </div>
                </div>
              </div>
              <div class="rounded-lg bg-white dark:bg-zinc-900 p-3 ring-1 ring-zinc-200 dark:ring-zinc-700">
                <p class="text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-2">Treatment</p>
                <div class="grid grid-cols-3 gap-2 text-center">
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-treat-ctr">—</p>
                    <p class="text-[10px] text-zinc-500">CTR</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-treat-zero">—</p>
                    <p class="text-[10px] text-zinc-500">Zero-Result</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-treat-pos">—</p>
                    <p class="text-[10px] text-zinc-500">Avg Position</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Stat Cards -->
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Total Experiments</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white" id="exp-stat-total">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Running</p>
                <p class="mt-1 text-2xl font-semibold text-indigo-600 dark:text-indigo-400" id="exp-stat-running">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Completed</p>
                <p class="mt-1 text-2xl font-semibold text-lime-600 dark:text-lime-400" id="exp-stat-completed">&mdash;</p>
              </div>
            </div>
            <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
              <div class="p-5">
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Draft</p>
                <p class="mt-1 text-2xl font-semibold text-zinc-500 dark:text-zinc-400" id="exp-stat-draft">&mdash;</p>
              </div>
            </div>
          </div>

          <!-- Experiment List -->
          <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="px-5 py-3 border-b border-zinc-200 dark:border-zinc-700 flex items-center justify-between">
              <h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">All Experiments</h3>
              <select id="exp-filter-status" onchange="loadExperiments()" class="text-xs rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 px-2 py-1">
                <option value="">All statuses</option>
                <option value="draft">Draft</option>
                <option value="running">Running</option>
                <option value="paused">Paused</option>
                <option value="completed">Completed</option>
                <option value="archived">Archived</option>
              </select>
            </div>
            <div id="exp-list" class="divide-y divide-zinc-200 dark:divide-zinc-700">
              <div class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">Loading experiments...</div>
            </div>
          </div>

          <!-- Create Experiment Modal -->
          <div id="exp-create-modal" class="hidden fixed inset-0 z-50 overflow-y-auto">
            <div class="flex min-h-full items-center justify-center p-4">
              <div class="fixed inset-0 bg-zinc-900/50 dark:bg-black/50" onclick="closeCreateExperiment()"></div>
              <div class="relative w-full max-w-lg rounded-2xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-xl p-6">
                <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">New Experiment</h3>

                <div class="space-y-4">
                  <div>
                    <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Name</label>
                    <input id="exp-name" type="text" placeholder="e.g. Title Boost Test"
                      class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2" />
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Description</label>
                    <textarea id="exp-desc" rows="2" placeholder="What are you testing and why?"
                      class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2"></textarea>
                  </div>

                  <div class="grid grid-cols-2 gap-4">
                    <div>
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Mode</label>
                      <select id="exp-mode"
                        class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2">
                        <option value="ab">A/B Split</option>
                        <option value="interleave">Interleaving</option>
                      </select>
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Traffic %</label>
                      <input id="exp-traffic" type="number" value="100" min="1" max="100"
                        class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2" />
                    </div>
                  </div>

                  <div class="grid grid-cols-2 gap-4">
                    <div>
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Split Ratio (treatment %)</label>
                      <input id="exp-split" type="number" value="50" min="10" max="90" step="5"
                        class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2" />
                    </div>
                    <div>
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Min Searches</label>
                      <input id="exp-min-searches" type="number" value="100" min="10"
                        class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2" />
                    </div>
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                      Treatment Overrides <span class="text-zinc-400 font-normal">(JSON — settings that differ from control)</span>
                    </label>
                    <textarea id="exp-overrides" rows="4" placeholder='{ "fts5_title_boost": 8, "query_rewriting_enabled": true }'
                      class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm font-mono px-3 py-2"></textarea>
                    <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                      Testable: fts5_title_boost, fts5_slug_boost, fts5_body_boost, query_rewriting_enabled,
                      reranking_enabled, query_synonyms_enabled, results_limit, cache_duration, facets_enabled
                    </p>
                  </div>
                </div>

                <div class="mt-6 flex justify-end gap-3">
                  <button onclick="closeCreateExperiment()" type="button"
                    class="rounded-lg px-4 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800">
                    Cancel
                  </button>
                  <button onclick="createExperiment()" type="button"
                    class="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700">
                    Create Draft
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
  `
}

export function renderExperimentsScript(): string {
  return `
      // ── Experiments Tab State ──────────────────
      let experimentsLoaded = false
      let activeExperimentId = null

      function loadExperimentsOnTabSwitch() {
        if (!experimentsLoaded) {
          experimentsLoaded = true
          loadExperiments()
        }
      }

      // ── Load Experiments ──────────────────────
      async function loadExperiments() {
        try {
          const status = document.getElementById('exp-filter-status')?.value || ''
          const params = status ? '?status=' + status : ''
          const resp = await fetch('/admin/plugins/ai-search/api/experiments' + params)
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)

          const experiments = json.data || []

          // Update stat cards
          const total = experiments.length
          const running = experiments.filter(e => e.status === 'running').length
          const completed = experiments.filter(e => e.status === 'completed').length
          const draft = experiments.filter(e => e.status === 'draft').length

          document.getElementById('exp-stat-total').textContent = total
          document.getElementById('exp-stat-running').textContent = running
          document.getElementById('exp-stat-completed').textContent = completed
          document.getElementById('exp-stat-draft').textContent = draft

          // Active experiment banner
          const activeExp = experiments.find(e => e.status === 'running')
          const banner = document.getElementById('exp-active-banner')
          if (activeExp) {
            activeExperimentId = activeExp.id
            banner.classList.remove('hidden')
            document.getElementById('exp-active-name').textContent = activeExp.name
            document.getElementById('exp-active-desc').textContent = activeExp.description || 'No description'
            document.getElementById('exp-active-mode-badge').textContent = activeExp.mode === 'interleave' ? 'Interleaving' : 'A/B Split'

            if (activeExp.metrics) {
              const m = activeExp.metrics
              document.getElementById('exp-active-metrics').classList.remove('hidden')
              document.getElementById('exp-active-searches').textContent = (m.control.searches + m.treatment.searches).toLocaleString()
              document.getElementById('exp-active-confidence').textContent = (m.confidence * 100).toFixed(1) + '%'
              document.getElementById('exp-active-confidence-bar').style.width = (m.confidence * 100) + '%'

              document.getElementById('exp-ctrl-ctr').textContent = (m.control.ctr * 100).toFixed(1) + '%'
              document.getElementById('exp-ctrl-zero').textContent = (m.control.zero_result_rate * 100).toFixed(1) + '%'
              document.getElementById('exp-ctrl-pos').textContent = m.control.avg_click_position ? m.control.avg_click_position.toFixed(1) : '—'

              document.getElementById('exp-treat-ctr').textContent = (m.treatment.ctr * 100).toFixed(1) + '%'
              document.getElementById('exp-treat-zero').textContent = (m.treatment.zero_result_rate * 100).toFixed(1) + '%'
              document.getElementById('exp-treat-pos').textContent = m.treatment.avg_click_position ? m.treatment.avg_click_position.toFixed(1) : '—'
            } else {
              document.getElementById('exp-active-metrics').classList.add('hidden')
              document.getElementById('exp-active-searches').textContent = '0'
              document.getElementById('exp-active-confidence').textContent = '0%'
              document.getElementById('exp-active-confidence-bar').style.width = '0%'
            }
          } else {
            activeExperimentId = null
            banner.classList.add('hidden')
          }

          // Render experiment list
          const listEl = document.getElementById('exp-list')
          if (experiments.length === 0) {
            listEl.innerHTML = '<div class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No experiments yet. Click "New Experiment" to get started.</div>'
            return
          }

          listEl.innerHTML = experiments.map(exp => {
            const statusColors = {
              draft: 'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300',
              running: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300',
              paused: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
              completed: 'bg-lime-100 text-lime-700 dark:bg-lime-900 dark:text-lime-300',
              archived: 'bg-zinc-100 text-zinc-500 dark:bg-zinc-800 dark:text-zinc-500',
            }
            const modeLabel = exp.mode === 'interleave' ? 'Interleave' : 'A/B'
            const date = new Date(exp.created_at).toLocaleDateString()
            const winnerBadge = exp.winner
              ? '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-lime-100 text-lime-700 dark:bg-lime-900 dark:text-lime-300">Winner: ' + exp.winner + '</span>'
              : ''

            let actions = ''
            if (exp.status === 'draft') {
              actions = '<button onclick="startExperimentById(\\'' + exp.id + '\\')" class="text-xs text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 font-medium">Start</button>'
                + ' <button onclick="deleteExperimentById(\\'' + exp.id + '\\')" class="text-xs text-red-600 hover:text-red-800 dark:text-red-400 font-medium ml-2">Delete</button>'
            } else if (exp.status === 'completed') {
              actions = '<button onclick="archiveExperimentById(\\'' + exp.id + '\\')" class="text-xs text-zinc-600 hover:text-zinc-800 dark:text-zinc-400 font-medium">Archive</button>'
            }

            return '<div class="px-5 py-3 flex items-center justify-between hover:bg-zinc-50 dark:hover:bg-zinc-800/50">'
              + '<div class="flex items-center gap-3 min-w-0">'
              + '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ' + (statusColors[exp.status] || '') + '">' + exp.status + '</span>'
              + '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">' + modeLabel + '</span>'
              + '<span class="text-sm font-medium text-zinc-900 dark:text-white truncate">' + exp.name + '</span>'
              + winnerBadge
              + '</div>'
              + '<div class="flex items-center gap-4 text-xs text-zinc-500 dark:text-zinc-400 flex-shrink-0">'
              + '<span>' + date + '</span>'
              + actions
              + '</div>'
              + '</div>'
          }).join('')

        } catch (error) {
          console.error('Failed to load experiments:', error)
          document.getElementById('exp-list').innerHTML = '<div class="px-5 py-8 text-center text-sm text-red-500">Failed to load experiments</div>'
        }
      }

      // ── CRUD Operations ───────────────────────
      function openCreateExperiment() {
        document.getElementById('exp-create-modal').classList.remove('hidden')
      }

      function closeCreateExperiment() {
        document.getElementById('exp-create-modal').classList.add('hidden')
      }

      async function createExperiment() {
        try {
          const name = document.getElementById('exp-name').value.trim()
          if (!name) { alert('Name is required'); return }

          let overrides = {}
          const overridesText = document.getElementById('exp-overrides').value.trim()
          if (overridesText) {
            try { overrides = JSON.parse(overridesText) }
            catch { alert('Invalid JSON in treatment overrides'); return }
          }

          const resp = await fetch('/admin/plugins/ai-search/api/experiments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name,
              description: document.getElementById('exp-desc').value.trim() || null,
              mode: document.getElementById('exp-mode').value,
              traffic_pct: Number(document.getElementById('exp-traffic').value),
              split_ratio: Number(document.getElementById('exp-split').value) / 100,
              min_searches: Number(document.getElementById('exp-min-searches').value),
              variants: { control: {}, treatment: overrides },
            }),
          })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)

          closeCreateExperiment()
          showMsg('Experiment created: ' + json.data.name)
          loadExperiments()

          // Clear form
          document.getElementById('exp-name').value = ''
          document.getElementById('exp-desc').value = ''
          document.getElementById('exp-overrides').value = ''
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function startExperimentById(id) {
        if (!confirm('Start this experiment? It will affect live search traffic.')) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + id + '/start', { method: 'POST' })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Experiment started')
          loadExperiments()
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function pauseExperiment() {
        if (!activeExperimentId) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + activeExperimentId + '/pause', { method: 'POST' })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Experiment paused')
          loadExperiments()
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function completeExperiment() {
        if (!activeExperimentId) return
        if (!confirm('Stop this experiment? This will complete it and stop collecting data.')) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + activeExperimentId + '/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
          })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Experiment completed' + (json.data.winner ? ' — Winner: ' + json.data.winner : ''))
          loadExperiments()
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function deleteExperimentById(id) {
        if (!confirm('Delete this experiment? This cannot be undone.')) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + id, { method: 'DELETE' })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Experiment deleted')
          loadExperiments()
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function archiveExperimentById(id) {
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'archived' }),
          })
          // Archive uses the lifecycle method, not PUT
          // Actually archive needs a dedicated endpoint — for now use direct status update
          // This will need the service's archive method
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      function showMsg(text) {
        const el = document.getElementById('msg')
        if (el) {
          el.textContent = text
          el.classList.remove('hidden')
          setTimeout(() => el.classList.add('hidden'), 3000)
        }
      }
  `
}
