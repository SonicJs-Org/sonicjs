/**
 * Admin Search Dashboard — A/B Tests Tab
 *
 * A/B testing and interleaving experiments: create via templates or custom,
 * manage with visual settings editor, and analyze with recommendations.
 */

import {
  EXPERIMENT_TEMPLATES,
  TESTABLE_SETTINGS,
  DEFAULT_SETTINGS,
} from '../../plugins/core-plugins/ai-search-plugin/constants/experiment-templates'

export function renderExperimentsTab(): string {
  return `
      <div id="tab-experiments" class="tab-panel hidden">
        <div class="space-y-6">

          <!-- Header -->
          <div class="flex items-center justify-between">
            <div>
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Search A/B Tests</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">A/B test and interleave search configurations to measure what works best</p>
            </div>
            <div class="flex items-center gap-3">
              <button onclick="openCreateExperiment()" type="button"
                class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700">
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                </svg>
                New A/B Test
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
                  <span class="text-sm font-semibold text-indigo-700 dark:text-indigo-300" id="exp-active-name">&mdash;</span>
                  <span id="exp-active-mode-badge" class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium bg-indigo-100 text-indigo-700 dark:bg-indigo-900 dark:text-indigo-300">A/B</span>
                </div>
                <p class="mt-1 text-xs text-indigo-600 dark:text-indigo-400" id="exp-active-desc">&mdash;</p>
              </div>
              <div class="flex items-center gap-6">
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
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-ctrl-ctr">&mdash;</p>
                    <p class="text-[10px] text-zinc-500">CTR</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-ctrl-zero">&mdash;</p>
                    <p class="text-[10px] text-zinc-500">Zero-Result</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-ctrl-pos">&mdash;</p>
                    <p class="text-[10px] text-zinc-500">Avg Position</p>
                  </div>
                </div>
              </div>
              <div class="rounded-lg bg-white dark:bg-zinc-900 p-3 ring-1 ring-zinc-200 dark:ring-zinc-700">
                <p class="text-xs font-medium text-zinc-500 dark:text-zinc-400 mb-2">Treatment</p>
                <div class="grid grid-cols-3 gap-2 text-center">
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-treat-ctr">&mdash;</p>
                    <p class="text-[10px] text-zinc-500">CTR</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-treat-zero">&mdash;</p>
                    <p class="text-[10px] text-zinc-500">Zero-Result</p>
                  </div>
                  <div>
                    <p class="text-lg font-semibold text-zinc-900 dark:text-white" id="exp-treat-pos">&mdash;</p>
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
                <p class="text-sm text-zinc-600 dark:text-zinc-400">Total Tests</p>
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

          <!-- Test List -->
          <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="px-5 py-3 border-b border-zinc-200 dark:border-zinc-700 flex items-center justify-between">
              <h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">All Tests</h3>
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
              <div class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">Loading tests...</div>
            </div>
          </div>

          <!-- Test Recommendations Panel -->
          <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="px-5 py-3 border-b border-zinc-200 dark:border-zinc-700">
              <h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Test Recommendations</h3>
              <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Based on your search analytics</p>
            </div>
            <div id="exp-recommendations" class="p-5">
              <div class="text-center text-sm text-zinc-500 dark:text-zinc-400 py-4">
                <svg class="animate-spin h-5 w-5 mx-auto mb-2 text-zinc-400" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
                </svg>
                Loading analytics data...
              </div>
            </div>
          </div>

          <!-- Create Test Modal -->
          <div id="exp-create-modal" class="hidden fixed inset-0 z-50 overflow-y-auto">
            <div class="flex min-h-full items-center justify-center p-4">
              <div class="fixed inset-0 bg-zinc-900/50 dark:bg-black/50" onclick="closeCreateExperiment()"></div>
              <div class="relative w-full max-w-2xl rounded-2xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-xl p-6 max-h-[90vh] overflow-y-auto">
                <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">New A/B Test</h3>

                <!-- Template Picker -->
                <div class="mb-5">
                  <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2">Choose a Template</label>
                  <div id="exp-template-grid" class="grid grid-cols-3 gap-2">
                    <!-- Populated by JS -->
                  </div>
                </div>

                <!-- Mode Rationale -->
                <div id="exp-mode-rationale" class="hidden mb-4 rounded-lg bg-blue-50 dark:bg-blue-950/30 p-3 text-xs text-blue-700 dark:text-blue-300 ring-1 ring-blue-200 dark:ring-blue-800">
                </div>

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

                  <div class="grid grid-cols-3 gap-4">
                    <div>
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Mode</label>
                      <select id="exp-mode" onchange="onModeChange()"
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
                    <div>
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Min Searches</label>
                      <input id="exp-min-searches" type="number" value="100" min="10"
                        class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm px-3 py-2" />
                    </div>
                  </div>

                  <!-- Visual Settings Editor -->
                  <div>
                    <div class="flex items-center justify-between mb-2">
                      <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300">Treatment Overrides</label>
                      <button type="button" onclick="toggleRawJson()" id="exp-raw-toggle"
                        class="text-xs text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200">
                        Advanced: Raw JSON
                      </button>
                    </div>

                    <!-- Visual editor -->
                    <div id="exp-visual-editor">
                      <div id="exp-overrides-list" class="space-y-3">
                        <!-- Override rows populated by JS -->
                      </div>
                      <div class="mt-3">
                        <div class="flex items-center gap-2">
                          <select id="exp-add-setting"
                            class="flex-1 rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-xs px-3 py-1.5">
                            <option value="">+ Add Setting Override</option>
                          </select>
                          <button type="button" onclick="addSelectedOverride()"
                            class="rounded-lg px-3 py-1.5 text-xs font-medium text-indigo-600 hover:text-indigo-800 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-950/30 hover:bg-indigo-100 dark:hover:bg-indigo-900/50">
                            Add
                          </button>
                        </div>
                      </div>
                    </div>

                    <!-- Raw JSON fallback (hidden by default) -->
                    <div id="exp-raw-editor" class="hidden">
                      <textarea id="exp-overrides" rows="4" placeholder='{ "fts5_title_boost": 8, "query_rewriting_enabled": true }'
                        class="w-full rounded-lg border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-sm font-mono px-3 py-2"></textarea>
                      <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                        Testable: fts5_title_boost, fts5_slug_boost, fts5_body_boost, query_rewriting_enabled,
                        reranking_enabled, query_synonyms_enabled, results_limit, cache_duration, facets_enabled
                      </p>
                    </div>
                  </div>

                  <!-- Summary Panel -->
                  <div id="exp-summary-panel" class="hidden rounded-lg bg-zinc-50 dark:bg-zinc-800/50 p-4 ring-1 ring-zinc-200 dark:ring-zinc-700">
                    <h4 class="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider mb-2">Test Summary</h4>
                    <div id="exp-summary-text" class="text-sm text-zinc-700 dark:text-zinc-300 space-y-1">
                    </div>
                    <div id="exp-duration-estimate" class="hidden mt-2 text-xs text-zinc-500 dark:text-zinc-400 italic">
                    </div>
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
  // Embed templates and settings as JSON for the client-side script
  const templatesJson = JSON.stringify(EXPERIMENT_TEMPLATES)
  const settingsJson = JSON.stringify(TESTABLE_SETTINGS)
  const defaultsJson = JSON.stringify(DEFAULT_SETTINGS)

  return `
      // ── Experiments Tab State ──────────────────
      let experimentsLoaded = false
      let activeExperimentId = null
      let expCurrentOverrides = {}
      let expControlSettings = ${defaultsJson}
      let expUsingRawJson = false
      let expSelectedTemplateId = null
      let expDailySearchVolume = 0
      let expAllExperiments = []

      // Embedded data
      var EXP_TEMPLATES = ${templatesJson}
      var EXP_TESTABLE_SETTINGS = ${settingsJson}
      var EXP_DEFAULT_SETTINGS = ${defaultsJson}

      function loadExperimentsOnTabSwitch() {
        if (!experimentsLoaded) {
          experimentsLoaded = true
          loadExperiments()
          fetchControlSettings()
          loadRecommendations()
        }
      }

      // ── Fetch live control settings ─────────────
      async function fetchControlSettings() {
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/settings')
          const json = await resp.json()
          if (json.success && json.data) {
            // Merge live settings over defaults for keys we care about
            for (var s of EXP_TESTABLE_SETTINGS) {
              if (json.data[s.key] !== undefined) {
                expControlSettings[s.key] = json.data[s.key]
              }
            }
          }
        } catch (e) {
          console.warn('Could not fetch live settings, using defaults')
        }
      }

      // ── Template Picker ─────────────────────────
      function renderTemplateGrid() {
        var grid = document.getElementById('exp-template-grid')
        if (!grid) return

        var categoryColors = {
          relevance: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
          performance: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
          features: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900 dark:text-emerald-300',
          comprehensive: 'bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300',
        }

        var html = EXP_TEMPLATES.map(function(t) {
          return '<button type="button" onclick="selectTemplate(\\'' + t.id + '\\')" '
            + 'id="exp-tpl-' + t.id + '" '
            + 'class="exp-tpl-card text-left rounded-lg p-3 ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-indigo-400 dark:hover:ring-indigo-500 transition-all cursor-pointer">'
            + '<div class="flex items-center gap-2 mb-1">'
            + '<span class="inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ' + (categoryColors[t.category] || '') + '">' + t.category + '</span>'
            + '</div>'
            + '<p class="text-xs font-medium text-zinc-900 dark:text-white leading-tight">' + t.name + '</p>'
            + '<p class="text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5 line-clamp-2">' + t.description + '</p>'
            + '</button>'
        }).join('')

        // Custom card
        html += '<button type="button" onclick="selectTemplate(\\'custom\\')" '
          + 'id="exp-tpl-custom" '
          + 'class="exp-tpl-card text-left rounded-lg p-3 ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-indigo-400 dark:hover:ring-indigo-500 transition-all cursor-pointer">'
          + '<div class="flex items-center gap-2 mb-1">'
          + '<span class="inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">custom</span>'
          + '</div>'
          + '<p class="text-xs font-medium text-zinc-900 dark:text-white leading-tight">Custom Test</p>'
          + '<p class="text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5">Configure everything manually</p>'
          + '</button>'

        grid.innerHTML = html
      }

      function selectTemplate(templateId) {
        expSelectedTemplateId = templateId

        // Highlight selected card
        document.querySelectorAll('.exp-tpl-card').forEach(function(card) {
          card.classList.remove('ring-indigo-500', 'dark:ring-indigo-400', 'bg-indigo-50', 'dark:bg-indigo-950/20')
          card.classList.add('ring-zinc-200', 'dark:ring-zinc-700')
        })
        var selected = document.getElementById('exp-tpl-' + templateId)
        if (selected) {
          selected.classList.remove('ring-zinc-200', 'dark:ring-zinc-700')
          selected.classList.add('ring-indigo-500', 'dark:ring-indigo-400', 'bg-indigo-50', 'dark:bg-indigo-950/20')
        }

        var rationale = document.getElementById('exp-mode-rationale')

        if (templateId === 'custom') {
          // Clear all fields
          document.getElementById('exp-name').value = ''
          document.getElementById('exp-desc').value = ''
          document.getElementById('exp-mode').value = 'ab'
          document.getElementById('exp-traffic').value = '100'
          document.getElementById('exp-min-searches').value = '100'
          expCurrentOverrides = {}
          renderOverrideRows()
          rationale.classList.add('hidden')
          updateTestSummary()
          return
        }

        var tpl = EXP_TEMPLATES.find(function(t) { return t.id === templateId })
        if (!tpl) return

        document.getElementById('exp-name').value = tpl.name
        document.getElementById('exp-desc').value = tpl.description
        document.getElementById('exp-mode').value = tpl.mode
        document.getElementById('exp-traffic').value = String(tpl.traffic_pct)
        document.getElementById('exp-min-searches').value = String(tpl.min_searches)

        // Set overrides
        expCurrentOverrides = Object.assign({}, tpl.overrides)
        renderOverrideRows()

        // Show mode rationale
        rationale.textContent = tpl.mode_rationale
        rationale.classList.remove('hidden')

        updateAddSettingDropdown()
        updateTestSummary()
      }

      // ── Visual Settings Editor ──────────────────
      function renderOverrideRows() {
        var container = document.getElementById('exp-overrides-list')
        if (!container) return

        var keys = Object.keys(expCurrentOverrides)
        if (keys.length === 0) {
          container.innerHTML = '<p class="text-xs text-zinc-400 dark:text-zinc-500 italic py-2">No overrides yet — select a template or add settings below</p>'
          updateAddSettingDropdown()
          updateTestSummary()
          return
        }

        container.innerHTML = keys.map(function(key) {
          var meta = EXP_TESTABLE_SETTINGS.find(function(s) { return s.key === key })
          if (!meta) return ''

          var value = expCurrentOverrides[key]
          var controlVal = expControlSettings[key] !== undefined ? expControlSettings[key] : meta.default_value

          var controlDisplay = meta.type === 'boolean' ? (controlVal ? 'ON' : 'OFF') : String(controlVal)

          var controlHtml = '<span class="text-xs text-zinc-400 dark:text-zinc-500">Control: ' + controlDisplay + '</span>'

          var inputHtml = ''
          if (meta.type === 'number') {
            inputHtml = '<div class="flex items-center gap-2 flex-1">'
              + '<input type="range" min="' + (meta.min || 0) + '" max="' + (meta.max || 100) + '" step="' + (meta.step || 1) + '" '
              + 'value="' + value + '" '
              + 'oninput="updateOverrideValue(\\'' + key + '\\', Number(this.value))" '
              + 'class="flex-1 h-1.5 bg-zinc-200 dark:bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-indigo-600" />'
              + '<input type="number" min="' + (meta.min || 0) + '" max="' + (meta.max || 100) + '" step="' + (meta.step || 1) + '" '
              + 'value="' + value + '" '
              + 'oninput="updateOverrideValue(\\'' + key + '\\', Number(this.value))" '
              + 'data-exp-num="' + key + '" '
              + 'class="w-16 rounded-md border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 text-zinc-900 dark:text-white text-xs px-2 py-1 text-center" />'
              + '</div>'
          } else {
            // Boolean toggle
            var checked = value ? 'checked' : ''
            inputHtml = '<label class="relative inline-flex items-center cursor-pointer">'
              + '<input type="checkbox" ' + checked + ' '
              + 'onchange="updateOverrideValue(\\'' + key + '\\', this.checked)" '
              + 'class="sr-only peer" />'
              + '<div class="w-9 h-5 bg-zinc-200 peer-focus:outline-none rounded-full peer dark:bg-zinc-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[\\'\\'] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600"></div>'
              + '<span class="ml-2 text-xs font-medium text-zinc-700 dark:text-zinc-300">' + (value ? 'ON' : 'OFF') + '</span>'
              + '</label>'
          }

          return '<div class="flex items-center gap-3 py-2 px-3 rounded-lg bg-zinc-50 dark:bg-zinc-800/50 ring-1 ring-zinc-200 dark:ring-zinc-700" data-override-key="' + key + '">'
            + '<div class="w-32 flex-shrink-0">'
            + '<p class="text-xs font-medium text-zinc-700 dark:text-zinc-300">' + meta.label + '</p>'
            + controlHtml
            + '</div>'
            + '<div class="flex-1">'
            + inputHtml
            + '</div>'
            + '<button type="button" onclick="removeOverride(\\'' + key + '\\')" '
            + 'class="flex-shrink-0 text-zinc-400 hover:text-red-500 dark:text-zinc-500 dark:hover:text-red-400">'
            + '<svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg>'
            + '</button>'
            + '</div>'
        }).join('')

        updateAddSettingDropdown()
        updateTestSummary()
      }

      function updateOverrideValue(key, value) {
        expCurrentOverrides[key] = value

        // Sync the range and number inputs for number types
        var meta = EXP_TESTABLE_SETTINGS.find(function(s) { return s.key === key })
        if (meta && meta.type === 'number') {
          var row = document.querySelector('[data-override-key="' + key + '"]')
          if (row) {
            var rangeInput = row.querySelector('input[type="range"]')
            var numInput = row.querySelector('input[type="number"]')
            if (rangeInput) rangeInput.value = value
            if (numInput) numInput.value = value
          }
        }

        // Update toggle label for booleans
        if (meta && meta.type === 'boolean') {
          var row = document.querySelector('[data-override-key="' + key + '"]')
          if (row) {
            var label = row.querySelector('.peer ~ span')
            if (label) label.textContent = value ? 'ON' : 'OFF'
          }
        }

        updateTestSummary()
      }

      function removeOverride(key) {
        delete expCurrentOverrides[key]
        renderOverrideRows()
      }

      function updateAddSettingDropdown() {
        var select = document.getElementById('exp-add-setting')
        if (!select) return

        var usedKeys = Object.keys(expCurrentOverrides)
        var available = EXP_TESTABLE_SETTINGS.filter(function(s) {
          return usedKeys.indexOf(s.key) === -1
        })

        select.innerHTML = '<option value="">+ Add Setting Override</option>'
          + available.map(function(s) {
            return '<option value="' + s.key + '">' + s.label + ' (' + s.key + ')</option>'
          }).join('')
      }

      function addSelectedOverride() {
        var select = document.getElementById('exp-add-setting')
        var key = select.value
        if (!key) return

        var meta = EXP_TESTABLE_SETTINGS.find(function(s) { return s.key === key })
        if (!meta) return

        expCurrentOverrides[key] = meta.default_value
        renderOverrideRows()
        select.value = ''
      }

      // ── Raw JSON Toggle ─────────────────────────
      function toggleRawJson() {
        expUsingRawJson = !expUsingRawJson
        var visual = document.getElementById('exp-visual-editor')
        var raw = document.getElementById('exp-raw-editor')
        var toggle = document.getElementById('exp-raw-toggle')

        if (expUsingRawJson) {
          visual.classList.add('hidden')
          raw.classList.remove('hidden')
          toggle.textContent = 'Visual Editor'
          // Sync overrides to raw JSON
          document.getElementById('exp-overrides').value = JSON.stringify(expCurrentOverrides, null, 2)
        } else {
          visual.classList.remove('hidden')
          raw.classList.add('hidden')
          toggle.textContent = 'Advanced: Raw JSON'
          // Sync raw JSON back to visual
          try {
            var parsed = JSON.parse(document.getElementById('exp-overrides').value.trim() || '{}')
            expCurrentOverrides = parsed
            renderOverrideRows()
          } catch (e) {
            // Keep existing overrides if JSON is invalid
          }
        }
      }

      function onModeChange() {
        // Clear the template-specific rationale when mode is manually changed
        var rationale = document.getElementById('exp-mode-rationale')
        rationale.classList.add('hidden')
        updateTestSummary()
      }

      // ── Summary Panel ───────────────────────────
      function updateTestSummary() {
        var panel = document.getElementById('exp-summary-panel')
        var textEl = document.getElementById('exp-summary-text')
        var durationEl = document.getElementById('exp-duration-estimate')

        var keys = Object.keys(expCurrentOverrides)
        if (keys.length === 0) {
          panel.classList.add('hidden')
          return
        }
        panel.classList.remove('hidden')

        var lines = []
        keys.forEach(function(key) {
          var meta = EXP_TESTABLE_SETTINGS.find(function(s) { return s.key === key })
          var label = meta ? meta.label : key
          var controlVal = expControlSettings[key]
          var treatmentVal = expCurrentOverrides[key]

          if (typeof treatmentVal === 'boolean') {
            lines.push('Testing <strong>' + label + ' = ' + (treatmentVal ? 'ON' : 'OFF') + '</strong> vs control (' + (controlVal ? 'ON' : 'OFF') + ')')
          } else {
            lines.push('Testing <strong>' + label + ' = ' + treatmentVal + '</strong> vs control (' + controlVal + ')')
          }
        })

        var minSearches = Number(document.getElementById('exp-min-searches').value) || 100
        lines.push('Minimum searches needed: <strong>' + minSearches.toLocaleString() + '</strong>')

        textEl.innerHTML = lines.map(function(l) { return '<p>' + l + '</p>' }).join('')

        // Duration estimate
        if (expDailySearchVolume > 0) {
          var days = Math.ceil(minSearches / expDailySearchVolume)
          durationEl.textContent = 'At ~' + expDailySearchVolume + ' searches/day, roughly ' + days + ' day' + (days !== 1 ? 's' : '')
          durationEl.classList.remove('hidden')
        } else {
          durationEl.classList.add('hidden')
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
          expAllExperiments = experiments

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
            listEl.innerHTML = '<div class="px-5 py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No tests yet. Click "New A/B Test" to get started.</div>'
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
          document.getElementById('exp-list').innerHTML = '<div class="px-5 py-8 text-center text-sm text-red-500">Failed to load tests</div>'
        }
      }

      // ── CRUD Operations ───────────────────────
      function openCreateExperiment(templateId) {
        renderTemplateGrid()
        expCurrentOverrides = {}
        expSelectedTemplateId = null
        expUsingRawJson = false
        document.getElementById('exp-visual-editor').classList.remove('hidden')
        document.getElementById('exp-raw-editor').classList.add('hidden')
        document.getElementById('exp-raw-toggle').textContent = 'Advanced: Raw JSON'
        document.getElementById('exp-mode-rationale').classList.add('hidden')
        document.getElementById('exp-summary-panel').classList.add('hidden')

        // Reset form
        document.getElementById('exp-name').value = ''
        document.getElementById('exp-desc').value = ''
        document.getElementById('exp-mode').value = 'ab'
        document.getElementById('exp-traffic').value = '100'
        document.getElementById('exp-min-searches').value = '100'
        document.getElementById('exp-overrides').value = ''

        renderOverrideRows()
        document.getElementById('exp-create-modal').classList.remove('hidden')

        // If a template was requested (e.g. from recommendations), select it
        if (templateId) {
          setTimeout(function() { selectTemplate(templateId) }, 50)
        }
      }

      function closeCreateExperiment() {
        document.getElementById('exp-create-modal').classList.add('hidden')
      }

      async function createExperiment() {
        try {
          const name = document.getElementById('exp-name').value.trim()
          if (!name) { alert('Name is required'); return }

          let overrides = {}

          if (expUsingRawJson) {
            const overridesText = document.getElementById('exp-overrides').value.trim()
            if (overridesText) {
              try { overrides = JSON.parse(overridesText) }
              catch { alert('Invalid JSON in treatment overrides'); return }
            }
          } else {
            overrides = Object.assign({}, expCurrentOverrides)
          }

          const resp = await fetch('/admin/plugins/ai-search/api/experiments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name,
              description: document.getElementById('exp-desc').value.trim() || null,
              mode: document.getElementById('exp-mode').value,
              traffic_pct: Number(document.getElementById('exp-traffic').value),
              split_ratio: 0.5,
              min_searches: Number(document.getElementById('exp-min-searches').value),
              variants: { control: {}, treatment: overrides },
            }),
          })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)

          closeCreateExperiment()
          showMsg('Test created: ' + json.data.name)
          loadExperiments()

        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function startExperimentById(id) {
        if (!confirm('Start this test? It will affect live search traffic.')) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + id + '/start', { method: 'POST' })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Test started')
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
          showMsg('Test paused')
          loadExperiments()
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function completeExperiment() {
        if (!activeExperimentId) return
        if (!confirm('Stop this test? This will complete it and stop collecting data.')) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + activeExperimentId + '/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
          })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Test completed' + (json.data.winner ? ' — Winner: ' + json.data.winner : ''))
          loadExperiments()
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      async function deleteExperimentById(id) {
        if (!confirm('Delete this test? This cannot be undone.')) return
        try {
          const resp = await fetch('/admin/plugins/ai-search/api/experiments/' + id, { method: 'DELETE' })
          const json = await resp.json()
          if (!json.success) throw new Error(json.error)
          showMsg('Test deleted')
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
        } catch (error) {
          alert('Error: ' + error.message)
        }
      }

      // ── Recommendations ─────────────────────────
      async function loadRecommendations() {
        var container = document.getElementById('exp-recommendations')
        if (!container) return

        try {
          var resp = await fetch('/admin/plugins/ai-search/api/analytics/extended')
          var json = await resp.json()

          if (!json.success) {
            container.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400 text-center py-4">Could not load analytics data</p>'
            return
          }

          var analytics = json.data || {}
          var totalQueries = analytics.total_queries || 0
          var zeroResults = analytics.zero_result_queries || 0
          var totalClicks = analytics.total_clicks || 0
          var avgPosition = analytics.avg_click_position || 0
          var avgResponseTime = analytics.avg_response_time_ms || 0
          var facetClicks = analytics.facet_clicks || 0
          var facetsEnabled = analytics.facets_enabled || false
          var distinctZeroQueries = analytics.distinct_zero_result_queries || 0

          // Calculate daily volume for duration estimates
          var daysOfData = analytics.days_of_data || 30
          expDailySearchVolume = daysOfData > 0 ? Math.round(totalQueries / daysOfData) : 0

          // Not enough data
          if (totalQueries < 10) {
            container.innerHTML = '<div class="text-center py-6">'
              + '<svg class="h-8 w-8 mx-auto mb-2 text-zinc-300 dark:text-zinc-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
              + '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>'
              + '</svg>'
              + '<p class="text-sm font-medium text-zinc-600 dark:text-zinc-400">Not enough data yet</p>'
              + '<p class="text-xs text-zinc-500 dark:text-zinc-500 mt-1">Run at least 10 searches to get recommendations</p>'
              + '</div>'
            return
          }

          // Rule engine
          var recommendations = []
          var zeroRate = totalQueries > 0 ? (zeroResults / totalQueries) : 0
          var ctr = totalQueries > 0 ? (totalClicks / totalQueries) : 0

          // High zero-result rate
          if (zeroRate > 0.10) {
            recommendations.push({
              templateId: 'query-rewriting',
              reason: 'Zero-result rate is ' + (zeroRate * 100).toFixed(1) + '% (above 10% threshold)',
              impact: 'HIGH',
            })
            recommendations.push({
              templateId: 'full-ai-enhancement',
              reason: 'High zero-result rate (' + (zeroRate * 100).toFixed(1) + '%) suggests queries need expansion',
              impact: 'HIGH',
            })
          }

          // Low CTR
          if (ctr < 0.05 && totalQueries > 50) {
            recommendations.push({
              templateId: 'title-boost',
              reason: 'CTR is ' + (ctr * 100).toFixed(1) + '% (below 5% threshold with ' + totalQueries + ' queries)',
              impact: 'HIGH',
            })
            recommendations.push({
              templateId: 'compact-results',
              reason: 'Low CTR (' + (ctr * 100).toFixed(1) + '%) — fewer results may increase engagement',
              impact: 'HIGH',
            })
          }

          // High average click position
          if (avgPosition > 3.0) {
            recommendations.push({
              templateId: 'title-boost',
              reason: 'Average click position is ' + avgPosition.toFixed(1) + ' (above 3.0 — users scrolling past top results)',
              impact: 'HIGH',
            })
            recommendations.push({
              templateId: 'aggressive-title-slug',
              reason: 'Users clicking results at position ' + avgPosition.toFixed(1) + ' suggests ranking needs improvement',
              impact: 'MEDIUM',
            })
          }

          // Slow response times
          if (avgResponseTime > 500) {
            recommendations.push({
              templateId: 'disable-reranking',
              reason: 'Average response time is ' + Math.round(avgResponseTime) + 'ms (above 500ms threshold)',
              impact: 'MEDIUM',
            })
            recommendations.push({
              templateId: 'compact-results',
              reason: 'Slow responses (' + Math.round(avgResponseTime) + 'ms) — fewer results may speed things up',
              impact: 'MEDIUM',
            })
          }

          // No facet usage
          if (!facetsEnabled && facetClicks === 0) {
            recommendations.push({
              templateId: 'enable-facets',
              reason: 'Faceted search is disabled — could help users narrow down results',
              impact: 'MEDIUM',
            })
          }

          // Many zero-result queries
          if (distinctZeroQueries > 5) {
            recommendations.push({
              templateId: 'body-focus',
              reason: distinctZeroQueries + ' distinct queries returned zero results — body content may contain matches',
              impact: 'LOW',
            })
          }

          // Deduplicate by templateId, keeping highest impact
          var impactOrder = { HIGH: 3, MEDIUM: 2, LOW: 1 }
          var seen = {}
          var deduped = []
          recommendations.sort(function(a, b) { return (impactOrder[b.impact] || 0) - (impactOrder[a.impact] || 0) })
          recommendations.forEach(function(r) {
            if (!seen[r.templateId]) {
              seen[r.templateId] = true
              deduped.push(r)
            }
          })

          // Exclude templates matching already-run experiments
          var pastOverrides = expAllExperiments
            .filter(function(e) { return e.status === 'completed' || e.status === 'running' })
            .map(function(e) {
              return e.variants && e.variants.treatment ? JSON.stringify(e.variants.treatment) : '{}'
            })

          var filtered = deduped.filter(function(r) {
            var tpl = EXP_TEMPLATES.find(function(t) { return t.id === r.templateId })
            if (!tpl) return false
            var overridesStr = JSON.stringify(tpl.overrides)
            return pastOverrides.indexOf(overridesStr) === -1
          })

          // Render
          if (filtered.length === 0) {
            container.innerHTML = '<div class="text-center py-6">'
              + '<svg class="h-8 w-8 mx-auto mb-2 text-lime-400 dark:text-lime-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">'
              + '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>'
              + '</svg>'
              + '<p class="text-sm font-medium text-zinc-600 dark:text-zinc-400">All healthy</p>'
              + '<p class="text-xs text-zinc-500 dark:text-zinc-500 mt-1">Your search metrics look good — no tests recommended right now</p>'
              + '</div>'
            return
          }

          var impactColors = {
            HIGH: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
            MEDIUM: 'bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300',
            LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
          }

          container.innerHTML = '<div class="space-y-3">'
            + filtered.map(function(r) {
              var tpl = EXP_TEMPLATES.find(function(t) { return t.id === r.templateId })
              if (!tpl) return ''
              return '<div class="flex items-start justify-between gap-4 p-3 rounded-lg ring-1 ring-zinc-200 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800/50">'
                + '<div class="min-w-0">'
                + '<div class="flex items-center gap-2 mb-1">'
                + '<span class="inline-flex items-center rounded-full px-1.5 py-0.5 text-[10px] font-medium ' + (impactColors[r.impact] || '') + '">' + r.impact + '</span>'
                + '<span class="text-sm font-medium text-zinc-900 dark:text-white">' + tpl.name + '</span>'
                + '</div>'
                + '<p class="text-xs text-zinc-500 dark:text-zinc-400">' + r.reason + '</p>'
                + '</div>'
                + '<button type="button" onclick="openCreateExperiment(\\'' + r.templateId + '\\')" '
                + 'class="flex-shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium text-indigo-600 bg-indigo-50 hover:bg-indigo-100 dark:text-indigo-400 dark:bg-indigo-950/30 dark:hover:bg-indigo-900/50">'
                + 'Create This Test'
                + '</button>'
                + '</div>'
            }).join('')
            + '</div>'

        } catch (error) {
          console.error('Failed to load recommendations:', error)
          container.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400 text-center py-4">Could not load analytics data</p>'
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
