/**
 * Admin Search Dashboard — Configuration Tab
 *
 * Collections to index, settings toggles, reindexing controls,
 * and faceted search configuration.
 */

import type { TabProps } from './admin-search.template'

export function renderConfigTab(props: TabProps): string {
  const {
    collections, selectedCollectionIds, dismissedCollectionIds,
    enabled, aiModeEnabled, autocompleteEnabled, indexMedia,
    settings, vectorizeStatusText, facetsEnabled, data
  } = props

  return `
      <div id="tab-configuration" class="tab-panel hidden">
        <form id="settingsForm" class="space-y-6">

          <!-- Collections to Index -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-4">
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-1">Collections to Index</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">Select which collections are included in search. Rebuild indexes below after changes.</p>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2" id="collections-list">
              ${collections.length === 0
                ? '<p class="text-sm text-zinc-500 dark:text-zinc-400 col-span-2">No collections available.</p>'
                : collections.map((collection) => {
                  const collectionId = String(collection.id)
                  const isChecked = selectedCollectionIds.has(collectionId)
                  const isDismissed = dismissedCollectionIds.has(collectionId)
                  const colStatus = (data.indexStatus || {})[collectionId]
                  const isNew = collection.is_new === true && !isDismissed && !colStatus

                  return `<label for="col_${collectionId}" class="flex items-center gap-2.5 px-3 py-2 rounded-md border ${isChecked ? 'border-indigo-300 bg-indigo-50 dark:border-indigo-700 dark:bg-indigo-900/20' : 'border-zinc-200 dark:border-zinc-700'} hover:bg-zinc-50 dark:hover:bg-zinc-800 cursor-pointer select-none transition-colors">
                    <input type="checkbox" id="col_${collectionId}" name="selected_collections" value="${collectionId}" ${isChecked ? 'checked' : ''}
                      class="w-4 h-4 text-indigo-600 bg-white border-gray-300 rounded focus:ring-indigo-500 cursor-pointer" style="flex-shrink:0" />
                    <span class="flex-1 min-w-0 text-sm text-zinc-900 dark:text-zinc-100 truncate">${collection.display_name || collection.name || 'Unnamed'}</span>
                    <span class="text-xs text-zinc-400 dark:text-zinc-500 whitespace-nowrap">${collection.item_count || 0}</span>
                    ${isNew ? '<span class="px-1.5 py-0.5 text-[10px] font-medium rounded bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">NEW</span>' : ''}
                  </label>`
                }).join('')}
            </div>
          </div>

          <!-- Settings: two-column -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-5">
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-1">Settings</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">Configure search behavior, hybrid mode, and advanced options.</p>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <!-- Left: Enable Search + Options -->
              <div class="space-y-4">
                <h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider">Search Mode</h3>
                <div class="flex items-center gap-3 p-3 border border-indigo-200 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg">
                  <input type="checkbox" id="enabled" name="enabled" ${enabled ? 'checked' : ''} class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">
                  <div class="flex-1">
                    <label for="enabled" class="text-sm font-medium text-zinc-900 dark:text-white select-none cursor-pointer block">Enable Search</label>
                    <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">Turn on search capabilities across your content</p>
                  </div>
                </div>

                <div class="grid grid-cols-2 gap-2">
                  <div class="flex items-center gap-2.5 p-3 border border-zinc-200 dark:border-zinc-700 rounded-lg">
                    <input type="checkbox" id="autocomplete_enabled" name="autocomplete_enabled" ${autocompleteEnabled ? 'checked' : ''} class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">
                    <div>
                      <label for="autocomplete_enabled" class="text-sm font-medium text-zinc-950 dark:text-white select-none cursor-pointer block">Autocomplete</label>
                      <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Suggestions as you type</p>
                    </div>
                  </div>
                  <div class="flex items-center gap-2.5 p-3 border border-zinc-200 dark:border-zinc-700 rounded-lg">
                    <input type="checkbox" id="index_media" name="index_media" ${indexMedia ? 'checked' : ''} class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">
                    <div>
                      <label for="index_media" class="text-sm font-medium text-zinc-950 dark:text-white select-none cursor-pointer block">Index Media</label>
                      <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Include media in results</p>
                    </div>
                  </div>
                  <div class="p-3 border border-zinc-200 dark:border-zinc-700 rounded-lg">
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Cache (hours)</label>
                    <input type="number" id="cache_duration" name="cache_duration" value="${settings.cache_duration || 1}" min="0" max="24" class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
                  </div>
                  <div class="p-3 border border-zinc-200 dark:border-zinc-700 rounded-lg">
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-1.5">Results / Page</label>
                    <input type="number" id="results_limit" name="results_limit" value="${settings.results_limit || 20}" min="10" max="100" class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
                  </div>
                </div>
              </div>

              <!-- Right: AI / Semantic + Hybrid -->
              <div class="space-y-4">
                <h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider">AI / Semantic Search</h3>
                <div class="flex items-center gap-3 p-3 border border-blue-200 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <input type="checkbox" id="ai_mode_enabled" name="ai_mode_enabled" ${aiModeEnabled ? 'checked' : ''} class="w-4 h-4 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer">
                  <div class="flex-1">
                    <label for="ai_mode_enabled" class="text-sm font-medium text-zinc-900 dark:text-white select-none cursor-pointer block">Enable AI / Semantic Search</label>
                    <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">Natural language queries via Workers AI <a href="https://developers.cloudflare.com/workers-ai/" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline">Setup</a></p>
                  </div>
                </div>
                <div class="flex items-center gap-3 p-3 border border-purple-200 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                  <input type="checkbox" id="reranking_enabled" name="reranking_enabled" ${settings.reranking_enabled !== false ? 'checked' : ''} class="w-4 h-4 rounded border-gray-300 text-purple-600 focus:ring-purple-500 cursor-pointer">
                  <div class="flex-1">
                    <label for="reranking_enabled" class="text-sm font-medium text-zinc-900 dark:text-white select-none cursor-pointer block">AI Reranking</label>
                    <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">Cross-encoder reranks for better relevance (+50-150ms)</p>
                  </div>
                </div>
                <div class="flex items-center gap-3 p-3 border border-amber-200 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
                  <input type="checkbox" id="query_rewriting_enabled" name="query_rewriting_enabled" ${settings.query_rewriting_enabled ? 'checked' : ''} class="w-4 h-4 rounded border-gray-300 text-amber-600 focus:ring-amber-500 cursor-pointer">
                  <div class="flex-1">
                    <label for="query_rewriting_enabled" class="text-sm font-medium text-zinc-900 dark:text-white select-none cursor-pointer block">Query Rewriting (LLM)</label>
                    <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">Expands vague queries for better recall (+100-300ms)</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Reindexing: two-column -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-5">
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-1">Reindexing</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">Rebuild search indexes after changing collections or importing content.</p>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <!-- Left: FTS5 -->
              <div>
                <h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider mb-2">FTS5 Full-Text Search</h3>
                <p class="text-xs text-zinc-600 dark:text-zinc-400 mb-3">BM25 ranking, stemming, and highlighting. No AI binding required.</p>
                <div id="fts5-status" class="p-4 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800">
                  <div>
                    <span class="text-sm font-medium text-zinc-700 dark:text-zinc-300" id="fts5-status-text">Checking FTS5 status...</span>
                    <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1" id="fts5-stats-text"></p>
                  </div>
                  <button
                    type="button"
                    id="fts5-reindex-btn"
                    onclick="reindexFTS5All()"
                    class="mt-3 w-full px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition-colors flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    disabled
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Reindex FTS5
                  </button>
                </div>
              </div>

              <!-- Right: Vectorize -->
              <div>
                <h3 class="text-sm font-semibold text-zinc-900 dark:text-zinc-100 uppercase tracking-wider mb-2">Vectorize (AI / Hybrid)</h3>
                <p class="text-xs text-zinc-600 dark:text-zinc-400 mb-3">Semantic search via AI embeddings. Required for AI and Hybrid modes.</p>
                <div class="p-4 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800">
                  <div>
                    <span class="text-sm font-medium text-zinc-700 dark:text-zinc-300" id="vectorize-status-text">Vectorize binding available</span>
                    <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1" id="vectorize-stats-text">${vectorizeStatusText}</p>
                  </div>
                  <button
                    type="button"
                    id="vectorize-reindex-btn"
                    onclick="reindexVectorizeAll()"
                    class="mt-3 w-full px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors flex items-center justify-center gap-2"
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Reindex Vectorize
                  </button>
                  <div id="vectorize-progress-wrap" class="mt-3 hidden">
                    <div class="flex items-center justify-between mb-1">
                      <span class="text-xs text-zinc-500 dark:text-zinc-400" id="vectorize-progress-label">Embedding...</span>
                      <span class="text-xs font-medium text-zinc-700 dark:text-zinc-300" id="vectorize-progress-count">0/0</span>
                    </div>
                    <div class="w-full bg-gray-200 rounded-full h-2 dark:bg-gray-700">
                      <div id="vectorize-progress-bar" class="bg-purple-600 h-2 rounded-full transition-all duration-500" style="width: 0%"></div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Faceted Search -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-4 flex items-center justify-between">
              <div>
                <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-1">Faceted Search</h2>
                <p class="text-sm text-zinc-600 dark:text-zinc-400">
                  Auto-discovers filterable fields from your collection schemas.
                  Enable facets to show filter panels alongside search results.
                </p>
              </div>
              <div class="flex items-center gap-3">
                <label class="relative inline-flex items-center cursor-pointer">
                  <input type="checkbox" id="facets_enabled" name="facets_enabled" class="sr-only peer" onchange="toggleFacetsEnabled(this.checked)">
                  <div class="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-indigo-500 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-indigo-600"></div>
                  <span class="ml-2 text-sm font-medium text-zinc-900 dark:text-zinc-100">Enable</span>
                </label>
              </div>
            </div>

            <div id="facet-config-section" class="hidden">
              <div class="flex items-center justify-between mb-3">
                <span class="text-sm text-zinc-600 dark:text-zinc-400" id="facet-config-status">Loading facet configuration...</span>
                <button type="button" onclick="rediscoverFacets()" class="text-xs text-indigo-600 dark:text-indigo-400 hover:underline">Re-discover Fields</button>
              </div>
              <div class="overflow-x-auto">
                <table class="w-full text-sm" id="facet-config-table">
                  <thead>
                    <tr class="border-b border-zinc-200 dark:border-zinc-700">
                      <th class="text-left py-2 px-2 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Enabled</th>
                      <th class="text-left py-2 px-2 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Name</th>
                      <th class="text-left py-2 px-2 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Field</th>
                      <th class="text-left py-2 px-2 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Type</th>
                      <th class="text-left py-2 px-2 text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Source</th>
                    </tr>
                  </thead>
                  <tbody id="facet-config-body">
                    <tr><td colspan="5" class="py-4 text-center text-zinc-400">Loading...</td></tr>
                  </tbody>
                </table>
              </div>
              <div class="mt-3 flex justify-end">
                <button type="button" onclick="saveFacetConfig()" class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition-colors">
                  Save Facet Config
                </button>
              </div>
            </div>
          </div>

          <!-- Save Button -->
          <div class="flex items-center justify-end">
            <button type="submit" class="inline-flex items-center justify-center rounded-lg bg-indigo-600 text-white px-6 py-2.5 text-sm font-semibold hover:bg-indigo-500 shadow-sm transition-colors">
              Save Settings
            </button>
          </div>
        </form>
      </div>
  `
}

export function renderConfigScript(): string {
  return `
      // =============================================
      // Form submission with error handling
      // =============================================
      document.getElementById('settingsForm').addEventListener('submit', async function(e) {
        e.preventDefault();
        console.log('[AI Search Client] Form submitted');

        try {
          var btn = e.submitter;
          btn.innerText = 'Saving...';
          btn.disabled = true;

          var formData = new FormData(e.target);
          var selectedCollections = Array.from(formData.getAll('selected_collections')).map(String);

          var data = {
            enabled: document.getElementById('enabled').checked,
            ai_mode_enabled: document.getElementById('ai_mode_enabled').checked,
            selected_collections: selectedCollections,
            autocomplete_enabled: document.getElementById('autocomplete_enabled').checked,
            cache_duration: Number(formData.get('cache_duration')),
            results_limit: Number(formData.get('results_limit')),
            index_media: document.getElementById('index_media').checked,
            reranking_enabled: document.getElementById('reranking_enabled').checked,
            query_rewriting_enabled: document.getElementById('query_rewriting_enabled').checked,
            facets_enabled: document.getElementById('facets_enabled').checked,
            facet_config: facetConfigData.length > 0 ? facetConfigData : undefined,
          };

          console.log('[AI Search Client] Sending data:', data);
          console.log('[AI Search Client] Selected collections:', selectedCollections);

          var res = await fetch('/admin/plugins/ai-search', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data)
          });

          console.log('[AI Search Client] Response status:', res.status);

          if (res.ok) {
            var result = await res.json();
            console.log('[AI Search Client] Save successful:', result);
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() {
              document.getElementById('msg').classList.add('hidden');
              location.reload();
            }, 2000);
          } else {
            var error = await res.text();
            console.error('[AI Search Client] Save failed:', error);
            alert('Failed to save settings: ' + error);
          }

          btn.innerText = 'Save Settings';
          btn.disabled = false;
        } catch (error) {
          console.error('[AI Search Client] Error:', error);
          alert('Error saving settings: ' + error.message);
        }
      });

      // =============================================
      // Add collection to index
      // =============================================
      async function addCollectionToIndex(collectionId) {
        var form = document.getElementById('settingsForm');
        var checkbox = document.getElementById('collection_' + collectionId);
        if (checkbox) {
          checkbox.checked = true;
          form.dispatchEvent(new Event('submit'));
        }
      }

      // =============================================
      // Dismiss collection
      // =============================================
      async function dismissCollection(collectionId) {
        var res = await fetch('/admin/plugins/ai-search', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            dismissed_collections: [collectionId]
          })
        });
        if (res.ok) {
          location.reload();
        }
      }

      // =============================================
      // FTS5 status check on load
      // =============================================
      (async function checkFTS5Status() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/fts5/status');
          if (res.ok) {
            var body = await res.json();
            var data = body.data;
            var statusText = document.getElementById('fts5-status-text');
            var statsText = document.getElementById('fts5-stats-text');
            var reindexBtn = document.getElementById('fts5-reindex-btn');
            if (data.available) {
              statusText.textContent = 'FTS5 is available';
              statsText.textContent = data.total_indexed + ' items indexed across ' + Object.keys(data.by_collection || {}).length + ' collections';
              reindexBtn.disabled = false;
            } else {
              statusText.textContent = 'FTS5 tables not created yet';
              statsText.textContent = 'Run migrations to enable FTS5 full-text search.';
            }
          }
        } catch (e) {
          console.error('FTS5 status check failed:', e);
        }
      })();

      // =============================================
      // Reindex all collections for FTS5
      // =============================================
      async function reindexFTS5All() {
        var btn = document.getElementById('fts5-reindex-btn');
        btn.disabled = true;
        btn.textContent = 'Reindexing...';
        try {
          var res = await fetch('/admin/plugins/ai-search/api/fts5/reindex-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (res.ok) {
            var result = await res.json();
            alert('FTS5 reindex started for ' + (result.collections ? result.collections.length : 0) + ' collections');
            setTimeout(function() { location.reload(); }, 3000);
          } else {
            alert('Failed to start FTS5 reindex');
            btn.disabled = false;
            btn.textContent = 'Reindex FTS5';
          }
        } catch (e) {
          alert('Error: ' + e.message);
          btn.disabled = false;
          btn.textContent = 'Reindex FTS5';
        }
      }

      // =============================================
      // Reindex all collections for Vectorize
      // =============================================
      var vectorizePollTimer = null;

      async function reindexVectorizeAll() {
        var btn = document.getElementById('vectorize-reindex-btn');
        btn.disabled = true;
        btn.textContent = 'Reindexing...';
        var statsText = document.getElementById('vectorize-stats-text');
        var progressWrap = document.getElementById('vectorize-progress-wrap');
        try {
          var res = await fetch('/admin/plugins/ai-search/api/vectorize/reindex-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (res.ok) {
            var result = await res.json();
            var count = result.collections ? result.collections.length : 0;
            if (statsText) statsText.textContent = 'Reindexing ' + count + ' collection(s)...';
            if (progressWrap) progressWrap.classList.remove('hidden');
            startVectorizePoll();
          } else {
            var error = await res.json().catch(function() { return {}; });
            alert('Failed to start Vectorize reindex: ' + (error.error || 'Unknown error'));
            btn.disabled = false;
            btn.textContent = 'Reindex Vectorize';
          }
        } catch (e) {
          alert('Error: ' + e.message);
          btn.disabled = false;
          btn.textContent = 'Reindex Vectorize';
        }
      }

      function startVectorizePoll() {
        if (vectorizePollTimer) clearTimeout(vectorizePollTimer);
        pollVectorizeStatus();
      }

      async function pollVectorizeStatus() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/status');
          if (!res.ok) { vectorizePollTimer = setTimeout(pollVectorizeStatus, 3000); return; }
          var json = await res.json();
          var data = json.data || {};
          var totalItems = 0, indexedItems = 0, hasIndexing = false, hasCompleted = false;
          for (var colId in data) {
            var s = data[colId];
            totalItems += (s.total_items || 0);
            indexedItems += (s.indexed_items || 0);
            if (s.status === 'indexing') hasIndexing = true;
            if (s.status === 'completed') hasCompleted = true;
          }
          var pct = totalItems > 0 ? Math.round((indexedItems / totalItems) * 100) : 0;
          var bar = document.getElementById('vectorize-progress-bar');
          var label = document.getElementById('vectorize-progress-label');
          var countEl = document.getElementById('vectorize-progress-count');
          var statsText = document.getElementById('vectorize-stats-text');
          if (bar) bar.style.width = pct + '%';
          if (countEl) countEl.textContent = indexedItems + '/' + totalItems;
          if (label) label.textContent = hasIndexing ? 'Embedding & indexing...' : 'Complete';

          if (hasIndexing) {
            if (statsText) statsText.textContent = 'Indexing: ' + indexedItems + '/' + totalItems + ' items (' + pct + '%)';
            vectorizePollTimer = setTimeout(pollVectorizeStatus, 3000);
          } else {
            // Done
            var btn = document.getElementById('vectorize-reindex-btn');
            btn.disabled = false;
            btn.textContent = 'Reindex Vectorize';
            if (bar) bar.style.width = '100%';
            if (label) label.textContent = 'Complete';
            if (countEl) countEl.textContent = indexedItems + '/' + totalItems;
            if (statsText) statsText.textContent = 'Vectorize index: ' + totalItems + ' items indexed';
            setTimeout(function() {
              var wrap = document.getElementById('vectorize-progress-wrap');
              if (wrap) wrap.classList.add('hidden');
            }, 5000);
          }
        } catch (e) {
          vectorizePollTimer = setTimeout(pollVectorizeStatus, 5000);
        }
      }

      // Auto-start Vectorize polling if indexing is already in progress
      (async function checkVectorizeOnLoad() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/status');
          if (res.ok) {
            var json = await res.json();
            var data = json.data || {};
            var hasIndexing = false;
            for (var colId in data) {
              if (data[colId].status === 'indexing') hasIndexing = true;
            }
            if (hasIndexing) {
              var wrap = document.getElementById('vectorize-progress-wrap');
              var btn = document.getElementById('vectorize-reindex-btn');
              if (wrap) wrap.classList.remove('hidden');
              if (btn) { btn.disabled = true; btn.textContent = 'Reindexing...'; }
              startVectorizePoll();
            }
          }
        } catch (e) { /* ignore */ }
      })();

      // ==========================================
      // Faceted Search Configuration
      // ==========================================
      var facetConfigData = []; // Current facet config array

      var facetConfigLoaded = false;

      function toggleFacetsEnabled(enabled) {
        var section = document.getElementById('facet-config-section');
        if (enabled) {
          section.classList.remove('hidden');
          if (!facetConfigLoaded) {
            loadFacetConfig(true);
          }
        } else {
          section.classList.add('hidden');
        }
      }

      async function loadFacetConfig(keepToggleState) {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/facets/config');
          var json = await res.json();
          if (!json.success) throw new Error('Failed to load config');

          var toggle = document.getElementById('facets_enabled');

          // Only set the toggle from DB on initial page load, not when
          // the user just clicked it (keepToggleState = true)
          if (!keepToggleState) {
            toggle.checked = json.data.enabled;
            if (json.data.enabled) {
              document.getElementById('facet-config-section').classList.remove('hidden');
            }
          }

          facetConfigData = json.data.config || [];
          facetConfigLoaded = true;

          if (facetConfigData.length === 0 && (toggle.checked || json.data.enabled)) {
            // Auto-generate on first load
            await autoGenerateFacets();
            return;
          }

          renderFacetConfigTable(facetConfigData);
        } catch (error) {
          console.error('Error loading facet config:', error);
          document.getElementById('facet-config-status').textContent = 'Error loading facet configuration';
        }
      }

      async function autoGenerateFacets() {
        try {
          document.getElementById('facet-config-status').textContent = 'Auto-discovering fields...';
          var res = await fetch('/admin/plugins/ai-search/api/facets/auto-generate', { method: 'POST' });
          var json = await res.json();
          if (!json.success) throw new Error('Failed to auto-generate');

          facetConfigData = json.data.config || [];
          document.getElementById('facet-config-status').textContent =
            'Discovered ' + json.data.discovered_count + ' fields, auto-enabled ' + json.data.auto_enabled_count;
          renderFacetConfigTable(facetConfigData);
        } catch (error) {
          console.error('Error auto-generating facets:', error);
          document.getElementById('facet-config-status').textContent = 'Error: ' + error.message;
        }
      }

      async function rediscoverFacets() {
        try {
          document.getElementById('facet-config-status').textContent = 'Re-discovering fields...';
          var res = await fetch('/admin/plugins/ai-search/api/facets/discover');
          var json = await res.json();
          if (!json.success) throw new Error('Failed to discover');

          var discovered = json.data || [];
          // Merge: keep existing config, add new discovered fields
          var existingFields = new Set(facetConfigData.map(function(f) { return f.field; }));
          var newFields = discovered.filter(function(d) { return !existingFields.has(d.field); });

          for (var i = 0; i < newFields.length; i++) {
            facetConfigData.push({
              name: newFields[i].title,
              field: newFields[i].field,
              type: newFields[i].type,
              collections: newFields[i].collections.map(function(c) { return c.id; }),
              enabled: newFields[i].recommended,
              source: 'auto',
              position: facetConfigData.length
            });
          }

          document.getElementById('facet-config-status').textContent =
            discovered.length + ' fields found' + (newFields.length > 0 ? ', ' + newFields.length + ' new' : '');
          renderFacetConfigTable(facetConfigData);
        } catch (error) {
          console.error('Error re-discovering facets:', error);
          document.getElementById('facet-config-status').textContent = 'Error: ' + error.message;
        }
      }

      function renderFacetConfigTable(config) {
        var tbody = document.getElementById('facet-config-body');
        if (!config || config.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" class="py-4 text-center text-zinc-400">No facets configured. Click "Re-discover Fields" to scan collection schemas.</td></tr>';
          return;
        }

        var typeBadge = function(type) {
          switch (type) {
            case 'builtin': return '<span class="px-1.5 py-0.5 text-[10px] font-medium rounded bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">built-in</span>';
            case 'json_array': return '<span class="px-1.5 py-0.5 text-[10px] font-medium rounded bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">array</span>';
            case 'json_scalar': return '<span class="px-1.5 py-0.5 text-[10px] font-medium rounded bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">scalar</span>';
            default: return '<span class="px-1.5 py-0.5 text-[10px] font-medium rounded bg-zinc-100 text-zinc-600">' + type + '</span>';
          }
        };
        var sourceBadge = function(source) {
          switch (source) {
            case 'auto': return '<span class="text-xs text-zinc-400">auto</span>';
            case 'manual': return '<span class="text-xs text-indigo-500">manual</span>';
            case 'agent': return '<span class="text-xs text-purple-500">agent</span>';
            default: return '<span class="text-xs text-zinc-400">' + (source || 'auto') + '</span>';
          }
        };

        var html = '';
        for (var i = 0; i < config.length; i++) {
          var f = config[i];
          html += '<tr class="border-b border-zinc-100 dark:border-zinc-800">' +
            '<td class="py-2 px-2"><input type="checkbox" ' + (f.enabled ? 'checked' : '') + ' onchange="toggleFacetConfig(' + i + ', this.checked)" class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"></td>' +
            '<td class="py-2 px-2 text-sm text-zinc-900 dark:text-zinc-100">' + (f.name || f.field) + '</td>' +
            '<td class="py-2 px-2 text-xs font-mono text-zinc-500 dark:text-zinc-400">' + f.field + '</td>' +
            '<td class="py-2 px-2">' + typeBadge(f.type) + '</td>' +
            '<td class="py-2 px-2">' + sourceBadge(f.source) + '</td>' +
            '</tr>';
        }
        tbody.innerHTML = html;
        document.getElementById('facet-config-status').textContent = config.length + ' facets configured, ' + config.filter(function(f) { return f.enabled; }).length + ' enabled';
      }

      function toggleFacetConfig(index, enabled) {
        if (facetConfigData[index]) {
          facetConfigData[index].enabled = enabled;
          // If manually changed, update source
          if (facetConfigData[index].source !== 'manual') {
            facetConfigData[index].source = 'manual';
          }
          renderFacetConfigTable(facetConfigData);
        }
      }

      async function saveFacetConfig() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/facets/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              enabled: document.getElementById('facets_enabled').checked,
              config: facetConfigData
            })
          });
          var json = await res.json();
          if (json.success) {
            document.getElementById('facet-config-status').textContent = 'Facet configuration saved!';
            setTimeout(function() {
              renderFacetConfigTable(facetConfigData);
            }, 2000);
          } else {
            document.getElementById('facet-config-status').textContent = 'Error saving: ' + (json.error || 'Unknown error');
          }
        } catch (error) {
          console.error('Error saving facet config:', error);
          document.getElementById('facet-config-status').textContent = 'Error: ' + error.message;
        }
      }

      // Load facet config on page load (if on configuration tab)
      if (initTab === 'configuration') {
        loadFacetConfig();
      }
  `
}
