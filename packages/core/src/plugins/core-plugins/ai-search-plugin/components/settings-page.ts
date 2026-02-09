import { renderAdminLayout } from '../../../../templates/layouts/admin-layout-v2.template'
import type {
  AISearchSettings,
  CollectionInfo,
  IndexStatus,
  NewCollectionNotification,
} from '../types'

interface SettingsPageData {
  settings: AISearchSettings | null
  collections: CollectionInfo[]
  newCollections: NewCollectionNotification[]
  indexStatus: Record<number, IndexStatus>
  analytics: {
    total_queries: number
    ai_queries: number
    keyword_queries: number
    fts5_queries: number
    hybrid_queries: number
    popular_queries: Array<{ query: string; count: number }>
    average_query_time: number
  }
  user?: {
    name: string
    email: string
    role: string
  }
}

export function renderSettingsPage(data: SettingsPageData): string {
  const settings = data.settings || {
    enabled: false,
    ai_mode_enabled: true,
    selected_collections: [],
    dismissed_collections: [],
    autocomplete_enabled: true,
    cache_duration: 1,
    results_limit: 20,
    index_media: false,
  }

  // Ensure arrays exist
  const selectedCollections = Array.isArray(settings.selected_collections) ? settings.selected_collections : []
  const dismissedCollections = Array.isArray(settings.dismissed_collections) ? settings.dismissed_collections : []

  const enabled = settings.enabled === true
  const aiModeEnabled = settings.ai_mode_enabled !== false
  const autocompleteEnabled = settings.autocomplete_enabled !== false
  const indexMedia = settings.index_media === true

  const selectedCollectionIds = new Set(selectedCollections.map(id => String(id)))
  const dismissedCollectionIds = new Set(dismissedCollections.map(id => String(id)))

  // Ensure collections array exists
  const collections = Array.isArray(data.collections) ? data.collections : []

  // Debug: Log collections in template
  console.log('[SettingsPage Template] Collections received:', collections.length)
  if (collections.length > 0) {
    console.log('[SettingsPage Template] First collection:', collections[0])
  }

  const content = `
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Header with Back Button -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">🔍 AI Search Settings</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Configure advanced search with Cloudflare AI Search. Select collections to index and manage search preferences.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none flex gap-3">
          <a href="/admin/plugins/ai-search/integration" target="_blank" class="inline-flex items-center justify-center rounded-lg bg-green-600 hover:bg-green-700 px-3.5 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
            Headless Guide
          </a>
          <a href="/admin/plugins/ai-search/test" target="_blank" class="inline-flex items-center justify-center rounded-lg bg-indigo-600 hover:bg-indigo-700 px-3.5 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/>
            </svg>
            Test Search
          </a>
          <a href="/admin/plugins" class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back to Plugins
          </a>
        </div>
      </div>


          <!-- Main Settings Card -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
            <form id="settingsForm" class="space-y-6">
              <!-- Enable Search Section -->
              <div>
                <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-4">🔍 Search Settings</h2>
                <div class="space-y-3">
                  <div class="flex items-center gap-3 p-4 border border-indigo-200 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg">
                    <input type="checkbox" id="enabled" name="enabled" ${enabled ? 'checked' : ''} class="w-5 h-5 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">
                    <div class="flex-1">
                      <label for="enabled" class="text-base font-semibold text-zinc-900 dark:text-white select-none cursor-pointer block">Enable AI Search</label>
                      <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">Turn on advanced search capabilities across your content</p>
                    </div>
                  </div>

                  <div class="flex items-center gap-3 p-4 border border-blue-200 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <input type="checkbox" id="ai_mode_enabled" name="ai_mode_enabled" ${aiModeEnabled ? 'checked' : ''} class="w-5 h-5 rounded border-gray-300 text-blue-600 focus:ring-blue-500 cursor-pointer">
                    <div class="flex-1">
                      <label for="ai_mode_enabled" class="text-base font-semibold text-zinc-900 dark:text-white select-none cursor-pointer block">🤖 AI/Semantic Search</label>
                      <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">
                        Enable natural language queries (requires Cloudflare Workers AI binding)
                        <a href="https://developers.cloudflare.com/workers-ai/" target="_blank" class="text-blue-600 dark:text-blue-400 hover:underline ml-1">→ Setup Guide</a>
                      </p>
                      <p class="text-xs text-amber-600 dark:text-amber-400 mt-1">
                        ⚠️ If AI binding unavailable, will fallback to keyword search
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <hr class="border-zinc-200 dark:border-zinc-800">

              <!-- Collections Section -->
              <div>
                <div class="flex items-start justify-between mb-4">
                  <div>
                    <h2 class="text-xl font-semibold text-zinc-950 dark:text-white">📚 Collections to Index</h2>
                    <p class="text-sm text-zinc-600 dark:text-zinc-400 mt-1">
                      Select which content collections should be indexed and searchable. Only checked collections will be included in search results.
                    </p>
                  </div>
                </div>
            <div class="space-y-3 max-h-96 overflow-y-auto border-2 border-zinc-300 dark:border-zinc-700 rounded-lg p-4 bg-white dark:bg-zinc-800" id="collections-list">
              ${collections.length === 0
      ? '<p class="text-sm text-zinc-500 dark:text-zinc-400 p-4">No collections available. Create collections first.</p>'
      : collections.map((collection) => {
        const collectionId = String(collection.id)
        const isChecked = selectedCollectionIds.has(collectionId)
        const isDismissed = dismissedCollectionIds.has(collectionId)
        const indexStatusMap: Record<string, any> = data.indexStatus || {}
        const status = indexStatusMap[collectionId]
        // Only show NEW badge if collection is new, not dismissed, and has never been indexed
        const isNew = collection.is_new === true && !isDismissed && !status
        // Only show status badge if collection is CHECKED and has status
        const statusBadge = (status && isChecked)
          ? `<span class="ml-2 px-2 py-1 text-xs rounded-full ${status.status === 'completed'
            ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
            : status.status === 'indexing'
              ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300'
              : status.status === 'error'
                ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                : 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300'
          }">${status.status}</span>`
          : ''

        return `<div class="flex items-start gap-3 p-3 rounded-lg border border-zinc-200 dark:border-zinc-700 ${isNew ? 'bg-blue-50 dark:bg-blue-900/10 border-blue-200 dark:border-blue-800' : 'hover:bg-zinc-50 dark:hover:bg-zinc-800'}">
                      <input
                        type="checkbox"
                        id="collection_${collectionId}"
                        name="selected_collections"
                        value="${collectionId}"
                        ${isChecked ? 'checked' : ''}
                        class="mt-1 w-5 h-5 text-indigo-600 bg-white border-gray-300 rounded focus:ring-indigo-500 focus:ring-2 cursor-pointer"
                        style="cursor: pointer; flex-shrink: 0;"
                      />
                      <div class="flex-1 min-w-0">
                        <label for="collection_${collectionId}" class="text-sm font-medium text-zinc-950 dark:text-white select-none cursor-pointer flex items-center">
                          ${collection.display_name || collection.name || 'Unnamed Collection'}
                          ${isNew ? '<span class="ml-2 px-2 py-0.5 text-xs rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">NEW</span>' : ''}
                          ${statusBadge}
                        </label>
                        <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                          ${collection.description || collection.name || 'No description'} • ${collection.item_count || 0} items
                          ${status ? ` • ${status.indexed_items}/${status.total_items} indexed` : ''}
                        </p>
                        ${status && status.status === 'indexing'
            ? `<div class="mt-2 w-full bg-gray-200 rounded-full h-2 dark:bg-gray-700">
                              <div class="bg-blue-600 h-2 rounded-full" style="width: ${(status.indexed_items / status.total_items) * 100}%"></div>
                            </div>`
            : ''}
                      </div>
                      ${isChecked ? `
                        <button
                          type="button"
                          onclick="reindexCollection('${collectionId}')"
                          class="px-3 py-1.5 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-md transition-colors flex items-center gap-1.5 whitespace-nowrap"
                          ${status && status.status === 'indexing' ? 'disabled' : ''}
                        >
                          <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                          </svg>
                          Re-index
                        </button>
                      ` : ''}
                    </div>`
      }).join('')}
            </div>
          </div>

              <hr class="border-zinc-200 dark:border-zinc-800">

              <!-- Advanced Options -->
              <div>
                <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-4">⚙️ Advanced Options</h2>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div class="flex items-start gap-3 p-3 border border-zinc-200 dark:border-zinc-700 rounded-lg">
                    <input type="checkbox" id="autocomplete_enabled" name="autocomplete_enabled" ${autocompleteEnabled ? 'checked' : ''} class="mt-0.5 w-5 h-5 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">
                    <div>
                      <label for="autocomplete_enabled" class="text-sm font-medium text-zinc-950 dark:text-white select-none cursor-pointer block">Autocomplete Suggestions</label>
                      <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Show search suggestions as users type</p>
                    </div>
                  </div>

                  <div class="flex items-start gap-3 p-3 border border-zinc-200 dark:border-zinc-700 rounded-lg">
                    <input type="checkbox" id="index_media" name="index_media" ${indexMedia ? 'checked' : ''} class="mt-0.5 w-5 h-5 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">
                    <div>
                      <label for="index_media" class="text-sm font-medium text-zinc-950 dark:text-white select-none cursor-pointer block">Index Media Metadata</label>
                      <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">Include media files in search results</p>
                    </div>
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Cache Duration (hours)</label>
                    <input type="number" id="cache_duration" name="cache_duration" value="${settings.cache_duration || 1}" min="0" max="24" class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
                  </div>
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Results Per Page</label>
                    <input type="number" id="results_limit" name="results_limit" value="${settings.results_limit || 20}" min="10" max="100" class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
                  </div>
                </div>
          </div>

              <hr class="border-zinc-200 dark:border-zinc-800">

              <!-- Hybrid Search Settings -->
              <div>
                <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Hybrid Search</h2>
                <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-4">
                  Hybrid mode combines FTS5 + AI search with Reciprocal Rank Fusion for best-quality results. Use <code>mode: "hybrid"</code> in your API requests.
                </p>
                <div class="space-y-3">
                  <div class="flex items-center gap-3 p-4 border border-purple-200 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                    <input type="checkbox" id="reranking_enabled" name="reranking_enabled" ${settings.reranking_enabled !== false ? 'checked' : ''} class="w-5 h-5 rounded border-gray-300 text-purple-600 focus:ring-purple-500 cursor-pointer">
                    <div class="flex-1">
                      <label for="reranking_enabled" class="text-base font-semibold text-zinc-900 dark:text-white select-none cursor-pointer block">AI Reranking</label>
                      <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">
                        Cross-encoder reranks results for better relevance. Adds ~50-150ms. Cost: ~$0.003/M tokens.
                      </p>
                    </div>
                  </div>
                  <div class="flex items-center gap-3 p-4 border border-amber-200 bg-amber-50 dark:bg-amber-900/20 rounded-lg">
                    <input type="checkbox" id="query_rewriting_enabled" name="query_rewriting_enabled" ${settings.query_rewriting_enabled ? 'checked' : ''} class="w-5 h-5 rounded border-gray-300 text-amber-600 focus:ring-amber-500 cursor-pointer">
                    <div class="flex-1">
                      <label for="query_rewriting_enabled" class="text-base font-semibold text-zinc-900 dark:text-white select-none cursor-pointer block">Query Rewriting (LLM)</label>
                      <p class="text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">
                        Expands vague queries using an LLM for better recall. Adds ~100-300ms. Best for large content libraries.
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <hr class="border-zinc-200 dark:border-zinc-800">

              <!-- FTS5 Full-Text Search Section -->
              <div>
                <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">FTS5 Full-Text Search</h2>
                <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-4">
                  SQLite FTS5 provides fast full-text search with BM25 ranking, stemming, and highlighting. No AI binding required.
                </p>
                <div id="fts5-status" class="p-4 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800 mb-4">
                  <div class="flex items-center justify-between">
                    <div>
                      <span class="text-sm font-medium text-zinc-700 dark:text-zinc-300" id="fts5-status-text">Checking FTS5 status...</span>
                      <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1" id="fts5-stats-text"></p>
                    </div>
                    <button
                      type="button"
                      id="fts5-reindex-btn"
                      onclick="reindexFTS5All()"
                      class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                      disabled
                    >
                      <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                      </svg>
                      Reindex All (FTS5)
                    </button>
                  </div>
                </div>
              </div>

              <!-- Save Button -->
              <div class="flex items-center justify-between pt-4 border-t border-zinc-200 dark:border-zinc-800">
                <p class="text-xs text-zinc-500 dark:text-zinc-400">
                  💡 Collections marked as <span class="px-1.5 py-0.5 text-xs font-medium rounded-full bg-blue-500 text-white">NEW</span> haven't been indexed yet
                </p>
                <button type="submit" class="inline-flex items-center justify-center rounded-lg bg-indigo-600 text-white px-6 py-2.5 text-sm font-semibold hover:bg-indigo-500 shadow-sm transition-colors">
                  💾 Save Settings
                </button>
              </div>
        </form>
      </div>


          <!-- Search Analytics -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-4">📊 Search Analytics</h2>
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <div class="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800">
            <div class="text-sm text-zinc-500 dark:text-zinc-400">Total Queries</div>
            <div class="text-2xl font-bold text-zinc-950 dark:text-white mt-1">${data.analytics.total_queries}</div>
          </div>
          <div class="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800">
            <div class="text-sm text-zinc-500 dark:text-zinc-400">AI Queries</div>
            <div class="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-1">${data.analytics.ai_queries}</div>
          </div>
          <div class="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800">
            <div class="text-sm text-zinc-500 dark:text-zinc-400">Keyword Queries</div>
            <div class="text-2xl font-bold text-indigo-600 dark:text-indigo-400 mt-1">${data.analytics.keyword_queries}</div>
          </div>
          <div class="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800">
            <div class="text-sm text-zinc-500 dark:text-zinc-400">FTS5 Queries</div>
            <div class="text-2xl font-bold text-green-600 dark:text-green-400 mt-1">${data.analytics.fts5_queries || 0}</div>
          </div>
          <div class="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800">
            <div class="text-sm text-zinc-500 dark:text-zinc-400">Hybrid Queries</div>
            <div class="text-2xl font-bold text-purple-600 dark:text-purple-400 mt-1">${data.analytics.hybrid_queries || 0}</div>
          </div>
        </div>
        ${data.analytics.popular_queries.length > 0
      ? `
              <div>
                <h3 class="text-sm font-semibold text-zinc-950 dark:text-white mb-2">Popular Searches</h3>
                <div class="space-y-1">
                  ${data.analytics.popular_queries.map(
        (item) => `
                      <div class="flex items-center justify-between text-sm">
                        <span class="text-zinc-700 dark:text-zinc-300">"${item.query}"</span>
                        <span class="text-zinc-500 dark:text-zinc-400">${item.count} times</span>
                      </div>
                    `
      ).join('')}
                </div>
              </div>
            `
      : '<p class="text-sm text-zinc-500 dark:text-zinc-400">No search history yet.</p>'}
      </div>

          <!-- Success Message -->
          <div id="msg" class="hidden fixed bottom-4 right-4 p-4 rounded-lg bg-green-50 text-green-900 border border-green-200 dark:bg-green-900/20 dark:text-green-100 dark:border-green-800 shadow-lg z-50">
            <div class="flex items-center gap-2">
              <span class="text-xl">✅</span>
              <span class="font-semibold">Settings Saved Successfully!</span>
            </div>
          </div>
    </div>
    <script>
      // Form submission with error handling
      document.getElementById('settingsForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        console.log('[AI Search Client] Form submitted');
        
        try {
          const btn = e.submitter;
          btn.innerText = 'Saving...'; 
          btn.disabled = true;
          
          const formData = new FormData(e.target);
          const selectedCollections = Array.from(formData.getAll('selected_collections')).map(String);
          
          const data = {
            enabled: document.getElementById('enabled').checked,
            ai_mode_enabled: document.getElementById('ai_mode_enabled').checked,
            selected_collections: selectedCollections,
            autocomplete_enabled: document.getElementById('autocomplete_enabled').checked,
            cache_duration: Number(formData.get('cache_duration')),
            results_limit: Number(formData.get('results_limit')),
            index_media: document.getElementById('index_media').checked,
            reranking_enabled: document.getElementById('reranking_enabled').checked,
            query_rewriting_enabled: document.getElementById('query_rewriting_enabled').checked,
          };
          
          console.log('[AI Search Client] Sending data:', data);
          console.log('[AI Search Client] Selected collections:', selectedCollections);
          
          const res = await fetch('/admin/plugins/ai-search', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify(data) 
          });
          
          console.log('[AI Search Client] Response status:', res.status);
          
          if (res.ok) {
            const result = await res.json();
            console.log('[AI Search Client] Save successful:', result);
            document.getElementById('msg').classList.remove('hidden'); 
            setTimeout(() => {
              document.getElementById('msg').classList.add('hidden');
              location.reload();
            }, 2000); 
          } else {
            const error = await res.text();
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

      // Add collection to index
      async function addCollectionToIndex(collectionId) {
        const form = document.getElementById('settingsForm');
        const checkbox = document.getElementById('collection_' + collectionId);
        if (checkbox) {
          checkbox.checked = true;
          form.dispatchEvent(new Event('submit'));
        }
      }

      // Dismiss collection
      async function dismissCollection(collectionId) {
        const res = await fetch('/admin/plugins/ai-search', {
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

      // Re-index collection
      async function reindexCollection(collectionId) {
        const res = await fetch('/admin/plugins/ai-search/api/reindex', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ collection_id: collectionId })
        });
        if (res.ok) {
          alert('Re-indexing started. Page will refresh in a moment.');
          setTimeout(() => location.reload(), 2000);
        } else {
          alert('Failed to start re-indexing. Please try again.');
        }
      }

      // Poll for index status updates
      setInterval(async () => {
        const res = await fetch('/admin/plugins/ai-search/api/status');
        if (res.ok) {
          const { data } = await res.json();
          // Update status indicators if needed
          // For now, just reload every 30 seconds if indexing is in progress
          const hasIndexing = Object.values(data).some((s) => s.status === 'indexing');
          if (hasIndexing) {
            location.reload();
          }
        }
      }, 30000);

      // FTS5 status check on load
      (async function checkFTS5Status() {
        try {
          const res = await fetch('/admin/plugins/ai-search/api/fts5/status');
          if (res.ok) {
            const { data } = await res.json();
            const statusText = document.getElementById('fts5-status-text');
            const statsText = document.getElementById('fts5-stats-text');
            const reindexBtn = document.getElementById('fts5-reindex-btn');
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

      // Reindex all collections for FTS5
      async function reindexFTS5All() {
        const btn = document.getElementById('fts5-reindex-btn');
        btn.disabled = true;
        btn.textContent = 'Reindexing...';
        try {
          const res = await fetch('/admin/plugins/ai-search/api/fts5/reindex-all', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (res.ok) {
            const result = await res.json();
            alert('FTS5 reindex started for ' + (result.collections?.length || 0) + ' collections');
            setTimeout(() => location.reload(), 3000);
          } else {
            alert('Failed to start FTS5 reindex');
            btn.disabled = false;
            btn.textContent = 'Reindex All (FTS5)';
          }
        } catch (e) {
          alert('Error: ' + e.message);
          btn.disabled = false;
          btn.textContent = 'Reindex All (FTS5)';
        }
      }
    </script>
  `

  return renderAdminLayout({
    title: 'AI Search Settings',
    pageTitle: 'AI Search Settings',
    currentPath: '/admin/plugins/ai-search/settings',
    user: data.user,
    content: content
  })
}
