/**
 * @deprecated Superseded by /admin/search (Phase 1).
 * See: src/routes/admin-search.ts + src/templates/pages/admin-search.template.ts
 * The plugin GET / route now redirects to /admin/search.
 * Kept for one release cycle — remove after v2.9.
 */
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
                        </p>
                      </div>
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

          <!-- Search Benchmark (BEIR SciFact) -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Search Benchmark</h2>
            <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-4">
              BEIR SciFact dataset — scientific abstracts with 300+ test queries and ground-truth relevance judgments.
              Seed the data, index it, then evaluate search quality with standard IR metrics (nDCG@10, Precision, Recall, MRR).
            </p>
            <div id="benchmark-status" class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Checking benchmark status...</div>

            <!-- Corpus Size + Seed Row -->
            <div class="flex flex-wrap items-center gap-3 mb-4">
              <div class="flex items-center gap-2">
                <label for="bench-corpus-size" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Corpus:</label>
                <select id="bench-corpus-size"
                  class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                  <option value="subset">Subset (~483 docs)</option>
                  <option value="full">Full corpus (~5K docs)</option>
                </select>
              </div>
              <button onclick="seedBenchmark()" id="bench-seed-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed">
                Seed Data
              </button>
              <button onclick="indexBenchmark()" id="bench-index-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                Index (FTS5)
              </button>
              <button onclick="indexBenchmarkVectorize()" id="bench-vectorize-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                Index (Vectorize)
              </button>
              <button onclick="purgeBenchmark()" id="bench-purge-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                Purge Data
              </button>
            </div>

            <!-- Evaluate Buttons Row -->
            <div class="flex flex-wrap items-center gap-3 mb-4">
              <span class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Evaluate:</span>
              <div class="flex items-center gap-2">
                <label for="bench-query-count" class="text-sm text-zinc-600 dark:text-zinc-400">Queries:</label>
                <select id="bench-query-count"
                  class="rounded-lg bg-white dark:bg-zinc-800 px-2 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                  <option value="15">15</option>
                  <option value="50">50</option>
                  <option value="100">100</option>
                  <option value="0" selected>All (~301)</option>
                </select>
              </div>
              <button onclick="runBenchmark('fts5')" id="bench-fts5-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                FTS5
              </button>
              <button onclick="runBenchmark('keyword')" id="bench-keyword-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-zinc-600 hover:bg-zinc-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                Keyword
              </button>
              <button onclick="runBenchmark('hybrid')" id="bench-hybrid-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                Hybrid
              </button>
              <button onclick="runBenchmark('ai')" id="bench-ai-btn"
                class="px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
                AI (Vectorize)
              </button>
            </div>
            <p class="text-xs text-zinc-400 dark:text-zinc-500 mb-4">
              Hybrid and AI modes require Vectorize index binding. If unavailable, they will return an error.
            </p>

            <div id="benchmark-progress" class="hidden mb-4">
              <div class="text-sm text-zinc-600 dark:text-zinc-400 mb-1" id="benchmark-progress-text">Running...</div>
              <div class="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-2">
                <div id="benchmark-progress-bar" class="bg-indigo-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
              </div>
            </div>
            <div id="benchmark-results" class="hidden">
              <div class="p-4 rounded-lg bg-zinc-50 dark:bg-zinc-800">
                <h3 class="text-sm font-semibold text-zinc-950 dark:text-white mb-3" id="benchmark-results-title">Results</h3>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3" id="benchmark-metrics"></div>
                <div class="text-xs text-zinc-500 dark:text-zinc-400" id="benchmark-details"></div>
              </div>
            </div>
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

      // --- Benchmark Functions ---

      // Check benchmark status on page load
      (async function checkBenchmarkStatus() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/status');
          if (res.ok) {
            var body = await res.json();
            var d = body.data;
            var statusEl = document.getElementById('benchmark-status');
            var corpusSelect = document.getElementById('bench-corpus-size');

            // Update corpus size options with actual counts
            if (d.subset_size && d.corpus_size) {
              corpusSelect.options[0].textContent = 'Subset (~' + d.subset_size + ' docs)';
              corpusSelect.options[1].textContent = 'Full corpus (' + d.corpus_size + ' docs)';
            }

            if (d.seeded) {
              statusEl.textContent = 'Benchmark data seeded: ' + d.seeded_count + ' documents (queries: ' + d.query_count + ', qrels: ' + d.qrel_count + ')';
              document.getElementById('bench-seed-btn').textContent = 'Re-seed Data';
              document.getElementById('bench-index-btn').disabled = false;
              document.getElementById('bench-vectorize-btn').disabled = false;
              document.getElementById('bench-fts5-btn').disabled = false;
              document.getElementById('bench-keyword-btn').disabled = false;
              document.getElementById('bench-hybrid-btn').disabled = false;
              document.getElementById('bench-ai-btn').disabled = false;
              document.getElementById('bench-purge-btn').disabled = false;
            } else {
              statusEl.textContent = 'Dataset: ' + d.dataset + ' (' + d.corpus_size + ' docs, ' + d.query_count + ' queries, ' + d.qrel_count + ' qrels) — Not yet seeded';
            }
          }
        } catch (e) {
          document.getElementById('benchmark-status').textContent = 'Could not check benchmark status';
        }
      })();

      async function seedBenchmark() {
        var btn = document.getElementById('bench-seed-btn');
        var corpusSize = document.getElementById('bench-corpus-size').value;
        btn.textContent = 'Seeding (' + corpusSize + ')...';
        btn.disabled = true;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/seed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ corpus_size: corpusSize })
          });
          var data = await res.json();
          if (data.success) {
            document.getElementById('benchmark-status').textContent = data.message;
            btn.textContent = 'Re-seed Data';
            document.getElementById('bench-index-btn').disabled = false;
            document.getElementById('bench-vectorize-btn').disabled = false;
            document.getElementById('bench-fts5-btn').disabled = false;
            document.getElementById('bench-keyword-btn').disabled = false;
            document.getElementById('bench-hybrid-btn').disabled = false;
            document.getElementById('bench-ai-btn').disabled = false;
            document.getElementById('bench-purge-btn').disabled = false;
          } else {
            alert('Seed failed: ' + (data.error || 'Unknown error'));
            btn.textContent = 'Seed Data';
          }
        } catch (e) {
          alert('Error: ' + e.message);
          btn.textContent = 'Seed Data';
        }
        btn.disabled = false;
      }

      async function indexBenchmark() {
        var btn = document.getElementById('bench-index-btn');
        btn.disabled = true;
        var statusEl = document.getElementById('benchmark-status');

        // Use batch endpoint — loop until all indexed
        var totalIndexed = 0;
        var remaining = 1; // start loop
        var batchNum = 0;

        while (remaining > 0) {
          batchNum++;
          btn.textContent = 'Indexing batch ' + batchNum + '...';
          try {
            var res = await fetch('/admin/plugins/ai-search/api/benchmark/index-fts5-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ batch_size: 200 })
            });
            var data = await res.json();
            if (!data.success) {
              alert('FTS5 indexing failed: ' + (data.error || 'Unknown error'));
              break;
            }
            totalIndexed += data.indexed;
            remaining = data.remaining;
            var done = data.total - remaining;
            statusEl.textContent = 'FTS5 indexing: ' + done + '/' + data.total + ' docs indexed...';
            btn.textContent = 'Indexing... (' + done + '/' + data.total + ')';
          } catch (e) {
            alert('FTS5 indexing error: ' + e.message);
            break;
          }
        }

        statusEl.textContent = 'FTS5 indexing complete: ' + totalIndexed + ' docs indexed in ' + batchNum + ' batches.';
        btn.textContent = 'Index (FTS5)';
        btn.disabled = false;
      }

      async function indexBenchmarkVectorize() {
        var btn = document.getElementById('bench-vectorize-btn');
        btn.disabled = true;
        var statusEl = document.getElementById('benchmark-status');

        // Reset index meta first
        try {
          await fetch('/admin/plugins/ai-search/api/benchmark/index-vectorize', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }
          });
        } catch (e) { /* continue anyway */ }

        // Client-driven batch loop — processes 25 docs per request
        var offset = 0;
        var remaining = 1;
        var batchNum = 0;
        var totalChunks = 0;

        while (remaining > 0) {
          batchNum++;
          btn.textContent = 'Embedding batch ' + batchNum + '...';
          try {
            var res = await fetch('/admin/plugins/ai-search/api/benchmark/index-vectorize-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ batch_size: 25, offset: offset })
            });
            var data = await res.json();
            if (!data.success) {
              alert('Vectorize indexing failed: ' + (data.error || 'Unknown error'));
              break;
            }
            totalChunks += data.indexed;
            offset = data.offset;
            remaining = data.remaining;
            var done = data.total - remaining;
            statusEl.textContent = 'Vectorize: ' + done + '/' + data.total + ' docs embedded (' + totalChunks + ' chunks)...';
            btn.textContent = 'Embedding... (' + done + '/' + data.total + ')';
          } catch (e) {
            alert('Vectorize indexing error: ' + e.message);
            break;
          }
        }

        statusEl.textContent = 'Vectorize indexing complete: ' + totalChunks + ' chunks indexed in ' + batchNum + ' batches.';
        btn.textContent = 'Index (Vectorize)';
        btn.disabled = false;
      }

      async function runBenchmark(mode) {
        var btn = document.getElementById('bench-' + mode + '-btn');
        var origText = btn.textContent;
        btn.textContent = 'Running...';
        btn.disabled = true;

        var progressDiv = document.getElementById('benchmark-progress');
        var progressText = document.getElementById('benchmark-progress-text');
        var progressBar = document.getElementById('benchmark-progress-bar');
        progressDiv.classList.remove('hidden');
        progressBar.style.width = '2%';

        var maxQueries = parseInt(document.getElementById('bench-query-count').value, 10);
        var BATCH_SIZE = 15;
        var startTime = Date.now();

        try {
          // Step 1: Get evaluable query IDs
          progressText.textContent = 'Fetching query list...';
          var idsRes = await fetch('/admin/plugins/ai-search/api/benchmark/query-ids?max_queries=' + maxQueries);
          var idsData = await idsRes.json();
          if (!idsData.success) {
            alert('Failed to get query IDs: ' + (idsData.error || 'Unknown error'));
            progressDiv.classList.add('hidden');
            btn.textContent = origText;
            btn.disabled = false;
            return;
          }

          var allQueryIds = idsData.query_ids;
          var totalQueries = allQueryIds.length;
          progressText.textContent = 'Evaluating ' + mode + ' mode: 0/' + totalQueries + ' queries...';

          // Step 2: Process in batches
          var allPerQuery = [];
          for (var i = 0; i < totalQueries; i += BATCH_SIZE) {
            var batchIds = allQueryIds.slice(i, i + BATCH_SIZE);
            var batchRes = await fetch('/admin/plugins/ai-search/api/benchmark/evaluate-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ mode: mode, limit: 10, query_ids: batchIds })
            });
            var batchData = await batchRes.json();

            if (!batchData.success) {
              alert('Batch evaluation failed: ' + (batchData.error || 'Unknown error'));
              break;
            }

            allPerQuery = allPerQuery.concat(batchData.per_query);
            var done = Math.min(i + BATCH_SIZE, totalQueries);
            var pct = Math.round((done / totalQueries) * 100);
            progressBar.style.width = pct + '%';
            progressText.textContent = 'Evaluating ' + mode + ' mode: ' + done + '/' + totalQueries + ' queries...';
          }

          // Step 3: Compute aggregate metrics client-side
          var totalTime = Date.now() - startTime;
          var n = allPerQuery.length;
          if (n > 0) {
            var sumNDCG = 0, sumPrec = 0, sumRecall = 0, sumMRR = 0;
            for (var j = 0; j < n; j++) {
              sumNDCG += allPerQuery[j].ndcg;
              sumPrec += allPerQuery[j].precision;
              sumRecall += allPerQuery[j].recall;
              sumMRR += allPerQuery[j].mrr;
            }
            var data = {
              success: true,
              mode: mode,
              limit: 10,
              queries_evaluated: n,
              total_time_ms: totalTime,
              avg_query_time_ms: Math.round(totalTime / n),
              metrics: {
                ndcg_at_k: sumNDCG / n,
                precision_at_k: sumPrec / n,
                recall_at_k: sumRecall / n,
                mrr: sumMRR / n
              },
              per_query: allPerQuery
            };
            progressBar.style.width = '100%';
            showBenchmarkResults(data, mode);
          } else {
            alert('No queries were evaluated.');
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }

        progressDiv.classList.add('hidden');
        btn.textContent = origText;
        btn.disabled = false;
      }

      // Persist benchmark results in localStorage across page refreshes
      var BENCH_STORAGE_KEY = 'sonicjs_benchmark_runs';

      function loadBenchmarkRuns() {
        try {
          var stored = localStorage.getItem(BENCH_STORAGE_KEY);
          return stored ? JSON.parse(stored) : [];
        } catch (e) { return []; }
      }

      function saveBenchmarkRuns(runs) {
        try { localStorage.setItem(BENCH_STORAGE_KEY, JSON.stringify(runs)); } catch (e) { /* ignore */ }
      }

      var benchmarkRuns = loadBenchmarkRuns();
      var benchmarkHistory = [];

      // Restore and render saved results on page load
      if (benchmarkRuns.length > 0) {
        renderAllBenchmarkRuns();
      }

      function showBenchmarkResults(data, mode) {
        var resultsDiv = document.getElementById('benchmark-results');

        // Store in current session history
        benchmarkHistory = benchmarkHistory.filter(function(h) { return h.mode !== mode; });
        benchmarkHistory.push({ mode: mode, data: data });

        // Also persist to localStorage with corpus label
        var corpusLabel = document.getElementById('bench-corpus-size').value;
        var runKey = corpusLabel + '_' + mode;
        var runEntry = {
          key: runKey,
          mode: mode,
          corpus: corpusLabel,
          corpus_size: data.corpus_size,
          metrics: data.metrics,
          limit: data.limit,
          queries_evaluated: data.queries_evaluated,
          total_time_ms: data.total_time_ms,
          avg_query_time_ms: data.avg_query_time_ms,
          timestamp: new Date().toISOString()
        };
        benchmarkRuns = benchmarkRuns.filter(function(r) { return r.key !== runKey; });
        benchmarkRuns.push(runEntry);
        saveBenchmarkRuns(benchmarkRuns);

        renderAllBenchmarkRuns();
        resultsDiv.classList.remove('hidden');
      }

      function renderAllBenchmarkRuns() {
        var resultsDiv = document.getElementById('benchmark-results');
        var titleEl = document.getElementById('benchmark-results-title');
        var metricsDiv = document.getElementById('benchmark-metrics');
        var detailsDiv = document.getElementById('benchmark-details');

        if (benchmarkRuns.length === 0) {
          resultsDiv.classList.add('hidden');
          return;
        }

        titleEl.textContent = 'Benchmark Results (k=10)';

        var modeColors = { fts5: 'indigo', keyword: 'zinc', hybrid: 'purple', ai: 'cyan' };
        var modeNotes = {
          keyword: 'LIKE substring',
          hybrid: 'FTS5 + AI/RRF',
          ai: 'Semantic/Vectorize'
        };

        // Group runs by corpus size
        var byCorpus = {};
        for (var i = 0; i < benchmarkRuns.length; i++) {
          var r = benchmarkRuns[i];
          if (!byCorpus[r.corpus]) byCorpus[r.corpus] = [];
          byCorpus[r.corpus].push(r);
        }

        var html = '';
        var corpusKeys = Object.keys(byCorpus).sort();
        for (var ci = 0; ci < corpusKeys.length; ci++) {
          var corpusKey = corpusKeys[ci];
          var runs = byCorpus[corpusKey];
          var sizeLabel = runs[0].corpus_size ? runs[0].corpus_size + ' docs' : corpusKey;

          html += '<div class="col-span-2 md:col-span-4 mt-' + (ci > 0 ? '4' : '0') + ' mb-1">' +
            '<span class="text-sm font-bold text-zinc-800 dark:text-zinc-200">' + corpusKey.toUpperCase() + ' (' + sizeLabel + ')</span>' +
            '</div>';

          // Sort by mode order: fts5, hybrid, ai, keyword
          var modeOrder = ['fts5', 'hybrid', 'ai', 'keyword'];
          runs.sort(function(a, b) { return modeOrder.indexOf(a.mode) - modeOrder.indexOf(b.mode); });

          for (var ri = 0; ri < runs.length; ri++) {
            var run = runs[ri];
            var m = run.metrics;
            var color = modeColors[run.mode] || 'indigo';
            var note = modeNotes[run.mode] || '';

            html += '<div class="col-span-2 md:col-span-4 text-xs font-semibold text-' + color + '-600 mt-1">' +
              run.mode.toUpperCase() + (note ? ' <span class="font-normal text-zinc-400">(' + note + ')</span>' : '') +
              '</div>';

            html +=
              '<div class="p-3 rounded bg-white dark:bg-zinc-900 text-center">' +
                '<div class="text-lg font-bold text-' + color + '-600">' + (m.ndcg_at_k * 100).toFixed(1) + '%</div>' +
                '<div class="text-xs text-zinc-500">nDCG@10</div>' +
              '</div>' +
              '<div class="p-3 rounded bg-white dark:bg-zinc-900 text-center">' +
                '<div class="text-lg font-bold text-' + color + '-600">' + (m.precision_at_k * 100).toFixed(1) + '%</div>' +
                '<div class="text-xs text-zinc-500">Precision@10</div>' +
              '</div>' +
              '<div class="p-3 rounded bg-white dark:bg-zinc-900 text-center">' +
                '<div class="text-lg font-bold text-' + color + '-600">' + (m.recall_at_k * 100).toFixed(1) + '%</div>' +
                '<div class="text-xs text-zinc-500">Recall@10</div>' +
              '</div>' +
              '<div class="p-3 rounded bg-white dark:bg-zinc-900 text-center">' +
                '<div class="text-lg font-bold text-' + color + '-600">' + (m.mrr * 100).toFixed(1) + '%</div>' +
                '<div class="text-xs text-zinc-500">MRR</div>' +
              '</div>';
          }
        }

        // Clear saved results button
        html += '<div class="col-span-2 md:col-span-4 mt-3 text-right">' +
          '<button onclick="clearBenchmarkHistory()" class="text-xs text-zinc-400 hover:text-red-500 underline">Clear saved results</button>' +
          '</div>';

        metricsDiv.innerHTML = html;

        // Show latest run details
        var latest = benchmarkRuns[benchmarkRuns.length - 1];
        detailsDiv.textContent = latest.queries_evaluated + ' queries evaluated in ' +
          (latest.total_time_ms / 1000).toFixed(1) + 's (avg ' + latest.avg_query_time_ms + 'ms/query) — ' +
          benchmarkRuns.length + ' total runs saved';

        resultsDiv.classList.remove('hidden');
      }

      function clearBenchmarkHistory() {
        if (!confirm('Clear all saved benchmark results?')) return;
        benchmarkRuns = [];
        benchmarkHistory = [];
        saveBenchmarkRuns([]);
        document.getElementById('benchmark-results').classList.add('hidden');
      }

      async function purgeBenchmark() {
        if (!confirm('Remove all benchmark data? This will delete benchmark documents and index entries.')) return;
        var btn = document.getElementById('bench-purge-btn');
        btn.textContent = 'Purging...';
        btn.disabled = true;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/purge', { method: 'POST' });
          var data = await res.json();
          if (data.success) {
            document.getElementById('benchmark-status').textContent = data.message + '. Benchmark data removed.';
            document.getElementById('benchmark-results').classList.add('hidden');
            benchmarkHistory = [];
            document.getElementById('bench-seed-btn').textContent = 'Seed Data';
            document.getElementById('bench-index-btn').disabled = true;
            document.getElementById('bench-vectorize-btn').disabled = true;
            document.getElementById('bench-fts5-btn').disabled = true;
            document.getElementById('bench-keyword-btn').disabled = true;
            document.getElementById('bench-hybrid-btn').disabled = true;
            document.getElementById('bench-ai-btn').disabled = true;
            document.getElementById('bench-purge-btn').disabled = true;
          } else {
            alert('Purge failed: ' + (data.error || 'Unknown error'));
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }
        btn.textContent = 'Purge Data';
        btn.disabled = false;
      }

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
