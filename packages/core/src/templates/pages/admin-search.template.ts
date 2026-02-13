/**
 * Admin Search Dashboard Template
 *
 * Full admin page for configuring and monitoring SonicJS Search.
 * Follows the same pattern as admin-cache.template.ts — renders into
 * renderAdminLayoutCatalyst with stat cards, tabbed UI, and client-side JS.
 */

import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'

export interface SearchDashboardData {
  settings: {
    enabled: boolean
    ai_mode_enabled: boolean
    selected_collections: string[]
    dismissed_collections: string[]
    autocomplete_enabled: boolean
    cache_duration: number
    results_limit: number
    index_media: boolean
    reranking_enabled?: boolean
    query_rewriting_enabled?: boolean
    query_synonyms_enabled?: boolean
    fts5_title_boost?: number
    fts5_slug_boost?: number
    fts5_body_boost?: number
  } | null
  collections: Array<{
    id: string | number
    name: string
    display_name?: string
    description?: string
    item_count?: number
    is_new?: boolean
  }>
  newCollections: Array<{ id: string; name: string }>
  indexStatus: Record<string, { status: string; indexed_items: number; total_items: number }>
  analytics: {
    total_queries: number
    ai_queries: number
    keyword_queries: number
    fts5_queries: number
    hybrid_queries: number
    popular_queries: Array<{ query: string; count: number }>
    average_query_time: number
  }
  fts5Status: { available: boolean; total_indexed: number; by_collection: Record<string, number> } | null
  benchmarkStatus: { seeded: boolean; seeded_count: number; corpus_size: number; query_count: number } | null
  user?: { name: string; email: string; role: string }
  version?: string
}

export function renderSearchDashboard(data: SearchDashboardData): string {
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

  const fts5Status = data.fts5Status
  const fts5Available = fts5Status ? fts5Status.available : false
  const fts5TotalIndexed = fts5Status ? fts5Status.total_indexed : 0

  // Compute Vectorize index summary from indexStatus
  const indexStatus = data.indexStatus || {}
  let vectorizeTotalItems = 0
  let vectorizeIndexedItems = 0
  let vectorizeHasData = false
  for (const colId of Object.keys(indexStatus)) {
    const s = indexStatus[colId]
    if (s) {
      vectorizeTotalItems += s.total_items || 0
      vectorizeIndexedItems += s.indexed_items || 0
      vectorizeHasData = true
    }
  }
  const vectorizeStatusText = vectorizeHasData
    ? `Vectorize index: ${vectorizeIndexedItems} items indexed`
    : 'Click reindex to rebuild the vector index for all selected collections'

  const searchMode = aiModeEnabled ? 'Hybrid' : 'FTS5 Only'
  const totalQueries = data.analytics ? data.analytics.total_queries : 0

  const pageContent = `
    <div class="space-y-6">
      <!-- Tab Navigation -->
      <div class="border-b border-zinc-200 dark:border-zinc-700">
        <nav class="-mb-px flex space-x-8" aria-label="Tabs">
          <button id="tab-btn-overview" onclick="switchTab('overview')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-indigo-500 text-indigo-600 dark:text-indigo-400">
            Overview
          </button>
          <button id="tab-btn-configuration" onclick="switchTab('configuration')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-transparent text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-300">
            Configuration
          </button>
          <button id="tab-btn-benchmark" onclick="switchTab('benchmark')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-transparent text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-300">
            Benchmark
          </button>
          <button id="tab-btn-relevance" onclick="switchTab('relevance')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-transparent text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-300">
            Relevance &amp; Ranking
          </button>
          <button id="tab-btn-analytics" onclick="switchTab('analytics')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-transparent text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-300">
            Analytics
          </button>
        </nav>
      </div>

      <!-- ========================================== -->
      <!-- TAB 1: Overview                            -->
      <!-- ========================================== -->
      <div id="tab-overview" class="tab-panel">
        <!-- Header -->
        <div class="flex items-center justify-between">
          <div>
            <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Search</h1>
            <p class="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
              Monitor and configure search across your content
            </p>
          </div>
          <div class="flex gap-3">
            <a
              href="/admin/plugins/ai-search/test"
              target="_blank"
              class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
              </svg>
              Test Search
            </a>
            <a
              href="/admin/plugins/ai-search/instantsearch"
              target="_blank"
              class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-800"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>
              </svg>
              InstantSearch
            </a>
            <a
              href="/admin/plugins/ai-search/integration"
              target="_blank"
              class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-800"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
              </svg>
              Integration Guide
            </a>
          </div>
        </div>

        <!-- Stat Cards -->
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mt-6">
          ${renderStatCard('Total Indexed Docs', String(fts5TotalIndexed), 'lime', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
          `)}

          ${renderStatCard('FTS5 Status', fts5Available ? 'Available' : 'Unavailable', fts5Available ? 'lime' : 'red', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          `)}

          ${renderStatCard('Search Mode', searchMode, 'purple', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
            </svg>
          `)}

          ${renderStatCard('Total Queries', String(totalQueries), 'sky', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
            </svg>
          `)}
        </div>

        <!-- System Status -->
        <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 mt-6">
          <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
            <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">System Status</h2>
          </div>
          <div class="p-6">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 class="text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-3">Binding Availability</h3>
                <div class="space-y-2">
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-zinc-600 dark:text-zinc-400">FTS5 (SQLite)</span>
                    <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${fts5Available
                      ? 'bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-400 ring-1 ring-inset ring-lime-600/20 dark:ring-lime-500/20'
                      : 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20'
                    }">${fts5Available ? 'Available' : 'Unavailable'}</span>
                  </div>
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-zinc-600 dark:text-zinc-400">AI / Vectorize</span>
                    <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${aiModeEnabled
                      ? 'bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-400 ring-1 ring-inset ring-lime-600/20 dark:ring-lime-500/20'
                      : 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20'
                    }">${aiModeEnabled ? 'Enabled' : 'Disabled'}</span>
                  </div>
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-zinc-600 dark:text-zinc-400">Search Enabled</span>
                    <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${enabled
                      ? 'bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-400 ring-1 ring-inset ring-lime-600/20 dark:ring-lime-500/20'
                      : 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20'
                    }">${enabled ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              </div>
              <div>
                <h3 class="text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-3">Index Summary</h3>
                <div class="space-y-2">
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-zinc-600 dark:text-zinc-400">Indexed Collections</span>
                    <span class="font-medium text-zinc-900 dark:text-zinc-100">${fts5Status ? Object.keys(fts5Status.by_collection || {}).length : 0}</span>
                  </div>
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-zinc-600 dark:text-zinc-400">Total Documents</span>
                    <span class="font-medium text-zinc-900 dark:text-zinc-100">${fts5TotalIndexed}</span>
                  </div>
                  <div class="flex items-center justify-between text-sm">
                    <span class="text-zinc-600 dark:text-zinc-400">Selected Collections</span>
                    <span class="font-medium text-zinc-900 dark:text-zinc-100">${selectedCollections.length}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- ========================================== -->
      <!-- TAB 2: Configuration                       -->
      <!-- ========================================== -->
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

      <!-- ========================================== -->
      <!-- TAB 3: Benchmark                           -->
      <!-- ========================================== -->
      <div id="tab-benchmark" class="tab-panel hidden">
        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Search Benchmark</h2>
          <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-4" id="bench-description">
            BEIR benchmark datasets with ground-truth relevance judgments.
            Seed the data, index it, then evaluate search quality with standard IR metrics (nDCG@10, Precision, Recall, MRR).
          </p>

          <!-- Dataset Selector -->
          <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="flex items-center gap-2">
              <label for="bench-dataset" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Dataset:</label>
              <select id="bench-dataset" onchange="switchBenchmarkDataset()"
                class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                <option value="scifact">SciFact (5,183 docs, scientific)</option>
                <option value="nfcorpus">NFCorpus (3,633 docs, biomedical)</option>
                <option value="fiqa">FiQA-2018 (57,638 docs, financial Q&amp;A)</option>
              </select>
            </div>
            <span id="bench-data-badge" class="hidden text-xs px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400">
              Data not uploaded to KV
            </span>
          </div>

          <div id="benchmark-status" class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Checking benchmark status...</div>

          <!-- Corpus Size + Seed Row -->
          <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="flex items-center gap-2">
              <label for="bench-corpus-size" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Corpus:</label>
              <select id="bench-corpus-size" onchange="updateBenchmarkStatusText()"
                class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                <option value="subset">Subset</option>
                <option value="full">Full corpus</option>
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
                <option value="0" selected>All</option>
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
      </div>

      <!-- ========================================== -->
      <!-- TAB 4: Relevance & Ranking                 -->
      <!-- ========================================== -->
      <div id="tab-relevance" class="tab-panel hidden">
        <div class="space-y-6">
          <!-- Ranking Pipeline Section -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-6">
              <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Ranking Pipeline</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">
                Composable scoring stages that post-process search results from any mode. Each stage produces a [0, 1] score, combined via weighted sum.
              </p>
            </div>

            <div id="pipeline-stages" class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="text-sm text-zinc-500 dark:text-zinc-400">Loading pipeline configuration...</div>
            </div>

            <!-- Formula Info -->
            <div class="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-4 mt-6">
              <div class="flex gap-3">
                <svg class="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <div class="text-sm">
                  <p class="font-medium text-blue-900 dark:text-blue-100">How scoring works</p>
                  <p class="text-blue-700 dark:text-blue-300 mt-1">
                    <code class="text-xs bg-blue-100 dark:bg-blue-800/50 px-1.5 py-0.5 rounded">pipeline_score = sum(weight x score) / sum(weight)</code>
                    <br/>Only enabled stages with weight &gt; 0 participate. If no stages are active, the original search order is preserved.
                  </p>
                </div>
              </div>
            </div>

            <!-- Action Buttons -->
            <div class="flex items-center justify-between pt-4 mt-4 border-t border-zinc-200 dark:border-zinc-800">
              <button
                type="button"
                onclick="resetPipeline()"
                class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
              >
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                </svg>
                Reset to Defaults
              </button>
              <button
                type="button"
                id="savePipelineBtn"
                onclick="savePipeline()"
                class="inline-flex items-center justify-center rounded-lg bg-indigo-600 text-white px-6 py-2.5 text-sm font-semibold hover:bg-indigo-500 shadow-sm"
              >
                Save Pipeline
              </button>
            </div>
          </div>

          <!-- Live Preview -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-4">
              <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-1">Live Preview</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">
                Test search results with current pipeline and field weight settings. Results update automatically as you adjust controls.
              </p>
            </div>

            <div class="flex items-center gap-3 mb-4">
              <input
                type="text"
                id="preview-query"
                placeholder="Type a search query..."
                class="flex-1 rounded-lg bg-white dark:bg-white/5 px-4 py-2.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 placeholder:text-zinc-400"
                onkeydown="if(event.key==='Enter'){event.preventDefault();previewSearch()}"
              />
              <button
                type="button"
                id="preview-search-btn"
                onclick="previewSearch()"
                class="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                </svg>
                Search
              </button>
            </div>

            <!-- Preview Results -->
            <div id="preview-results" class="hidden">
              <div id="preview-meta" class="flex items-center justify-between mb-3 text-xs text-zinc-500 dark:text-zinc-400">
              </div>
              <div id="preview-list" class="space-y-3">
              </div>
            </div>

            <div id="preview-empty" class="hidden text-center py-6">
              <p class="text-sm text-zinc-500 dark:text-zinc-400">No results found for this query with current weights.</p>
            </div>

            <div id="preview-error" class="hidden rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3">
              <p class="text-sm text-red-700 dark:text-red-300" id="preview-error-text"></p>
            </div>
          </div>

          <!-- Field Weights Section -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-6">
              <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Field Weights</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">
                Adjust BM25 field boosting for FTS5 and hybrid search modes. Higher weights increase the importance of matches in that field.
              </p>
            </div>

            <form id="relevanceForm" class="space-y-6">
              <div class="space-y-5">
                <!-- Title Weight -->
                <div>
                  <div class="flex items-center justify-between mb-2">
                    <label for="fts5_title_boost" class="text-sm font-medium text-zinc-950 dark:text-white">
                      Title Weight
                    </label>
                    <span class="text-sm text-zinc-600 dark:text-zinc-400">
                      <span id="title-weight-value" class="font-mono font-semibold text-indigo-600 dark:text-indigo-400">${settings.fts5_title_boost ?? 5.0}</span>
                      <span class="text-xs ml-1">(default: 5.0)</span>
                    </span>
                  </div>
                  <input
                    type="range"
                    id="fts5_title_boost"
                    name="fts5_title_boost"
                    min="0"
                    max="10"
                    step="0.1"
                    value="${settings.fts5_title_boost ?? 5.0}"
                    class="w-full h-2 bg-zinc-200 dark:bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-indigo-600"
                    oninput="document.getElementById('title-weight-value').textContent = parseFloat(this.value).toFixed(1); schedulePreview()"
                  />
                  <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                    Boost relevance for title matches — the most important field for keyword search
                  </p>
                </div>

                <!-- Slug Weight -->
                <div>
                  <div class="flex items-center justify-between mb-2">
                    <label for="fts5_slug_boost" class="text-sm font-medium text-zinc-950 dark:text-white">
                      Slug Weight
                    </label>
                    <span class="text-sm text-zinc-600 dark:text-zinc-400">
                      <span id="slug-weight-value" class="font-mono font-semibold text-purple-600 dark:text-purple-400">${settings.fts5_slug_boost ?? 2.0}</span>
                      <span class="text-xs ml-1">(default: 2.0)</span>
                    </span>
                  </div>
                  <input
                    type="range"
                    id="fts5_slug_boost"
                    name="fts5_slug_boost"
                    min="0"
                    max="10"
                    step="0.1"
                    value="${settings.fts5_slug_boost ?? 2.0}"
                    class="w-full h-2 bg-zinc-200 dark:bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-purple-600"
                    oninput="document.getElementById('slug-weight-value').textContent = parseFloat(this.value).toFixed(1); schedulePreview()"
                  />
                  <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                    Boost relevance for URL slug matches
                  </p>
                </div>

                <!-- Body Weight -->
                <div>
                  <div class="flex items-center justify-between mb-2">
                    <label for="fts5_body_boost" class="text-sm font-medium text-zinc-950 dark:text-white">
                      Body Weight
                    </label>
                    <span class="text-sm text-zinc-600 dark:text-zinc-400">
                      <span id="body-weight-value" class="font-mono font-semibold text-sky-600 dark:text-sky-400">${settings.fts5_body_boost ?? 1.0}</span>
                      <span class="text-xs ml-1">(default: 1.0)</span>
                    </span>
                  </div>
                  <input
                    type="range"
                    id="fts5_body_boost"
                    name="fts5_body_boost"
                    min="0"
                    max="10"
                    step="0.1"
                    value="${settings.fts5_body_boost ?? 1.0}"
                    class="w-full h-2 bg-zinc-200 dark:bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-sky-600"
                    oninput="document.getElementById('body-weight-value').textContent = parseFloat(this.value).toFixed(1); schedulePreview()"
                  />
                  <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                    Boost relevance for body content matches — the baseline field
                  </p>
                </div>
              </div>

              <hr class="border-zinc-200 dark:border-zinc-800">

              <!-- Impact Notice -->
              <div class="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-4">
                <div class="flex gap-3">
                  <svg class="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  <div class="text-sm">
                    <p class="font-medium text-blue-900 dark:text-blue-100">Applies to FTS5 and Hybrid search modes</p>
                    <p class="text-blue-700 dark:text-blue-300 mt-1">
                      Field weights control BM25 relevance scoring. Changes apply immediately to new searches.
                      Use the <a href="/admin/plugins/ai-search/test" class="underline font-medium hover:text-blue-900 dark:hover:text-blue-100">Test Search</a> page to evaluate different weight configurations.
                    </p>
                  </div>
                </div>
              </div>

              <!-- Action Buttons -->
              <div class="flex items-center justify-between pt-2">
                <button
                  type="button"
                  onclick="resetFieldWeights()"
                  class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                  Reset to Defaults
                </button>
                <button
                  type="submit"
                  id="saveWeightsBtn"
                  class="inline-flex items-center justify-center rounded-lg bg-indigo-600 text-white px-6 py-2.5 text-sm font-semibold hover:bg-indigo-500 shadow-sm"
                >
                  Save Field Weights
                </button>
              </div>
            </form>
          </div>

          <!-- Query Synonyms Section -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="flex items-center justify-between mb-6">
              <div>
                <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Custom Synonyms</h2>
                <p class="text-sm text-zinc-600 dark:text-zinc-400">
                  Define custom synonym groups for domain-specific terms, brand names, or acronyms. For general synonym expansion, enable Query Rewriting (LLM) in Configuration.
                </p>
              </div>
              <label class="flex items-center gap-2 cursor-pointer flex-shrink-0 ml-4">
                <span class="text-sm text-zinc-600 dark:text-zinc-400">Enabled</span>
                <input
                  type="checkbox"
                  id="synonyms-global-toggle"
                  ${settings.query_synonyms_enabled !== false ? 'checked' : ''}
                  onchange="toggleSynonymsGlobal(this.checked)"
                  class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                />
              </label>
            </div>

            <!-- Synonym count summary -->
            <div id="synonyms-summary" class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">
              Loading synonym groups...
            </div>

            <!-- Synonym groups list -->
            <div id="synonyms-list" class="space-y-2 mb-4">
            </div>

            <!-- Add new synonym group form (hidden by default) -->
            <div id="synonym-add-form" class="hidden border border-dashed border-zinc-300 dark:border-zinc-600 rounded-lg p-4 mb-4">
              <div class="flex items-center gap-3">
                <input
                  type="text"
                  id="synonym-new-terms"
                  placeholder="Enter comma-separated terms (e.g., coffee, espresso, caffeine)"
                  class="flex-1 rounded-lg bg-white dark:bg-white/5 px-4 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 placeholder:text-zinc-400"
                  onkeydown="if(event.key==='Enter'){event.preventDefault();saveSynonymGroup()}"
                />
                <button
                  type="button"
                  onclick="saveSynonymGroup()"
                  class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
                >
                  Save
                </button>
                <button
                  type="button"
                  onclick="cancelSynonymAdd()"
                  class="inline-flex items-center gap-1.5 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
                >
                  Cancel
                </button>
              </div>
              <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
                All terms in a group are equivalent. Minimum 2 terms required.
              </p>
            </div>

            <!-- Add button -->
            <button
              type="button"
              id="synonym-add-btn"
              onclick="showSynonymAddForm()"
              class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
              </svg>
              Add Synonym Group
            </button>

            <!-- Info callout -->
            <div class="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-4 mt-6">
              <div class="flex gap-3">
                <svg class="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <div class="text-sm">
                  <p class="font-medium text-blue-900 dark:text-blue-100">Deterministic &amp; fast — complements LLM Query Rewriting</p>
                  <p class="text-blue-700 dark:text-blue-300 mt-1">
                    Custom synonyms use a lookup table (no AI cost, zero latency). Best for exact mappings like brand names, acronyms, and domain jargon. For broad synonym coverage, use Query Rewriting in the Configuration tab.
                  </p>
                </div>
              </div>
            </div>
          </div>

          <!-- Future: Pin/Boost/Bury rules -->
        </div>
      </div>

      <!-- ========================================== -->
      <!-- TAB 5: Analytics (Placeholder)              -->
      <!-- ========================================== -->
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

      <!-- Success Message -->
      <div id="msg" class="hidden fixed bottom-4 right-4 p-4 rounded-lg bg-green-50 text-green-900 border border-green-200 dark:bg-green-900/20 dark:text-green-100 dark:border-green-800 shadow-lg z-50">
        <div class="flex items-center gap-2">
          <span class="font-semibold">Settings Saved Successfully!</span>
        </div>
      </div>
    </div>

    <script>
      // =============================================
      // Tab switching logic
      // =============================================
      function switchTab(tabId) {
        document.querySelectorAll('.tab-panel').forEach(function(p) { p.classList.add('hidden'); });
        document.querySelectorAll('.tab-btn').forEach(function(b) {
          b.classList.remove('border-indigo-500', 'text-indigo-600', 'dark:text-indigo-400');
          b.classList.add('border-transparent', 'text-zinc-500', 'dark:text-zinc-400');
        });
        var panel = document.getElementById('tab-' + tabId);
        var btn = document.getElementById('tab-btn-' + tabId);
        if (panel) panel.classList.remove('hidden');
        if (btn) {
          btn.classList.remove('border-transparent', 'text-zinc-500', 'dark:text-zinc-400');
          btn.classList.add('border-indigo-500', 'text-indigo-600', 'dark:text-indigo-400');
        }
        window.location.hash = tabId;
      }
      // Init from hash or default
      var initTab = window.location.hash.replace('#', '') || 'overview';
      switchTab(initTab);

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

      // =============================================
      // Benchmark Functions
      // =============================================

      var benchDescriptions = {
        scifact: 'BEIR SciFact — scientific abstracts with 300+ test queries and ground-truth relevance judgments.',
        nfcorpus: 'BEIR NFCorpus — biomedical IR from NutritionFacts with 323 queries and rich multi-level relevance (38 qrels/query).',
        fiqa: 'BEIR FiQA-2018 — financial opinion Q&A from StackExchange/Reddit with 648 test queries.'
      };

      function getBenchDataset() {
        return document.getElementById('bench-dataset').value;
      }

      async function switchBenchmarkDataset() {
        var dataset = getBenchDataset();
        // Update description
        document.getElementById('bench-description').textContent = benchDescriptions[dataset] ||
          'BEIR benchmark dataset. Seed, index, then evaluate with IR metrics.';
        // Reset UI
        document.getElementById('benchmark-status').textContent = 'Checking benchmark status...';
        document.getElementById('benchmark-results').classList.add('hidden');
        ['seed','index','vectorize','fts5','keyword','hybrid','ai','purge'].forEach(function(id) {
          var btn = document.getElementById('bench-' + id + '-btn');
          if (btn) btn.disabled = true;
        });
        document.getElementById('bench-seed-btn').disabled = false;
        document.getElementById('bench-seed-btn').textContent = 'Seed Data';
        document.getElementById('bench-data-badge').classList.add('hidden');
        await checkBenchmarkStatus(dataset);
        // Re-render saved results (filtered to selected dataset)
        renderAllBenchmarkRuns();
      }

      // Check benchmark status on page load
      // Cached status data for reactive UI updates
      var _lastBenchStatus = null;

      function updateBenchmarkStatusText() {
        var d = _lastBenchStatus;
        if (!d) return;
        var statusEl = document.getElementById('benchmark-status');
        var corpusSelect = document.getElementById('bench-corpus-size');
        var evalCount = d.evaluable_queries || d.query_count;
        var selectedSize = corpusSelect.value;

        if (d.seeded) {
          // Determine expected doc count for the selected corpus option
          var expectedCount = selectedSize === 'full' ? d.corpus_size : d.subset_size;
          if (expectedCount && d.seeded_count !== expectedCount) {
            statusEl.textContent = 'Seeded: ' + d.seeded_count.toLocaleString() + ' docs — selected: ' +
              corpusSelect.options[corpusSelect.selectedIndex].textContent +
              '. Click "Re-seed Data" to update.';
          } else {
            statusEl.textContent = 'Benchmark data seeded: ' + d.seeded_count.toLocaleString() + ' documents (' + evalCount + ' evaluable queries)';
          }
        } else {
          statusEl.textContent = 'Dataset: ' + d.dataset + ' (' + d.corpus_size.toLocaleString() + ' docs, ' + evalCount + ' evaluable queries) — Not yet seeded';
        }
      }

      async function checkBenchmarkStatus(dataset) {
        if (!dataset) dataset = getBenchDataset();
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/status?dataset=' + dataset);
          if (res.ok) {
            var body = await res.json();
            var d = body.data;
            _lastBenchStatus = d;
            var statusEl = document.getElementById('benchmark-status');
            var corpusSelect = document.getElementById('bench-corpus-size');
            var dataBadge = document.getElementById('bench-data-badge');

            // Show/hide KV data badge
            if (d.data_available) {
              dataBadge.classList.add('hidden');
            } else {
              dataBadge.classList.remove('hidden');
              statusEl.textContent = 'Dataset data not uploaded to KV. Run: npx tsx scripts/generate-benchmark-data.ts --dataset ' + dataset;
              return;
            }

            // Update corpus size options with actual counts
            if (d.subset_size && d.corpus_size) {
              corpusSelect.options[0].textContent = 'Subset (' + d.subset_size.toLocaleString() + ' docs)';
              corpusSelect.options[1].textContent = 'Full corpus (' + d.corpus_size.toLocaleString() + ' docs)';
            } else if (d.corpus_size) {
              corpusSelect.options[1].textContent = 'Full corpus (' + d.corpus_size.toLocaleString() + ' docs)';
            }

            // Auto-select the corpus option matching what's currently seeded
            if (d.seeded && d.subset_size && d.seeded_count <= d.subset_size) {
              corpusSelect.value = 'subset';
            } else if (d.seeded) {
              corpusSelect.value = 'full';
            }

            // Update Queries dropdown "All" option with actual evaluable count
            var querySelect = document.getElementById('bench-query-count');
            var evalCount = d.evaluable_queries || d.query_count;
            var allOption = querySelect.options[querySelect.options.length - 1];
            allOption.textContent = 'All (' + evalCount.toLocaleString() + ')';

            if (d.seeded) {
              document.getElementById('bench-seed-btn').textContent = 'Re-seed Data';
              document.getElementById('bench-index-btn').disabled = false;
              document.getElementById('bench-vectorize-btn').disabled = false;
              document.getElementById('bench-fts5-btn').disabled = false;
              document.getElementById('bench-keyword-btn').disabled = false;
              document.getElementById('bench-hybrid-btn').disabled = false;
              document.getElementById('bench-ai-btn').disabled = false;
              document.getElementById('bench-purge-btn').disabled = false;
            }

            // Set status text (uses cached _lastBenchStatus)
            updateBenchmarkStatusText();
          }
        } catch (e) {
          document.getElementById('benchmark-status').textContent = 'Could not check benchmark status: ' + e.message;
        }
      }
      checkBenchmarkStatus();

      async function seedBenchmark() {
        var btn = document.getElementById('bench-seed-btn');
        var corpusSize = document.getElementById('bench-corpus-size').value;
        var dataset = getBenchDataset();
        btn.textContent = 'Seeding (' + corpusSize + ')...';
        btn.disabled = true;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/seed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ corpus_size: corpusSize, dataset: dataset })
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
        var dataset = getBenchDataset();

        var totalIndexed = 0;
        var remaining = 1;
        var batchNum = 0;

        while (remaining > 0) {
          batchNum++;
          btn.textContent = 'Indexing batch ' + batchNum + '...';
          try {
            var res = await fetch('/admin/plugins/ai-search/api/benchmark/index-fts5-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ batch_size: 200, dataset: dataset })
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
        var dataset = getBenchDataset();

        // Reset index meta first
        try {
          await fetch('/admin/plugins/ai-search/api/benchmark/index-vectorize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dataset: dataset })
          });
        } catch (e) { /* continue anyway */ }

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
              body: JSON.stringify({ batch_size: 25, offset: offset, dataset: dataset })
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
        var dataset = getBenchDataset();
        var BATCH_SIZE = 15;
        var startTime = Date.now();

        try {
          // Step 1: Get evaluable query IDs
          progressText.textContent = 'Fetching query list...';
          var idsRes = await fetch('/admin/plugins/ai-search/api/benchmark/query-ids?max_queries=' + maxQueries + '&dataset=' + dataset);
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
              body: JSON.stringify({ mode: mode, limit: 10, query_ids: batchIds, dataset: dataset })
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
        var dataset = getBenchDataset();

        // Store in current session history
        benchmarkHistory = benchmarkHistory.filter(function(h) { return h.mode !== mode || h.dataset !== dataset; });
        benchmarkHistory.push({ mode: mode, dataset: dataset, data: data });

        // Also persist to localStorage with dataset + corpus label
        var corpusLabel = document.getElementById('bench-corpus-size').value;
        var runKey = dataset + '_' + corpusLabel + '_' + mode;
        var runEntry = {
          key: runKey,
          mode: mode,
          dataset: dataset,
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

        var datasetNames = { scifact: 'SciFact', nfcorpus: 'NFCorpus', fiqa: 'FiQA-2018' };
        var modeOrder = ['fts5', 'hybrid', 'ai', 'keyword'];
        var modeLabels = { fts5: 'FTS5', keyword: 'Keyword', hybrid: 'Hybrid', ai: 'AI/Vectorize' };

        titleEl.textContent = 'Benchmark Results (k=10)';

        // Group by dataset → corpus → mode
        var byDataset = {};
        var datasetOrder = ['scifact', 'nfcorpus', 'fiqa'];
        for (var i = 0; i < benchmarkRuns.length; i++) {
          var r = benchmarkRuns[i];
          var ds = r.dataset || 'scifact';
          if (!byDataset[ds]) byDataset[ds] = {};
          var corpus = r.corpus || 'subset';
          if (!byDataset[ds][corpus]) byDataset[ds][corpus] = [];
          byDataset[ds][corpus].push(r);
        }

        // Build a comparison table for each dataset+corpus group
        var html = '';
        for (var di = 0; di < datasetOrder.length; di++) {
          var dsKey = datasetOrder[di];
          if (!byDataset[dsKey]) continue;
          var corpusGroups = byDataset[dsKey];
          var corpusKeys = Object.keys(corpusGroups).sort();

          for (var ci = 0; ci < corpusKeys.length; ci++) {
            var corpusKey = corpusKeys[ci];
            var runs = corpusGroups[corpusKey];
            runs.sort(function(a, b) { return modeOrder.indexOf(a.mode) - modeOrder.indexOf(b.mode); });
            var sizeLabel = runs[0].corpus_size ? runs[0].corpus_size.toLocaleString() + ' docs' : '';
            var corpusDisplay = corpusKey === 'full' ? 'Full' : 'Subset';
            if (sizeLabel) corpusDisplay += ' (' + sizeLabel + ')';

            // Section header
            html += '<div class="col-span-2 md:col-span-4' + (di > 0 || ci > 0 ? ' mt-5 pt-4 border-t border-zinc-200 dark:border-zinc-700' : '') + '">' +
              '<div class="flex items-center gap-2 mb-2">' +
                '<span class="text-sm font-bold text-zinc-900 dark:text-white">' + (datasetNames[dsKey] || dsKey) + '</span>' +
                '<span class="text-xs px-2 py-0.5 rounded-full bg-zinc-100 dark:bg-zinc-700 text-zinc-600 dark:text-zinc-300">' + corpusDisplay + '</span>' +
              '</div>' +
            '</div>';

            // Table header
            html += '<div class="col-span-2 md:col-span-4">' +
              '<table class="w-full text-sm" style="table-layout:fixed">' +
              '<colgroup>' +
                '<col style="width:18%">' +
                '<col style="width:15%">' +
                '<col style="width:13%">' +
                '<col style="width:15%">' +
                '<col style="width:13%">' +
                '<col style="width:13%">' +
                '<col style="width:13%">' +
              '</colgroup>' +
              '<thead><tr class="text-xs text-zinc-500 dark:text-zinc-400 border-b border-zinc-200 dark:border-zinc-700">' +
              '<th class="text-left py-2 font-medium">Mode</th>' +
              '<th class="text-right py-2 font-medium">nDCG@10</th>' +
              '<th class="text-right py-2 font-medium">P@10</th>' +
              '<th class="text-right py-2 font-medium">Recall@10</th>' +
              '<th class="text-right py-2 font-medium">MRR</th>' +
              '<th class="text-right py-2 font-medium">Queries</th>' +
              '<th class="text-right py-2 font-medium">Avg ms</th>' +
              '</tr></thead><tbody>';

            for (var ri = 0; ri < runs.length; ri++) {
              var run = runs[ri];
              var m = run.metrics;
              var mc = run.mode === 'fts5' ? 'indigo' : run.mode === 'ai' ? 'cyan' : run.mode === 'hybrid' ? 'purple' : 'zinc';

              html += '<tr class="border-b border-zinc-100 dark:border-zinc-800">' +
                '<td class="py-2.5 font-semibold text-' + mc + '-600 dark:text-' + mc + '-400">' + (modeLabels[run.mode] || run.mode.toUpperCase()) + '</td>' +
                '<td class="py-2.5 text-right font-mono font-bold text-base text-' + mc + '-600 dark:text-' + mc + '-300">' + (m.ndcg_at_k * 100).toFixed(1) + '%</td>' +
                '<td class="py-2.5 text-right font-mono font-bold text-base text-' + mc + '-600 dark:text-' + mc + '-300">' + (m.precision_at_k * 100).toFixed(1) + '%</td>' +
                '<td class="py-2.5 text-right font-mono font-bold text-base text-' + mc + '-600 dark:text-' + mc + '-300">' + (m.recall_at_k * 100).toFixed(1) + '%</td>' +
                '<td class="py-2.5 text-right font-mono font-bold text-base text-' + mc + '-600 dark:text-' + mc + '-300">' + (m.mrr * 100).toFixed(1) + '%</td>' +
                '<td class="py-2.5 text-right text-zinc-500 dark:text-zinc-400">' + run.queries_evaluated + '</td>' +
                '<td class="py-2.5 text-right text-zinc-500 dark:text-zinc-400">' + run.avg_query_time_ms + 'ms</td>' +
              '</tr>';
            }

            html += '</tbody></table></div>';
          }
        }

        // Summary + clear button
        html += '<div class="col-span-2 md:col-span-4 mt-4 flex items-center justify-between">' +
          '<span class="text-xs text-zinc-400">' + benchmarkRuns.length + ' total runs across ' + Object.keys(byDataset).length + ' datasets</span>' +
          '<button onclick="clearBenchmarkHistory()" class="text-xs text-zinc-400 hover:text-red-500 underline">Clear all results</button>' +
          '</div>';

        metricsDiv.innerHTML = html;
        detailsDiv.textContent = '';
        resultsDiv.classList.remove('hidden');
      }

      function getRelativeTime(date) {
        var now = new Date();
        var diff = Math.floor((now - date) / 1000);
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
      }

      function clearBenchmarkHistory() {
        if (!confirm('Clear all saved benchmark results?')) return;
        benchmarkRuns = [];
        benchmarkHistory = [];
        saveBenchmarkRuns([]);
        document.getElementById('benchmark-results').classList.add('hidden');
      }

      async function purgeBenchmark() {
        var dataset = getBenchDataset();
        if (!confirm('Remove all ' + dataset + ' benchmark data? This will delete benchmark documents and index entries.')) return;
        var btn = document.getElementById('bench-purge-btn');
        btn.textContent = 'Purging...';
        btn.disabled = true;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/purge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dataset: dataset })
          });
          var data = await res.json();
          if (data.success) {
            document.getElementById('benchmark-status').textContent = data.message + '. Benchmark data removed.';
            document.getElementById('benchmark-results').classList.add('hidden');
            benchmarkHistory = benchmarkHistory.filter(function(h) { return h.dataset !== dataset; });
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

      // =============================================
      // Relevance: Field Weights
      // =============================================
      document.getElementById('relevanceForm')?.addEventListener('submit', async function(e) {
        e.preventDefault();
        var btn = document.getElementById('saveWeightsBtn');
        var origText = btn.textContent;
        btn.textContent = 'Saving...';
        btn.disabled = true;

        try {
          var formData = new FormData(e.target);
          var data = {
            fts5_title_boost: parseFloat(formData.get('fts5_title_boost')),
            fts5_slug_boost: parseFloat(formData.get('fts5_slug_boost')),
            fts5_body_boost: parseFloat(formData.get('fts5_body_boost'))
          };

          var res = await fetch('/admin/plugins/ai-search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
          });

          if (res.ok) {
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() {
              document.getElementById('msg').classList.add('hidden');
            }, 2000);
          } else {
            var error = await res.text();
            alert('Failed to save field weights: ' + error);
          }
        } catch (err) {
          alert('Error saving field weights: ' + err.message);
        }

        btn.textContent = origText;
        btn.disabled = false;
      });

      function resetFieldWeights() {
        if (!confirm('Reset all field weights to defaults (Title: 5.0, Slug: 2.0, Body: 1.0)?')) return;

        document.getElementById('fts5_title_boost').value = 5.0;
        document.getElementById('fts5_slug_boost').value = 2.0;
        document.getElementById('fts5_body_boost').value = 1.0;

        document.getElementById('title-weight-value').textContent = '5.0';
        document.getElementById('slug-weight-value').textContent = '2.0';
        document.getElementById('body-weight-value').textContent = '1.0';

        schedulePreview();
      }

      // =============================================
      // Ranking Pipeline
      // =============================================
      var pipelineStages = [];

      var STAGE_META = {
        exactMatch: { name: 'Exact Match', desc: 'Score 1.0 if query appears verbatim in title, 0.0 otherwise' },
        bm25:       { name: 'BM25 Score',  desc: 'Normalized BM25 score from FTS5 full-text search' },
        semantic:   { name: 'Semantic Score', desc: 'Cosine similarity from Vectorize AI embeddings' },
        recency:    { name: 'Recency',     desc: 'Exponential decay based on content age (configurable half-life)' },
        popularity: { name: 'Popularity',  desc: 'External popularity score (set via API or future analytics)' },
        custom:     { name: 'Custom Boost', desc: 'Manual pin/boost score for specific content items' }
      };

      (async function loadPipeline() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/pipeline');
          var data = await res.json();
          if (data.success && data.data) {
            pipelineStages = data.data;
            renderPipelineStages();
          }
        } catch (e) {
          console.error('Failed to load pipeline config:', e);
          document.getElementById('pipeline-stages').innerHTML =
            '<p class="text-sm text-red-500">Failed to load pipeline configuration.</p>';
        }
      })();

      function renderPipelineStages() {
        var container = document.getElementById('pipeline-stages');
        var html = '';

        for (var i = 0; i < pipelineStages.length; i++) {
          var s = pipelineStages[i];
          var meta = STAGE_META[s.type] || { name: s.type, desc: '' };
          var checked = s.enabled ? 'checked' : '';
          var weight = parseFloat(s.weight).toFixed(1);

          html += '<div class="p-3 rounded-lg border border-zinc-200 dark:border-zinc-700 ' +
            (s.enabled ? 'bg-white dark:bg-zinc-800/50' : 'bg-zinc-50 dark:bg-zinc-900 opacity-60') + '" title="' + meta.desc + '">' +
            '<div class="flex items-center justify-between mb-2">' +
              '<label class="flex items-center gap-2 cursor-pointer">' +
                '<input type="checkbox" id="stage-' + s.type + '-enabled" ' + checked + ' ' +
                  'onchange="toggleStage(\\'' + s.type + '\\', this.checked)" ' +
                  'class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer">' +
                '<span class="text-sm font-medium text-zinc-950 dark:text-white">' + meta.name + '</span>' +
              '</label>' +
              '<span id="stage-' + s.type + '-weight-value" class="text-sm font-mono font-semibold text-indigo-600 dark:text-indigo-400">' + weight + '</span>' +
            '</div>' +
            '<input type="range" id="stage-' + s.type + '-weight" min="0" max="10" step="0.1" value="' + weight + '" ' +
              'class="w-full h-1.5 bg-zinc-200 dark:bg-zinc-700 rounded-lg appearance-none cursor-pointer accent-indigo-600" ' +
              'oninput="updateStageWeight(\\'' + s.type + '\\', this.value)">';

          // Recency half-life config
          if (s.type === 'recency') {
            var halfLife = (s.config && s.config.half_life_days) || 30;
            html += '<div class="flex items-center gap-2 mt-2">' +
              '<label class="text-xs text-zinc-500 dark:text-zinc-400 whitespace-nowrap">Half-life:</label>' +
              '<input type="number" id="stage-recency-halflife" min="1" max="365" value="' + halfLife + '" ' +
                'class="w-14 rounded bg-white dark:bg-zinc-800 text-zinc-950 dark:text-white px-2 py-0.5 text-xs ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600">' +
              '<span class="text-xs text-zinc-400">days</span>' +
            '</div>';
          }

          html += '</div>';
        }

        container.innerHTML = html;
      }

      function toggleStage(type, enabled) {
        for (var i = 0; i < pipelineStages.length; i++) {
          if (pipelineStages[i].type === type) {
            pipelineStages[i].enabled = enabled;
            break;
          }
        }
        renderPipelineStages();
        schedulePreview();
      }

      function updateStageWeight(type, value) {
        var val = parseFloat(value).toFixed(1);
        var label = document.getElementById('stage-' + type + '-weight-value');
        if (label) label.textContent = val;
        for (var i = 0; i < pipelineStages.length; i++) {
          if (pipelineStages[i].type === type) {
            pipelineStages[i].weight = parseFloat(val);
            break;
          }
        }
        schedulePreview();
      }

      function resetPipeline() {
        pipelineStages = [
          { type: 'exactMatch', weight: 10, enabled: true },
          { type: 'bm25',       weight: 5,  enabled: true },
          { type: 'semantic',    weight: 3,  enabled: true },
          { type: 'recency',     weight: 1,  enabled: true, config: { half_life_days: 30 } },
          { type: 'popularity',  weight: 0,  enabled: false },
          { type: 'custom',      weight: 0,  enabled: false }
        ];
        renderPipelineStages();
        schedulePreview();
      }

      async function savePipeline() {
        var btn = document.getElementById('savePipelineBtn');
        btn.textContent = 'Saving...';
        btn.disabled = true;

        // Read recency half-life from input
        var halfLifeInput = document.getElementById('stage-recency-halflife');
        if (halfLifeInput) {
          for (var i = 0; i < pipelineStages.length; i++) {
            if (pipelineStages[i].type === 'recency') {
              if (!pipelineStages[i].config) pipelineStages[i].config = {};
              pipelineStages[i].config.half_life_days = parseInt(halfLifeInput.value, 10) || 30;
              break;
            }
          }
        }

        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/pipeline', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ stages: pipelineStages })
          });

          if (res.ok) {
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() { document.getElementById('msg').classList.add('hidden'); }, 2000);
          } else {
            var error = await res.json().catch(function() { return {}; });
            alert('Failed to save pipeline: ' + (error.error || 'Unknown error'));
          }
        } catch (err) {
          alert('Error saving pipeline: ' + err.message);
        }

        btn.textContent = 'Save Pipeline';
        btn.disabled = false;
      }

      // =============================================
      // Live Preview: search with current slider values
      // =============================================
      var previewTimer = null;

      function schedulePreview() {
        var query = document.getElementById('preview-query').value.trim();
        if (!query) return;
        clearTimeout(previewTimer);
        previewTimer = setTimeout(previewSearch, 600);
      }

      function sanitizePreviewHtml(html) {
        if (!html) return '';
        var tmp = document.createElement('div');
        tmp.innerHTML = html;
        // Walk nodes: keep only text and <mark> tags
        var result = '';
        function walk(node) {
          if (node.nodeType === 3) {
            // Text node — escape HTML entities
            result += node.textContent.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
          } else if (node.nodeType === 1) {
            if (node.tagName === 'MARK') {
              result += '<mark class="bg-yellow-200 dark:bg-yellow-700/50 px-0.5 rounded">';
              for (var i = 0; i < node.childNodes.length; i++) walk(node.childNodes[i]);
              result += '</mark>';
            } else {
              for (var i = 0; i < node.childNodes.length; i++) walk(node.childNodes[i]);
            }
          }
        }
        for (var i = 0; i < tmp.childNodes.length; i++) walk(tmp.childNodes[i]);
        return result;
      }

      async function previewSearch() {
        var queryInput = document.getElementById('preview-query');
        var query = queryInput.value.trim();
        if (!query) return;

        var btn = document.getElementById('preview-search-btn');
        var resultsDiv = document.getElementById('preview-results');
        var emptyDiv = document.getElementById('preview-empty');
        var errorDiv = document.getElementById('preview-error');

        // Hide previous state
        resultsDiv.classList.add('hidden');
        emptyDiv.classList.add('hidden');
        errorDiv.classList.add('hidden');

        btn.disabled = true;
        btn.querySelector('svg').classList.add('animate-spin');

        try {
          var titleWeight = parseFloat(document.getElementById('fts5_title_boost').value);
          var slugWeight = parseFloat(document.getElementById('fts5_slug_boost').value);
          var bodyWeight = parseFloat(document.getElementById('fts5_body_boost').value);

          var res = await fetch('/admin/plugins/ai-search/api/relevance/preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              query: query,
              title_weight: titleWeight,
              slug_weight: slugWeight,
              body_weight: bodyWeight,
              limit: 10
            })
          });

          if (!res.ok) {
            var errData = await res.json().catch(function() { return { error: 'Request failed' }; });
            throw new Error(errData.error || 'Preview search failed');
          }

          var json = await res.json();
          var data = json.data;

          if (!data.results || data.results.length === 0) {
            emptyDiv.classList.remove('hidden');
          } else {
            renderPreviewResults(data);
            resultsDiv.classList.remove('hidden');
          }
        } catch (err) {
          document.getElementById('preview-error-text').textContent = err.message;
          errorDiv.classList.remove('hidden');
        }

        btn.disabled = false;
        btn.querySelector('svg').classList.remove('animate-spin');
      }

      function renderPreviewResults(data) {
        var metaDiv = document.getElementById('preview-meta');
        var listDiv = document.getElementById('preview-list');

        // Meta line
        metaDiv.innerHTML =
          '<span>' + data.total + ' result' + (data.total !== 1 ? 's' : '') + ' in ' + (data.query_time_ms || 0) + 'ms' +
          (data.pipeline_applied ? ' <span class="text-purple-600 dark:text-purple-400">(pipeline active)</span>' : '') +
          '</span>' +
          '<span class="font-mono">T:' + data.weights.title.toFixed(1) + ' S:' + data.weights.slug.toFixed(1) + ' B:' + data.weights.body.toFixed(1) + '</span>';

        // Result cards
        var html = '';
        for (var i = 0; i < data.results.length; i++) {
          var r = data.results[i];
          var rank = i + 1;
          var title = sanitizePreviewHtml(r.highlighted_title || r.title || 'Untitled');
          var snippet = sanitizePreviewHtml(r.highlighted_body || r.body || '');
          // Truncate snippet to ~200 chars
          if (snippet.length > 250) {
            var cutoff = snippet.lastIndexOf(' ', 250);
            if (cutoff < 100) cutoff = 250;
            snippet = snippet.substring(0, cutoff) + '...';
          }
          var score = r.bm25_score != null ? parseFloat(r.bm25_score).toFixed(3) : (r.score != null ? parseFloat(r.score).toFixed(3) : '—');
          var pipelineScore = r.pipeline_score != null ? parseFloat(r.pipeline_score).toFixed(3) : null;
          var pipelineBadge = pipelineScore !== null
            ? '<span class="flex-shrink-0 inline-flex items-center rounded-full bg-purple-50 dark:bg-purple-900/30 px-2 py-0.5 text-xs font-mono font-semibold text-purple-700 dark:text-purple-300 ring-1 ring-inset ring-purple-600/20 dark:ring-purple-500/20 ml-1" title="Pipeline Score">' + pipelineScore + '</span>'
            : '';
          var collection = r.collection_id || r.collectionId || '';

          html +=
            '<div class="flex items-start gap-3 p-3 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-800/50">' +
              '<span class="flex-shrink-0 w-7 h-7 rounded-full bg-indigo-100 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 flex items-center justify-center text-xs font-bold">' + rank + '</span>' +
              '<div class="flex-1 min-w-0">' +
                '<div class="flex items-center justify-between gap-2">' +
                  '<h4 class="text-sm font-medium text-zinc-950 dark:text-white truncate">' + title + '</h4>' +
                  '<div class="flex items-center flex-shrink-0">' +
                    '<span class="inline-flex items-center rounded-full bg-indigo-50 dark:bg-indigo-900/30 px-2 py-0.5 text-xs font-mono font-semibold text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-600/20 dark:ring-indigo-500/20">' + score + '</span>' +
                    pipelineBadge +
                  '</div>' +
                '</div>' +
                (collection ? '<p class="text-xs text-zinc-400 dark:text-zinc-500 mt-0.5">' + collection + '</p>' : '') +
                (snippet ? '<p class="text-xs text-zinc-600 dark:text-zinc-400 mt-1 line-clamp-2">' + snippet + '</p>' : '') +
              '</div>' +
            '</div>';
        }

        listDiv.innerHTML = html;
      }
      // =============================================
      // Query Synonyms
      // =============================================
      var synonymGroups = [];
      var editingSynonymId = null;

      (async function loadSynonyms() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/synonyms');
          var data = await res.json();
          if (data.success && data.data) {
            synonymGroups = data.data;
            renderSynonyms();
          }
        } catch (e) {
          console.error('Failed to load synonym groups:', e);
          document.getElementById('synonyms-summary').textContent = 'Failed to load synonym groups.';
        }
      })();

      function renderSynonyms() {
        var container = document.getElementById('synonyms-list');
        var summary = document.getElementById('synonyms-summary');
        var enabledCount = synonymGroups.filter(function(g) { return g.enabled; }).length;
        summary.textContent = synonymGroups.length + ' synonym group' + (synonymGroups.length !== 1 ? 's' : '') +
          ' (' + enabledCount + ' enabled)';

        if (synonymGroups.length === 0) {
          container.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400 py-4 text-center">No synonym groups defined. Click "Add Synonym Group" to create one.</p>';
          return;
        }

        var html = '';
        for (var i = 0; i < synonymGroups.length; i++) {
          var g = synonymGroups[i];
          var isEditing = editingSynonymId === g.id;

          html += '<div class="flex items-center gap-3 p-3 rounded-lg border border-zinc-200 dark:border-zinc-700 ' +
            (g.enabled ? 'bg-white dark:bg-zinc-800/50' : 'bg-zinc-50 dark:bg-zinc-900 opacity-60') + '">';

          // Enable/disable toggle
          html += '<input type="checkbox" ' + (g.enabled ? 'checked' : '') +
            ' onchange="toggleSynonymGroup(\\'' + g.id + '\\', this.checked)" ' +
            'class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer flex-shrink-0" title="Enable/disable this group">';

          if (isEditing) {
            // Editing mode: show input
            var termsEscaped = g.terms.join(', ').replace(/"/g, '&quot;');
            html += '<input type="text" id="synonym-edit-input" value="' + termsEscaped + '" ' +
              'class="flex-1 rounded-lg bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500" ' +
              'onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();saveEditSynonym(\\'' + g.id + '\\')}">';
            html += '<button type="button" onclick="saveEditSynonym(\\'' + g.id + '\\')" ' +
              'class="text-xs font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 px-2 py-1">Save</button>';
            html += '<button type="button" onclick="cancelEditSynonym()" ' +
              'class="text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 px-2 py-1">Cancel</button>';
          } else {
            // Display mode: show term chips
            html += '<div class="flex-1 flex flex-wrap gap-1.5">';
            for (var j = 0; j < g.terms.length; j++) {
              html += '<span class="inline-flex items-center rounded-full bg-indigo-50 dark:bg-indigo-900/30 px-2.5 py-0.5 text-xs font-medium text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-600/20 dark:ring-indigo-500/20">' +
                g.terms[j].replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</span>';
            }
            html += '</div>';

            // Edit & Delete buttons
            html += '<button type="button" onclick="startEditSynonym(\\'' + g.id + '\\')" ' +
              'class="text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 px-2 py-1 flex-shrink-0" title="Edit">Edit</button>';
            html += '<button type="button" onclick="deleteSynonymGroup(\\'' + g.id + '\\')" ' +
              'class="text-xs font-medium text-red-500 hover:text-red-700 dark:hover:text-red-300 px-2 py-1 flex-shrink-0" title="Delete">Delete</button>';
          }

          html += '</div>';
        }

        container.innerHTML = html;
      }

      function showSynonymAddForm() {
        document.getElementById('synonym-add-form').classList.remove('hidden');
        document.getElementById('synonym-add-btn').classList.add('hidden');
        document.getElementById('synonym-new-terms').focus();
      }

      function cancelSynonymAdd() {
        document.getElementById('synonym-add-form').classList.add('hidden');
        document.getElementById('synonym-add-btn').classList.remove('hidden');
        document.getElementById('synonym-new-terms').value = '';
      }

      async function saveSynonymGroup() {
        var input = document.getElementById('synonym-new-terms');
        var terms = input.value.split(',').map(function(t) { return t.trim(); }).filter(function(t) { return t.length > 0; });
        if (terms.length < 2) {
          alert('Please enter at least 2 comma-separated terms.');
          return;
        }

        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/synonyms', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ terms: terms })
          });
          var data = await res.json();
          if (data.success) {
            synonymGroups.unshift(data.data);
            renderSynonyms();
            cancelSynonymAdd();
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() { document.getElementById('msg').classList.add('hidden'); }, 2000);
          } else {
            alert('Error: ' + (data.error || 'Failed to create synonym group'));
          }
        } catch (e) {
          alert('Error creating synonym group: ' + e.message);
        }
      }

      async function toggleSynonymGroup(id, enabled) {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/synonyms/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
          });
          var data = await res.json();
          if (data.success) {
            for (var i = 0; i < synonymGroups.length; i++) {
              if (synonymGroups[i].id === id) {
                synonymGroups[i].enabled = enabled;
                break;
              }
            }
            renderSynonyms();
          }
        } catch (e) {
          console.error('Error toggling synonym group:', e);
        }
      }

      function startEditSynonym(id) {
        editingSynonymId = id;
        renderSynonyms();
        var input = document.getElementById('synonym-edit-input');
        if (input) input.focus();
      }

      function cancelEditSynonym() {
        editingSynonymId = null;
        renderSynonyms();
      }

      async function saveEditSynonym(id) {
        var input = document.getElementById('synonym-edit-input');
        if (!input) return;
        var terms = input.value.split(',').map(function(t) { return t.trim(); }).filter(function(t) { return t.length > 0; });
        if (terms.length < 2) {
          alert('Please enter at least 2 comma-separated terms.');
          return;
        }

        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/synonyms/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ terms: terms })
          });
          var data = await res.json();
          if (data.success) {
            for (var i = 0; i < synonymGroups.length; i++) {
              if (synonymGroups[i].id === id) {
                synonymGroups[i] = data.data;
                break;
              }
            }
            editingSynonymId = null;
            renderSynonyms();
          } else {
            alert('Error: ' + (data.error || 'Failed to update'));
          }
        } catch (e) {
          alert('Error updating synonym group: ' + e.message);
        }
      }

      async function deleteSynonymGroup(id) {
        if (!confirm('Delete this synonym group?')) return;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/synonyms/' + id, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
          });
          var data = await res.json();
          if (data.success) {
            synonymGroups = synonymGroups.filter(function(g) { return g.id !== id; });
            renderSynonyms();
          }
        } catch (e) {
          alert('Error deleting synonym group: ' + e.message);
        }
      }

      async function toggleSynonymsGlobal(enabled) {
        try {
          var res = await fetch('/admin/plugins/ai-search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query_synonyms_enabled: enabled })
          });
          if (res.ok) {
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() { document.getElementById('msg').classList.add('hidden'); }, 2000);
          } else {
            alert('Failed to update synonym setting');
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }
      }

      // =============================================
      // Analytics Tab
      // =============================================
      var analyticsLoaded = false;
      var dailyChart = null;
      var modeChart = null;
      var ctrChart = null;

      // Load analytics when tab is switched to (or on page load if hash is #analytics)
      var origSwitchTab = switchTab;
      switchTab = function(tabId) {
        origSwitchTab(tabId);
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
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Search',
    pageTitle: 'Search',
    currentPath: '/admin/search',
    user: data.user,
    version: data.version,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}

function renderStatCard(label: string, value: string, color: string, icon: string, colorOverride?: string): string {
  const finalColor = colorOverride || color
  const colorClasses: Record<string, string> = {
    lime: 'bg-lime-50 dark:bg-lime-500/10 text-lime-600 dark:text-lime-400 ring-lime-600/20 dark:ring-lime-500/20',
    blue: 'bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 ring-blue-600/20 dark:ring-blue-500/20',
    purple: 'bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 ring-purple-600/20 dark:ring-purple-500/20',
    sky: 'bg-sky-50 dark:bg-sky-500/10 text-sky-600 dark:text-sky-400 ring-sky-600/20 dark:ring-sky-500/20',
    amber: 'bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 ring-amber-600/20 dark:ring-amber-500/20',
    red: 'bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 ring-red-600/20 dark:ring-red-500/20'
  }

  return `
    <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="p-6">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="rounded-lg p-2 ring-1 ring-inset ${colorClasses[finalColor] || colorClasses.blue}">
              ${icon}
            </div>
            <div>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">${label}</p>
              <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white">${value}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  `
}
