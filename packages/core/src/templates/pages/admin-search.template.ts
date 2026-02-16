/**
 * Admin Search Dashboard Template
 *
 * Thin orchestrator that imports per-tab modules, computes shared
 * data props, assembles tab navigation + header + tab HTML, wraps
 * all tab scripts in one <script> tag, and calls renderAdminLayoutCatalyst.
 */

import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderOverviewTab } from './admin-search-overview.template'
import { renderConfigTab, renderConfigScript } from './admin-search-config.template'
import { renderBenchmarkTab, renderBenchmarkScript } from './admin-search-benchmark.template'
import { renderRelevanceTab, renderRelevanceScript } from './admin-search-relevance.template'
import { renderAnalyticsTab, renderAnalyticsScript } from './admin-search-analytics.template'
import { renderAgentTab, renderAgentScript } from './admin-search-agent.template'
import { renderExperimentsTab, renderExperimentsScript } from './admin-search-experiments.template'

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
    facets_enabled?: boolean
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
  queriesToday?: number
  totalClicks30d?: number
  zeroResults30d?: number
  user?: { name: string; email: string; role: string }
  version?: string
}

export interface TabProps {
  settings: NonNullable<SearchDashboardData['settings']>
  collections: SearchDashboardData['collections']
  selectedCollections: string[]
  selectedCollectionIds: Set<string>
  dismissedCollectionIds: Set<string>
  enabled: boolean
  aiModeEnabled: boolean
  autocompleteEnabled: boolean
  indexMedia: boolean
  fts5Available: boolean
  fts5TotalIndexed: number
  vectorizeIndexedItems: number
  vectorizeStatusText: string
  totalQueries: number
  queriesToday: number
  totalClicks30d: number
  zeroResults30d: number
  avgQueryTime: number
  ctr: string | null
  popularQueries: Array<{ query: string; count: number }>
  facetsEnabled: boolean
  data: SearchDashboardData
}

export function renderSearchDashboard(data: SearchDashboardData): string {
  // ----- Data prep -----
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

  const selectedCollections = Array.isArray(settings.selected_collections) ? settings.selected_collections : []
  const dismissedCollections = Array.isArray(settings.dismissed_collections) ? settings.dismissed_collections : []

  const enabled = settings.enabled === true
  const aiModeEnabled = settings.ai_mode_enabled !== false
  const autocompleteEnabled = settings.autocomplete_enabled !== false
  const indexMedia = settings.index_media === true

  const selectedCollectionIds = new Set(selectedCollections.map(id => String(id)))
  const dismissedCollectionIds = new Set(dismissedCollections.map(id => String(id)))

  const collections = Array.isArray(data.collections) ? data.collections : []

  const fts5Status = data.fts5Status
  const fts5Available = fts5Status ? fts5Status.available : false
  const fts5TotalIndexed = fts5Status ? fts5Status.total_indexed : 0

  const indexStatus = data.indexStatus || {}
  let vectorizeIndexedItems = 0
  let vectorizeHasData = false
  for (const colId of Object.keys(indexStatus)) {
    const s = indexStatus[colId]
    if (s) {
      vectorizeIndexedItems += s.indexed_items || 0
      vectorizeHasData = true
    }
  }
  const vectorizeStatusText = vectorizeHasData
    ? `Vectorize index: ${vectorizeIndexedItems} items indexed`
    : 'Click reindex to rebuild the vector index for all selected collections'

  const totalQueries = data.analytics ? data.analytics.total_queries : 0
  const queriesToday = data.queriesToday ?? 0
  const totalClicks30d = data.totalClicks30d ?? 0
  const zeroResults30d = data.zeroResults30d ?? 0
  const avgQueryTime = data.analytics ? data.analytics.average_query_time : 0
  const ctr = totalQueries > 0 ? ((totalClicks30d / totalQueries) * 100).toFixed(1) : null
  const popularQueries = data.analytics ? data.analytics.popular_queries || [] : []
  const facetsEnabled = settings.facets_enabled === true

  // ----- Shared props for tab renderers -----
  const props: TabProps = {
    settings, collections, selectedCollections,
    selectedCollectionIds, dismissedCollectionIds,
    enabled, aiModeEnabled, autocompleteEnabled, indexMedia,
    fts5Available, fts5TotalIndexed, vectorizeIndexedItems,
    vectorizeStatusText,
    totalQueries, queriesToday, totalClicks30d, zeroResults30d,
    avgQueryTime, ctr, popularQueries, facetsEnabled,
    data
  }

  // ----- Assemble page -----
  const pageContent = `
    <div class="space-y-6">
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
          <button id="tab-btn-agent" onclick="switchTab('agent')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-transparent text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-300">
            Agent
          </button>
          <button id="tab-btn-experiments" onclick="switchTab('experiments')" type="button"
            class="tab-btn whitespace-nowrap border-b-2 px-1 py-3 text-sm font-medium border-transparent text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-300">
            Experiments
          </button>
        </nav>
      </div>

      ${renderOverviewTab(props)}
      ${renderConfigTab(props)}
      ${renderBenchmarkTab()}
      ${renderRelevanceTab(props)}
      ${renderAnalyticsTab()}
      ${renderAgentTab()}
      ${renderExperimentsTab()}

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

      ${renderConfigScript()}
      ${renderBenchmarkScript()}
      ${renderRelevanceScript()}
      ${renderAnalyticsScript()}
      ${renderAgentScript()}
      ${renderExperimentsScript()}

      // Hook experiments lazy-load into tab switch
      var origSwitchTab = switchTab;
      switchTab = function(tabId) {
        origSwitchTab(tabId);
        if (tabId === 'experiments' && typeof loadExperimentsOnTabSwitch === 'function') {
          loadExperimentsOnTabSwitch();
        }
      };
      // Re-init for hash
      if (initTab === 'experiments' && typeof loadExperimentsOnTabSwitch === 'function') {
        loadExperimentsOnTabSwitch();
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

// ----- Exported helpers (used by tab modules) -----

export function renderStatCard(label: string, value: string, color: string, icon: string, colorOverride?: string): string {
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

export function renderFeatureToggle(name: string, isOn: boolean): string {
  const dotClass = isOn
    ? 'bg-lime-500'
    : 'bg-zinc-300 dark:bg-zinc-600'
  const labelClass = isOn
    ? 'text-lime-700 dark:text-lime-400'
    : 'text-zinc-500 dark:text-zinc-400'
  return `
    <div class="flex items-center justify-between text-sm">
      <span class="text-zinc-700 dark:text-zinc-300">${name}</span>
      <span class="inline-flex items-center gap-1.5 ${labelClass}">
        <span class="h-2 w-2 rounded-full ${dotClass}"></span>
        ${isOn ? 'On' : 'Off'}
      </span>
    </div>
  `
}

export function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
