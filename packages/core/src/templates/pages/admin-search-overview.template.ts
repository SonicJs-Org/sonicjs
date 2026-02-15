/**
 * Admin Search Dashboard — Overview Tab
 *
 * Stat cards, Feature Status, Search Activity, and Index Health.
 * Pure HTML, no client-side JavaScript.
 */

import { renderStatCard, renderFeatureToggle, escapeHtml } from './admin-search.template'
import type { TabProps } from './admin-search.template'

export function renderOverviewTab(props: TabProps): string {
  const {
    fts5TotalIndexed, queriesToday, avgQueryTime, ctr,
    enabled, aiModeEnabled, facetsEnabled, settings,
    totalQueries, totalClicks30d, zeroResults30d,
    popularQueries,
    fts5Available, vectorizeIndexedItems,
    selectedCollections, collections
  } = props

  return `
      <div id="tab-overview" class="tab-panel">
        <!-- Stat Cards -->
        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mt-6">
          ${renderStatCard('Indexed Documents', String(fts5TotalIndexed), 'lime', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
          `)}

          ${renderStatCard('Queries Today', String(queriesToday), 'sky', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
          `)}

          ${renderStatCard('Avg Response Time', avgQueryTime > 0 ? avgQueryTime + 'ms' : 'N/A', 'purple', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          `)}

          ${renderStatCard('Click-Through Rate', ctr !== null ? ctr + '%' : 'N/A', 'amber', `
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 15l-2 5L9 9l11 4-5 2zm0 0l5 5M7.188 2.239l.777 2.897M5.136 7.965l-2.898-.777M13.95 4.05l-2.122 2.122m-5.657 5.656l-2.12 2.122"/>
            </svg>
          `)}
        </div>

        <!-- Feature Status & Search Activity -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mt-6">
          <!-- Feature Status -->
          <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Feature Status</h2>
            </div>
            <div class="p-6">
              <div class="grid grid-cols-2 gap-x-8 gap-y-3">
                ${renderFeatureToggle('Search', enabled)}
                ${renderFeatureToggle('AI Mode', aiModeEnabled)}
                ${renderFeatureToggle('Faceted Search', facetsEnabled)}
                ${renderFeatureToggle('Query Rewriting', settings.query_rewriting_enabled === true)}
                ${renderFeatureToggle('Reranking', settings.reranking_enabled === true)}
                ${renderFeatureToggle('Synonyms', settings.query_synonyms_enabled !== false)}
              </div>
            </div>
          </div>

          <!-- Search Activity -->
          <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
            <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
              <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Search Activity</h2>
            </div>
            <div class="p-6">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <!-- Quick Stats -->
                <div>
                  <h3 class="text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-3">Quick Stats</h3>
                  <div class="space-y-2">
                    <div class="flex items-center justify-between text-sm">
                      <span class="text-zinc-600 dark:text-zinc-400">Total Queries (30d)</span>
                      <span class="font-medium text-zinc-900 dark:text-zinc-100">${totalQueries}</span>
                    </div>
                    <div class="flex items-center justify-between text-sm">
                      <span class="text-zinc-600 dark:text-zinc-400">Queries Today</span>
                      <span class="font-medium text-zinc-900 dark:text-zinc-100">${queriesToday}</span>
                    </div>
                    <div class="flex items-center justify-between text-sm">
                      <span class="text-zinc-600 dark:text-zinc-400">Total Clicks (30d)</span>
                      <span class="font-medium text-zinc-900 dark:text-zinc-100">${totalClicks30d}</span>
                    </div>
                    <div class="flex items-center justify-between text-sm">
                      <span class="text-zinc-600 dark:text-zinc-400">Zero-Result Queries</span>
                      <span class="font-medium text-zinc-900 dark:text-zinc-100">${zeroResults30d}</span>
                    </div>
                  </div>
                </div>
                <!-- Popular Queries -->
                <div>
                  <h3 class="text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-3">Popular Queries</h3>
                  ${popularQueries.length > 0 ? `
                    <div class="space-y-2">
                      ${popularQueries.slice(0, 5).map(q => `
                        <div class="flex items-center justify-between text-sm">
                          <span class="text-zinc-600 dark:text-zinc-400 truncate mr-2">${escapeHtml(q.query)}</span>
                          <span class="inline-flex items-center rounded-full bg-zinc-100 dark:bg-zinc-800 px-2 py-0.5 text-xs font-medium text-zinc-600 dark:text-zinc-400">${q.count}</span>
                        </div>
                      `).join('')}
                      <button onclick="switchTab('analytics')" class="mt-2 text-xs text-indigo-600 dark:text-indigo-400 hover:underline">
                        View all in Analytics &rarr;
                      </button>
                    </div>
                  ` : `
                    <p class="text-sm text-zinc-500 dark:text-zinc-400">No queries recorded yet.</p>
                  `}
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Index Health -->
        <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 mt-6">
          <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
            <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Index Health</h2>
          </div>
          <div class="p-6">
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div class="flex items-center justify-between text-sm">
                <span class="text-zinc-600 dark:text-zinc-400">FTS5</span>
                <div class="flex items-center gap-2">
                  <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${fts5Available
                    ? 'bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-400 ring-1 ring-inset ring-lime-600/20 dark:ring-lime-500/20'
                    : 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20'
                  }">${fts5Available ? 'Available' : 'Unavailable'}</span>
                  <span class="text-xs text-zinc-500 dark:text-zinc-400">${fts5TotalIndexed} docs</span>
                </div>
              </div>
              <div class="flex items-center justify-between text-sm">
                <span class="text-zinc-600 dark:text-zinc-400">Vectorize</span>
                <div class="flex items-center gap-2">
                  <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${aiModeEnabled
                    ? 'bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-400 ring-1 ring-inset ring-lime-600/20 dark:ring-lime-500/20'
                    : 'bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20'
                  }">${aiModeEnabled ? 'Enabled' : 'Disabled'}</span>
                  <span class="text-xs text-zinc-500 dark:text-zinc-400">${vectorizeIndexedItems} items</span>
                </div>
              </div>
              <div class="flex items-center justify-between text-sm">
                <span class="text-zinc-600 dark:text-zinc-400">Collections</span>
                <span class="font-medium text-zinc-900 dark:text-zinc-100">${selectedCollections.length} selected / ${collections.length} total</span>
              </div>
            </div>
          </div>
        </div>
      </div>
  `
}
