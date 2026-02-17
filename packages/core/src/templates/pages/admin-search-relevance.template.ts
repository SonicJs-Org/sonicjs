/**
 * Admin Search Dashboard — Relevance & Ranking Tab
 *
 * Pipeline stages, live preview, field weights, and custom synonyms.
 */

import type { TabProps } from './admin-search.template'

export function renderRelevanceTab(props: TabProps): string {
  const { settings } = props

  return `
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

          <!-- Query Substitution Rules Section -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="flex items-center justify-between mb-6">
              <div>
                <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Query Substitution Rules</h2>
                <p class="text-sm text-zinc-600 dark:text-zinc-400">
                  Deterministic query replacement: "if user searches X, replace with Y". Runs before all search modes. First matching rule wins (priority order).
                </p>
              </div>
            </div>

            <!-- Rules count summary -->
            <div id="rules-summary" class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">
              Loading query rules...
            </div>

            <!-- Rules list -->
            <div id="rules-list" class="space-y-2 mb-4">
            </div>

            <!-- Add new rule form (hidden by default) -->
            <div id="rule-add-form" class="hidden border border-dashed border-zinc-300 dark:border-zinc-600 rounded-lg p-4 mb-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
                <div>
                  <label class="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Match Pattern</label>
                  <input
                    type="text"
                    id="rule-new-pattern"
                    placeholder="e.g., overview"
                    class="w-full rounded-lg bg-white dark:bg-white/5 px-4 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 placeholder:text-zinc-400"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Replace With</label>
                  <input
                    type="text"
                    id="rule-new-substitute"
                    placeholder="e.g., getting started"
                    class="w-full rounded-lg bg-white dark:bg-white/5 px-4 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 placeholder:text-zinc-400"
                    onkeydown="if(event.key==='Enter'){event.preventDefault();saveQueryRule()}"
                  />
                </div>
              </div>
              <div class="flex items-center gap-3">
                <div>
                  <label class="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Match Type</label>
                  <select
                    id="rule-new-match-type"
                    class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="exact">Exact</option>
                    <option value="prefix">Prefix</option>
                  </select>
                </div>
                <div>
                  <label class="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Priority</label>
                  <input
                    type="number"
                    id="rule-new-priority"
                    value="0"
                    min="0"
                    max="1000"
                    class="w-20 rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
                <div class="flex items-end gap-2 ml-auto">
                  <button
                    type="button"
                    onclick="saveQueryRule()"
                    class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
                  >
                    Save
                  </button>
                  <button
                    type="button"
                    onclick="cancelRuleAdd()"
                    class="inline-flex items-center gap-1.5 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
                  >
                    Cancel
                  </button>
                </div>
              </div>
              <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
                <strong>Exact</strong> matches the full query. <strong>Prefix</strong> matches the start and preserves any suffix (e.g., "docs api" with prefix rule "docs" &rarr; "documentation api").
              </p>
            </div>

            <!-- Add button -->
            <button
              type="button"
              id="rule-add-btn"
              onclick="showRuleAddForm()"
              class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
              </svg>
              Add Substitution Rule
            </button>

            <!-- Info callout -->
            <div class="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-4 mt-6">
              <div class="flex gap-3">
                <svg class="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <div class="text-sm">
                  <p class="font-medium text-blue-900 dark:text-blue-100">Pre-dispatch &mdash; affects all search modes</p>
                  <p class="text-blue-700 dark:text-blue-300 mt-1">
                    Rules run before FTS5, AI, keyword, and hybrid search. The API response includes <code class="text-xs bg-blue-100 dark:bg-blue-800/50 px-1 py-0.5 rounded">original_query</code> when a substitution occurs, so the frontend can show "Showing results for Y instead of X".
                  </p>
                </div>
              </div>
            </div>
          </div>

          <!-- Related Searches Section -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <div class="mb-6">
              <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Related Searches</h2>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">
                Manage related search suggestions shown to users. Pairs can be created manually, generated by the Quality Agent, or cached automatically from search sessions.
              </p>
            </div>

            <!-- Summary -->
            <div id="related-summary" class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">
              Loading related searches...
            </div>

            <!-- Related searches list -->
            <div id="related-list" class="space-y-2 mb-4">
            </div>

            <!-- Add new related search form (hidden by default) -->
            <div id="related-add-form" class="hidden border border-dashed border-zinc-300 dark:border-zinc-600 rounded-lg p-4 mb-4">
              <div class="grid grid-cols-1 md:grid-cols-2 gap-3 mb-3">
                <div>
                  <label class="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Source Query</label>
                  <input
                    type="text"
                    id="related-new-source"
                    placeholder="e.g., react hooks"
                    class="w-full rounded-lg bg-white dark:bg-white/5 px-4 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 placeholder:text-zinc-400"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">Related Query</label>
                  <input
                    type="text"
                    id="related-new-target"
                    placeholder="e.g., state management"
                    class="w-full rounded-lg bg-white dark:bg-white/5 px-4 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500 placeholder:text-zinc-400"
                    onkeydown="if(event.key==='Enter'){event.preventDefault();saveRelatedSearch()}"
                  />
                </div>
              </div>
              <div class="flex items-center gap-3">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    id="related-new-bidirectional"
                    class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer"
                  />
                  <span class="text-sm text-zinc-700 dark:text-zinc-300">Bidirectional</span>
                </label>
                <div class="flex items-center gap-2 ml-auto">
                  <button
                    type="button"
                    onclick="saveRelatedSearch()"
                    class="inline-flex items-center gap-1.5 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-500"
                  >
                    Save
                  </button>
                  <button
                    type="button"
                    onclick="cancelRelatedAdd()"
                    class="inline-flex items-center gap-1.5 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
                  >
                    Cancel
                  </button>
                </div>
              </div>
              <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
                <strong>Bidirectional</strong> creates both directions (A&rarr;B and B&rarr;A). Leave unchecked for one-way suggestions.
              </p>
            </div>

            <!-- Action buttons -->
            <div class="flex items-center gap-3">
              <button
                type="button"
                id="related-add-btn"
                onclick="showRelatedAddForm()"
                class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
              >
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
                </svg>
                Add Related Search
              </button>
              <button
                type="button"
                onclick="clearRelatedCache()"
                class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
              >
                Clear Auto Cache
              </button>
            </div>

            <!-- Info callout -->
            <div class="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 p-4 mt-6">
              <div class="flex gap-3">
                <svg class="h-5 w-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <div class="text-sm">
                  <p class="font-medium text-blue-900 dark:text-blue-100">Three-source architecture: manual &gt; agent &gt; auto</p>
                  <p class="text-blue-700 dark:text-blue-300 mt-1">
                    Manual pairs (created here) have highest priority. Agent suggestions come from the Quality Agent analysis. Auto-cached pairs are generated during search sessions. Results are merged with manual first, deduped, and limited to the configured max.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
  `
}

export function renderRelevanceScript(): string {
  return `
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
      // Query Substitution Rules
      // =============================================
      var queryRules = [];
      var editingRuleId = null;

      (async function loadQueryRules() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/rules');
          var data = await res.json();
          if (data.success && data.data) {
            queryRules = data.data;
            renderQueryRules();
          }
        } catch (e) {
          console.error('Failed to load query rules:', e);
          document.getElementById('rules-summary').textContent = 'Failed to load query rules.';
        }
      })();

      function renderQueryRules() {
        var container = document.getElementById('rules-list');
        var summary = document.getElementById('rules-summary');
        var enabledCount = queryRules.filter(function(r) { return r.enabled; }).length;
        summary.textContent = queryRules.length + ' rule' + (queryRules.length !== 1 ? 's' : '') +
          ' (' + enabledCount + ' enabled)';

        if (queryRules.length === 0) {
          container.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400 py-4 text-center">No substitution rules defined. Click "Add Substitution Rule" to create one.</p>';
          return;
        }

        var html = '';
        for (var i = 0; i < queryRules.length; i++) {
          var r = queryRules[i];
          var isEditing = editingRuleId === r.id;
          var matchTypeBadge = r.match_type === 'prefix'
            ? '<span class="inline-flex items-center rounded-full bg-amber-50 dark:bg-amber-900/30 px-2 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-300 ring-1 ring-inset ring-amber-600/20 dark:ring-amber-500/20">prefix</span>'
            : '<span class="inline-flex items-center rounded-full bg-emerald-50 dark:bg-emerald-900/30 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-300 ring-1 ring-inset ring-emerald-600/20 dark:ring-emerald-500/20">exact</span>';

          html += '<div class="flex items-center gap-3 p-3 rounded-lg border border-zinc-200 dark:border-zinc-700 ' +
            (r.enabled ? 'bg-white dark:bg-zinc-800/50' : 'bg-zinc-50 dark:bg-zinc-900 opacity-60') + '">';

          // Enable/disable toggle
          html += '<input type="checkbox" ' + (r.enabled ? 'checked' : '') +
            ' onchange="toggleQueryRule(\\'' + r.id + '\\', this.checked)" ' +
            'class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer flex-shrink-0" title="Enable/disable this rule">';

          if (isEditing) {
            // Editing mode
            var patternEscaped = r.match_pattern.replace(/"/g, '&quot;');
            var substituteEscaped = r.substitute_query.replace(/"/g, '&quot;');
            html += '<div class="flex-1 grid grid-cols-1 md:grid-cols-4 gap-2">' +
              '<input type="text" id="rule-edit-pattern" value="' + patternEscaped + '" placeholder="Pattern" ' +
                'class="rounded-lg bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">' +
              '<input type="text" id="rule-edit-substitute" value="' + substituteEscaped + '" placeholder="Replace with" ' +
                'class="rounded-lg bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500" ' +
                'onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();saveEditRule(\\'' + r.id + '\\')}">' +
              '<select id="rule-edit-match-type" class="rounded-lg bg-white dark:bg-zinc-800 px-2 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">' +
                '<option value="exact"' + (r.match_type === 'exact' ? ' selected' : '') + '>Exact</option>' +
                '<option value="prefix"' + (r.match_type === 'prefix' ? ' selected' : '') + '>Prefix</option>' +
              '</select>' +
              '<input type="number" id="rule-edit-priority" value="' + r.priority + '" min="0" max="1000" ' +
                'class="w-20 rounded-lg bg-white dark:bg-zinc-800 px-2 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10">' +
            '</div>';
            html += '<button type="button" onclick="saveEditRule(\\'' + r.id + '\\')" ' +
              'class="text-xs font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 px-2 py-1">Save</button>';
            html += '<button type="button" onclick="cancelEditRule()" ' +
              'class="text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 px-2 py-1">Cancel</button>';
          } else {
            // Display mode
            html += '<div class="flex-1 flex items-center gap-2 min-w-0">' +
              matchTypeBadge +
              '<span class="text-sm font-medium text-zinc-950 dark:text-white truncate">' +
                r.match_pattern.replace(/</g, '&lt;').replace(/>/g, '&gt;') +
              '</span>' +
              '<svg class="h-4 w-4 text-zinc-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>' +
              '<span class="text-sm text-indigo-600 dark:text-indigo-400 truncate">' +
                r.substitute_query.replace(/</g, '&lt;').replace(/>/g, '&gt;') +
              '</span>' +
              (r.priority > 0 ? '<span class="text-xs text-zinc-400 flex-shrink-0">p' + r.priority + '</span>' : '') +
            '</div>';

            // Edit & Delete buttons
            html += '<button type="button" onclick="startEditRule(\\'' + r.id + '\\')" ' +
              'class="text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 px-2 py-1 flex-shrink-0" title="Edit">Edit</button>';
            html += '<button type="button" onclick="deleteQueryRule(\\'' + r.id + '\\')" ' +
              'class="text-xs font-medium text-red-500 hover:text-red-700 dark:hover:text-red-300 px-2 py-1 flex-shrink-0" title="Delete">Delete</button>';
          }

          html += '</div>';
        }

        container.innerHTML = html;
      }

      function showRuleAddForm() {
        document.getElementById('rule-add-form').classList.remove('hidden');
        document.getElementById('rule-add-btn').classList.add('hidden');
        document.getElementById('rule-new-pattern').focus();
      }

      function cancelRuleAdd() {
        document.getElementById('rule-add-form').classList.add('hidden');
        document.getElementById('rule-add-btn').classList.remove('hidden');
        document.getElementById('rule-new-pattern').value = '';
        document.getElementById('rule-new-substitute').value = '';
        document.getElementById('rule-new-match-type').value = 'exact';
        document.getElementById('rule-new-priority').value = '0';
      }

      async function saveQueryRule() {
        var pattern = document.getElementById('rule-new-pattern').value.trim();
        var substitute = document.getElementById('rule-new-substitute').value.trim();
        var matchType = document.getElementById('rule-new-match-type').value;
        var priority = parseInt(document.getElementById('rule-new-priority').value, 10) || 0;

        if (!pattern || !substitute) {
          alert('Both pattern and replacement are required.');
          return;
        }

        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              match_pattern: pattern,
              match_type: matchType,
              substitute_query: substitute,
              priority: priority
            })
          });
          var data = await res.json();
          if (data.success) {
            queryRules.unshift(data.data);
            // Re-sort by priority DESC
            queryRules.sort(function(a, b) { return b.priority - a.priority; });
            renderQueryRules();
            cancelRuleAdd();
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() { document.getElementById('msg').classList.add('hidden'); }, 2000);
          } else {
            alert('Error: ' + (data.error || 'Failed to create rule'));
          }
        } catch (e) {
          alert('Error creating rule: ' + e.message);
        }
      }

      async function toggleQueryRule(id, enabled) {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/rules/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
          });
          var data = await res.json();
          if (data.success) {
            for (var i = 0; i < queryRules.length; i++) {
              if (queryRules[i].id === id) {
                queryRules[i].enabled = enabled;
                break;
              }
            }
            renderQueryRules();
          }
        } catch (e) {
          console.error('Error toggling query rule:', e);
        }
      }

      function startEditRule(id) {
        editingRuleId = id;
        renderQueryRules();
        var input = document.getElementById('rule-edit-pattern');
        if (input) input.focus();
      }

      function cancelEditRule() {
        editingRuleId = null;
        renderQueryRules();
      }

      async function saveEditRule(id) {
        var pattern = document.getElementById('rule-edit-pattern');
        var substitute = document.getElementById('rule-edit-substitute');
        var matchType = document.getElementById('rule-edit-match-type');
        var priority = document.getElementById('rule-edit-priority');
        if (!pattern || !substitute) return;

        var patternVal = pattern.value.trim();
        var substituteVal = substitute.value.trim();
        if (!patternVal || !substituteVal) {
          alert('Both pattern and replacement are required.');
          return;
        }

        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/rules/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              match_pattern: patternVal,
              match_type: matchType.value,
              substitute_query: substituteVal,
              priority: parseInt(priority.value, 10) || 0
            })
          });
          var data = await res.json();
          if (data.success) {
            for (var i = 0; i < queryRules.length; i++) {
              if (queryRules[i].id === id) {
                queryRules[i] = data.data;
                break;
              }
            }
            editingRuleId = null;
            queryRules.sort(function(a, b) { return b.priority - a.priority; });
            renderQueryRules();
          } else {
            alert('Error: ' + (data.error || 'Failed to update'));
          }
        } catch (e) {
          alert('Error updating rule: ' + e.message);
        }
      }

      async function deleteQueryRule(id) {
        if (!confirm('Delete this substitution rule?')) return;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/relevance/rules/' + id, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
          });
          var data = await res.json();
          if (data.success) {
            queryRules = queryRules.filter(function(r) { return r.id !== id; });
            renderQueryRules();
          }
        } catch (e) {
          alert('Error deleting rule: ' + e.message);
        }
      }

      // =============================================
      // Related Searches
      // =============================================
      var relatedSearches = [];
      var editingRelatedId = null;

      (async function loadRelatedSearches() {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/related-searches');
          var data = await res.json();
          if (data.success && data.data) {
            relatedSearches = data.data;
            renderRelatedSearches();
          }
        } catch (e) {
          console.error('Failed to load related searches:', e);
          document.getElementById('related-summary').textContent = 'Failed to load related searches.';
        }
      })();

      function renderRelatedSearches() {
        var container = document.getElementById('related-list');
        var summary = document.getElementById('related-summary');
        var enabledCount = relatedSearches.filter(function(r) { return r.enabled; }).length;
        summary.textContent = relatedSearches.length + ' pair' + (relatedSearches.length !== 1 ? 's' : '') +
          ' (' + enabledCount + ' enabled)';

        if (relatedSearches.length === 0) {
          container.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400 py-4 text-center">No related search pairs configured. Click \\'Add Related Search\\' to create one, or run the Quality Agent to generate suggestions.</p>';
          return;
        }

        var sourceColors = {
          manual: 'bg-emerald-50 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300 ring-emerald-600/20 dark:ring-emerald-500/20',
          agent: 'bg-purple-50 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 ring-purple-600/20 dark:ring-purple-500/20',
          auto: 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 ring-zinc-600/20 dark:ring-zinc-500/20'
        };

        var html = '';
        for (var i = 0; i < relatedSearches.length; i++) {
          var r = relatedSearches[i];
          var isEditing = editingRelatedId === r.id;
          var srcColor = sourceColors[r.source] || sourceColors.auto;

          html += '<div class="flex items-center gap-3 p-3 rounded-lg border border-zinc-200 dark:border-zinc-700 ' +
            (r.enabled ? 'bg-white dark:bg-zinc-800/50' : 'bg-zinc-50 dark:bg-zinc-900 opacity-60') + '">';

          // Enable/disable toggle
          html += '<input type="checkbox" ' + (r.enabled ? 'checked' : '') +
            ' onchange="toggleRelatedSearch(\\'' + r.id + '\\', this.checked)" ' +
            'class="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500 cursor-pointer flex-shrink-0" title="Enable/disable">';

          // Source badge
          html += '<span class="inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ' + srcColor + '">' + (r.source || 'manual') + '</span>';

          if (isEditing) {
            // Edit mode: only related_query is editable
            var targetEscaped = (r.related_query || '').replace(/"/g, '&quot;');
            html += '<span class="text-sm font-medium text-zinc-950 dark:text-white">' +
              (r.source_query || '').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</span>';
            html += '<svg class="h-4 w-4 text-zinc-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>';
            html += '<input type="text" id="related-edit-input" value="' + targetEscaped + '" ' +
              'class="flex-1 rounded-lg bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500" ' +
              'onkeydown="if(event.key===\\'Enter\\'){event.preventDefault();saveEditRelated(\\'' + r.id + '\\')}">';
            html += '<button type="button" onclick="saveEditRelated(\\'' + r.id + '\\')" ' +
              'class="text-xs font-medium text-indigo-600 dark:text-indigo-400 hover:text-indigo-500 px-2 py-1">Save</button>';
            html += '<button type="button" onclick="cancelEditRelated()" ' +
              'class="text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 px-2 py-1">Cancel</button>';
          } else {
            // Display mode
            html += '<div class="flex-1 flex items-center gap-2 min-w-0">' +
              '<span class="text-sm font-medium text-zinc-950 dark:text-white truncate">' +
                (r.source_query || '').replace(/</g, '&lt;').replace(/>/g, '&gt;') +
              '</span>' +
              '<svg class="h-4 w-4 text-zinc-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/></svg>' +
              '<span class="text-sm text-indigo-600 dark:text-indigo-400 truncate">' +
                (r.related_query || '').replace(/</g, '&lt;').replace(/>/g, '&gt;') +
              '</span>';

            // Bidirectional badge
            if (r.bidirectional) {
              html += '<span class="inline-flex items-center rounded-full bg-sky-50 dark:bg-sky-900/30 px-2 py-0.5 text-xs font-medium text-sky-700 dark:text-sky-300 ring-1 ring-inset ring-sky-600/20 dark:ring-sky-500/20">bidi</span>';
            }

            html += '</div>';

            // Edit & Delete buttons
            html += '<button type="button" onclick="startEditRelated(\\'' + r.id + '\\')" ' +
              'class="text-xs font-medium text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300 px-2 py-1 flex-shrink-0" title="Edit">Edit</button>';
            html += '<button type="button" onclick="deleteRelatedSearch(\\'' + r.id + '\\')" ' +
              'class="text-xs font-medium text-red-500 hover:text-red-700 dark:hover:text-red-300 px-2 py-1 flex-shrink-0" title="Delete">Delete</button>';
          }

          html += '</div>';
        }

        container.innerHTML = html;
      }

      function showRelatedAddForm() {
        document.getElementById('related-add-form').classList.remove('hidden');
        document.getElementById('related-add-btn').classList.add('hidden');
        document.getElementById('related-new-source').focus();
      }

      function cancelRelatedAdd() {
        document.getElementById('related-add-form').classList.add('hidden');
        document.getElementById('related-add-btn').classList.remove('hidden');
        document.getElementById('related-new-source').value = '';
        document.getElementById('related-new-target').value = '';
        document.getElementById('related-new-bidirectional').checked = false;
      }

      async function saveRelatedSearch() {
        var source = document.getElementById('related-new-source').value.trim();
        var target = document.getElementById('related-new-target').value.trim();
        var bidirectional = document.getElementById('related-new-bidirectional').checked;

        if (!source || !target) {
          alert('Both source query and related query are required.');
          return;
        }

        try {
          var body = { source_query: source, related_query: target };
          if (bidirectional) body.bidirectional = true;

          var res = await fetch('/admin/plugins/ai-search/api/related-searches', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
          });
          var data = await res.json();
          if (data.success) {
            // Reload full list to pick up bidirectional reverse pair if created
            var listRes = await fetch('/admin/plugins/ai-search/api/related-searches');
            var listData = await listRes.json();
            if (listData.success && listData.data) {
              relatedSearches = listData.data;
            }
            renderRelatedSearches();
            cancelRelatedAdd();
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() { document.getElementById('msg').classList.add('hidden'); }, 2000);
          } else {
            alert('Error: ' + (data.error || 'Failed to create related search'));
          }
        } catch (e) {
          alert('Error creating related search: ' + e.message);
        }
      }

      async function toggleRelatedSearch(id, enabled) {
        try {
          var res = await fetch('/admin/plugins/ai-search/api/related-searches/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: enabled })
          });
          var data = await res.json();
          if (data.success) {
            for (var i = 0; i < relatedSearches.length; i++) {
              if (relatedSearches[i].id === id) {
                relatedSearches[i].enabled = enabled;
                break;
              }
            }
            renderRelatedSearches();
          }
        } catch (e) {
          console.error('Error toggling related search:', e);
        }
      }

      function startEditRelated(id) {
        editingRelatedId = id;
        renderRelatedSearches();
        var input = document.getElementById('related-edit-input');
        if (input) input.focus();
      }

      function cancelEditRelated() {
        editingRelatedId = null;
        renderRelatedSearches();
      }

      async function saveEditRelated(id) {
        var input = document.getElementById('related-edit-input');
        if (!input) return;
        var relatedQuery = input.value.trim();
        if (!relatedQuery) {
          alert('Related query cannot be empty.');
          return;
        }

        try {
          var res = await fetch('/admin/plugins/ai-search/api/related-searches/' + id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ related_query: relatedQuery })
          });
          var data = await res.json();
          if (data.success) {
            for (var i = 0; i < relatedSearches.length; i++) {
              if (relatedSearches[i].id === id) {
                relatedSearches[i] = data.data;
                break;
              }
            }
            editingRelatedId = null;
            renderRelatedSearches();
          } else {
            alert('Error: ' + (data.error || 'Failed to update'));
          }
        } catch (e) {
          alert('Error updating related search: ' + e.message);
        }
      }

      async function deleteRelatedSearch(id) {
        if (!confirm('Delete this related search pair?')) return;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/related-searches/' + id, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
          });
          var data = await res.json();
          if (data.success) {
            relatedSearches = relatedSearches.filter(function(r) { return r.id !== id; });
            renderRelatedSearches();
          }
        } catch (e) {
          alert('Error deleting related search: ' + e.message);
        }
      }

      async function clearRelatedCache() {
        if (!confirm('This clears automatically generated suggestions. They will regenerate on the next search. Continue?')) return;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/related-searches/cache', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' }
          });
          var data = await res.json();
          if (data.success) {
            document.getElementById('msg').classList.remove('hidden');
            setTimeout(function() { document.getElementById('msg').classList.add('hidden'); }, 2000);
            // Reload list in case auto entries were removed
            var listRes = await fetch('/admin/plugins/ai-search/api/related-searches');
            var listData = await listRes.json();
            if (listData.success && listData.data) {
              relatedSearches = listData.data;
              renderRelatedSearches();
            }
          } else {
            alert('Error: ' + (data.error || 'Failed to clear cache'));
          }
        } catch (e) {
          alert('Error clearing cache: ' + e.message);
        }
      }
  `
}
