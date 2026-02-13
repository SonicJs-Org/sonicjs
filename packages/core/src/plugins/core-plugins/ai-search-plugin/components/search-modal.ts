import { html } from 'hono/html'
import type { CollectionInfo } from '../types'

interface SearchModalData {
  collections: CollectionInfo[]
  defaultMode?: 'ai' | 'keyword'
}

/**
 * Render the advanced search modal
 */
export function renderSearchModal(data: SearchModalData): string {
  const defaultMode = data.defaultMode || 'ai'

  const template = html`
    <!-- Advanced Search Modal -->
    <div id="advancedSearchModal" class="hidden fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
      <div class="flex items-center justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
        <!-- Background overlay -->
        <div class="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity" onclick="closeAdvancedSearch()"></div>

        <!-- Modal panel -->
        <div class="inline-block align-bottom bg-white dark:bg-zinc-900 rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full">
          <div class="bg-white dark:bg-zinc-900 px-4 pt-5 pb-4 sm:p-6">
            <!-- Header -->
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white" id="modal-title">
                🔍 Advanced Search
              </h3>
              <button onclick="closeAdvancedSearch()" class="text-zinc-400 hover:text-zinc-500 dark:hover:text-zinc-300">
                <svg class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <!-- Search Form -->
            <form id="advancedSearchForm" class="space-y-4">
              <!-- Search Input -->
              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search Query</label>
                <div class="relative">
                  <input
                    type="text"
                    id="searchQuery"
                    name="query"
                    placeholder="Enter your search query..."
                    class="w-full rounded-lg bg-white dark:bg-white/5 px-4 py-3 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
                    autocomplete="off"
                  />
                  <div id="searchSuggestions" class="hidden absolute z-10 w-full mt-1 bg-white dark:bg-zinc-800 rounded-lg shadow-lg border border-zinc-200 dark:border-zinc-700 max-h-60 overflow-y-auto"></div>
                </div>
              </div>

              <!-- Mode Toggle -->
              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search Mode</label>
                <div class="flex gap-4">
                  <label class="flex items-center">
                    <input type="radio" name="mode" value="ai" ${defaultMode === 'ai' ? 'checked' : ''} class="mr-2">
                    <span class="text-sm text-zinc-950 dark:text-white">🤖 AI Search (Semantic)</span>
                  </label>
                  <label class="flex items-center">
                    <input type="radio" name="mode" value="keyword" ${defaultMode === 'keyword' ? 'checked' : ''} class="mr-2">
                    <span class="text-sm text-zinc-950 dark:text-white">🔤 Keyword Search</span>
                  </label>
                </div>
              </div>

              <!-- Filters -->
              <div class="border-t border-zinc-200 dark:border-zinc-800 pt-4">
                <h4 class="text-sm font-semibold text-zinc-950 dark:text-white mb-3">Filters</h4>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <!-- Collection Filter -->
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Collections</label>
                    <select
                      id="filterCollections"
                      name="collections"
                      multiple
                      class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
                      size="4"
                    >
                      <option value="">All Collections</option>
                      ${data.collections.map(
                        (collection) => html`
                          <option value="${collection.id}">${collection.display_name} (${collection.item_count || 0} items)</option>
                        `
                      )}
                    </select>
                    <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">Hold Ctrl/Cmd to select multiple</p>
                  </div>

                  <!-- Status Filter -->
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Status</label>
                    <select
                      id="filterStatus"
                      name="status"
                      multiple
                      class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
                      size="4"
                    >
                      <option value="published">Published</option>
                      <option value="draft">Draft</option>
                      <option value="review">Under Review</option>
                      <option value="scheduled">Scheduled</option>
                      <option value="archived">Archived</option>
                    </select>
                  </div>

                  <!-- Date Range -->
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Created After</label>
                    <input
                      type="date"
                      id="filterDateStart"
                      name="date_start"
                      class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
                    />
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Created Before</label>
                    <input
                      type="date"
                      id="filterDateEnd"
                      name="date_end"
                      class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
                    />
                  </div>
                </div>
              </div>

              <!-- Actions -->
              <div class="flex items-center justify-end gap-3 pt-4 border-t border-zinc-200 dark:border-zinc-800">
                <button
                  type="button"
                  onclick="closeAdvancedSearch()"
                  class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  class="inline-flex items-center justify-center rounded-lg bg-indigo-600 text-white px-6 py-2.5 text-sm font-semibold hover:bg-indigo-500 shadow-sm"
                >
                  Search
                </button>
              </div>
            </form>
          </div>

          <!-- Results Area -->
          <div id="searchResults" class="hidden px-4 pb-4 sm:px-6">
            <div class="border-t border-zinc-200 dark:border-zinc-800 pt-4">
              <div id="searchResultsContent" class="space-y-3"></div>
              <div id="searchResultsPagination" class="mt-4 flex items-center justify-between"></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <script>
      // Open modal
      function openAdvancedSearch() {
        document.getElementById('advancedSearchModal').classList.remove('hidden');
        document.getElementById('searchQuery').focus();
      }

      // Close modal
      function closeAdvancedSearch() {
        document.getElementById('advancedSearchModal').classList.add('hidden');
        document.getElementById('searchResults').classList.add('hidden');
      }

      // Autocomplete
      let autocompleteTimeout;
      document.getElementById('searchQuery').addEventListener('input', (e) => {
        const query = e.target.value.trim();
        const suggestionsDiv = document.getElementById('searchSuggestions');
        
        clearTimeout(autocompleteTimeout);
        
        if (query.length < 2) {
          suggestionsDiv.classList.add('hidden');
          return;
        }

        autocompleteTimeout = setTimeout(async () => {
          try {
            const res = await fetch(\`/api/search/suggest?q=\${encodeURIComponent(query)}\`);
            const { data } = await res.json();
            
            if (data && data.length > 0) {
              suggestionsDiv.innerHTML = data.map(s => \`
                <div class="px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-700 cursor-pointer" onclick="selectSuggestion('\${s}')">\${s}</div>
              \`).join('');
              suggestionsDiv.classList.remove('hidden');
            } else {
              suggestionsDiv.classList.add('hidden');
            }
          } catch (error) {
            console.error('Autocomplete error:', error);
          }
        }, 300);
      });

      function selectSuggestion(suggestion) {
        document.getElementById('searchQuery').value = suggestion;
        document.getElementById('searchSuggestions').classList.add('hidden');
      }

      // Hide suggestions when clicking outside
      document.addEventListener('click', (e) => {
        if (!e.target.closest('#searchQuery') && !e.target.closest('#searchSuggestions')) {
          document.getElementById('searchSuggestions').classList.add('hidden');
        }
      });

      // Click tracking state
      var currentSearchId = null;
      var currentResults = [];

      function trackClick(contentId, contentTitle, position) {
        if (!currentSearchId) return;
        fetch('/api/search/click', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            search_id: currentSearchId,
            content_id: contentId,
            content_title: contentTitle,
            click_position: position
          })
        }).catch(function() {});
      }

      // Form submission
      document.getElementById('advancedSearchForm').addEventListener('submit', async (e) => {
        e.preventDefault();

        const formData = new FormData(e.target);
        const query = formData.get('query');
        const mode = formData.get('mode') || 'ai';

        // Build filters
        const filters = {};

        const collections = Array.from(formData.getAll('collections')).filter(c => c !== '');
        if (collections.length > 0) {
          filters.collections = collections.map(Number);
        }

        const status = Array.from(formData.getAll('status'));
        if (status.length > 0) {
          filters.status = status;
        }

        const dateStart = formData.get('date_start');
        const dateEnd = formData.get('date_end');
        if (dateStart || dateEnd) {
          filters.dateRange = {
            start: dateStart ? new Date(dateStart) : null,
            end: dateEnd ? new Date(dateEnd) : null,
            field: 'created_at'
          };
        }

        // Execute search
        try {
          const res = await fetch('/api/search', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              query,
              mode,
              filters,
              limit: 20
            })
          });

          const { data } = await res.json();

          if (data && data.results) {
            currentSearchId = data.search_id || null;
            currentResults = data.results;
            displaySearchResults(data);
          }
        } catch (error) {
          console.error('Search error:', error);
          alert('Search failed. Please try again.');
        }
      });

      function displaySearchResults(searchData) {
        const resultsDiv = document.getElementById('searchResultsContent');
        const resultsSection = document.getElementById('searchResults');

        if (searchData.results.length === 0) {
          resultsDiv.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400">No results found.</p>';
        } else {
          resultsDiv.innerHTML = searchData.results.map((result, idx) => \`
            <div class="p-4 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <h4 class="text-sm font-semibold text-zinc-950 dark:text-white mb-1">
                    <a href="/admin/content/edit?id=\${result.id}" onclick="trackClick('\${result.id}', '\${(result.title || '').replace(/'/g, "\\\\'")}', \${idx + 1})" class="hover:text-indigo-600 dark:hover:text-indigo-400">\${result.title || 'Untitled'}</a>
                  </h4>
                  <p class="text-xs text-zinc-500 dark:text-zinc-400 mb-2">
                    \${result.collection_name} • \${new Date(result.created_at).toLocaleDateString()}
                    \${result.relevance_score ? \` • Relevance: \${(result.relevance_score * 100).toFixed(0)}%\` : ''}
                  </p>
                  \${result.snippet ? \`<p class="text-sm text-zinc-600 dark:text-zinc-400">\${result.snippet}</p>\` : ''}
                </div>
                <div class="ml-4">
                  <span class="px-2 py-1 text-xs rounded-full \${result.status === 'published' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-300'}">\${result.status}</span>
                </div>
              </div>
            </div>
          \`).join('');
        }

        resultsSection.classList.remove('hidden');
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      // Make functions globally available
      window.openAdvancedSearch = openAdvancedSearch;
      window.closeAdvancedSearch = closeAdvancedSearch;
      window.trackClick = trackClick;
    </script>
  `
  
  return String(template)
}
