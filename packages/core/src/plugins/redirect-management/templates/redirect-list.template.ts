import { html } from 'hono/html'
import type { HtmlEscapedString } from 'hono/utils/html'
import type { Redirect } from '../types'
import { renderAdminLayoutCatalyst } from '../../../templates'

export interface RedirectListPageData {
  redirects: Redirect[]
  pagination: {
    page: number
    limit: number
    total: number
    totalPages: number
  }
  filters: {
    search?: string
    statusCode?: string
    matchType?: string
    isActive?: string
  }
  user: any
  successMessage?: string
}

/**
 * Render the redirect list page with table, filters, and pagination
 */
export function renderRedirectListPage(data: RedirectListPageData): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { redirects, pagination, filters, successMessage } = data

  const content = html`
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Success Message -->
      ${successMessage ? html`
        <div class="rounded-lg border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-400 p-4 mb-6">
          <p class="text-sm">${successMessage}</p>
        </div>
      ` : ''}

      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">↗️ Redirects</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Manage URL redirects and monitor redirect activity
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 flex items-center gap-3">
          <!-- Export CSV Button -->
          <a href="/admin/redirects/export${buildQueryString(filters)}"
             class="inline-flex items-center gap-2 px-3.5 py-2.5 text-sm font-medium text-zinc-700 dark:text-zinc-300 bg-white dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-600 rounded-lg hover:bg-zinc-50 dark:hover:bg-zinc-700 shadow-sm">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/>
            </svg>
            Export CSV (${pagination.total})
          </a>

          <!-- Import CSV Button -->
          <button type="button"
                  onclick="document.getElementById('import-form').classList.toggle('hidden')"
                  class="inline-flex items-center gap-2 px-3.5 py-2.5 text-sm font-medium text-zinc-700 dark:text-zinc-300 bg-white dark:bg-zinc-800 border border-zinc-300 dark:border-zinc-600 rounded-lg hover:bg-zinc-50 dark:hover:bg-zinc-700 shadow-sm">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/>
            </svg>
            Import CSV
          </button>

          <!-- New Redirect Button -->
          <a href="/admin/redirects/new" class="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-3.5 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
            </svg>
            New Redirect
          </a>
        </div>
      </div>

      <!-- Import Form (hidden by default) -->
      <div id="import-form" class="hidden mb-6 p-4 bg-zinc-50 dark:bg-zinc-800 rounded-lg border border-zinc-200 dark:border-zinc-700">
        <form hx-post="/admin/redirects/import"
              hx-encoding="multipart/form-data"
              hx-target="#import-result"
              hx-indicator="#import-progress"
              class="space-y-4">

          <div>
            <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2">
              Select CSV File
            </label>
            <input type="file"
                   name="csv_file"
                   accept=".csv"
                   required
                   class="block w-full text-sm text-zinc-500 dark:text-zinc-400
                          file:mr-4 file:py-2 file:px-4
                          file:rounded-lg file:border-0
                          file:text-sm file:font-medium
                          file:bg-blue-50 file:text-blue-700
                          dark:file:bg-blue-900/20 dark:file:text-blue-400
                          hover:file:bg-blue-100 dark:hover:file:bg-blue-900/30">
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
              Maximum 10MB, up to 10,000 rows
            </p>
          </div>

          <div>
            <label class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2">
              Duplicate Handling
            </label>
            <div class="space-y-2">
              <label class="flex items-center gap-2">
                <input type="radio" name="duplicate_handling" value="reject" checked
                       class="text-blue-600 focus:ring-blue-500">
                <span class="text-sm text-zinc-700 dark:text-zinc-300">
                  Reject file if duplicates found
                </span>
              </label>
              <label class="flex items-center gap-2">
                <input type="radio" name="duplicate_handling" value="skip"
                       class="text-blue-600 focus:ring-blue-500">
                <span class="text-sm text-zinc-700 dark:text-zinc-300">
                  Skip duplicate rows (import new only)
                </span>
              </label>
              <label class="flex items-center gap-2">
                <input type="radio" name="duplicate_handling" value="update"
                       class="text-blue-600 focus:ring-blue-500">
                <span class="text-sm text-zinc-700 dark:text-zinc-300">
                  Update existing redirects with CSV values
                </span>
              </label>
            </div>
          </div>

          <div class="flex items-center gap-3">
            <button type="submit"
                    class="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700">
              Upload and Import
            </button>
            <div id="import-progress" class="htmx-indicator">
              <svg class="animate-spin h-5 w-5 text-blue-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
              </svg>
            </div>
          </div>

          <div id="import-result"></div>
        </form>
      </div>

      <!-- Filter Bar -->
      ${renderFilterBar(filters)}

      <!-- Active Filter Chips -->
      ${renderActiveFilterChips(filters)}

      <!-- Table Card -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
        ${redirects.length > 0 ? renderTable(redirects) : renderEmptyState(filters)}
      </div>

      <!-- Pagination -->
      ${pagination.totalPages > 1 ? renderPagination(pagination, filters) : ''}
    </div>

    ${getConfirmationDialogScript()}
  `

  return renderLayout('Redirects', content)
}

/**
 * Render filter bar with search and filter controls
 */
function renderFilterBar(filters: RedirectListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <div class="mb-6 rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-4">
      <div class="flex flex-col lg:flex-row gap-4">
        <!-- Search Box -->
        <div class="flex-1">
          <input
            type="text"
            id="searchInput"
            name="search"
            placeholder="Search source or destination URLs..."
            value="${filters.search || ''}"
            class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
            oninput="debounceSearch(this.value, 300)"
          />
        </div>

        <!-- Status Code Filter -->
        <div class="w-full lg:w-48">
          <select
            name="statusCode"
            onchange="applyFilter('statusCode', this.value)"
            class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
          >
            <option value="">All Status Codes</option>
            <option value="301" ${filters.statusCode === '301' ? 'selected' : ''}>301 Permanent</option>
            <option value="302" ${filters.statusCode === '302' ? 'selected' : ''}>302 Temporary</option>
            <option value="307" ${filters.statusCode === '307' ? 'selected' : ''}>307 Temporary (Keep Method)</option>
            <option value="308" ${filters.statusCode === '308' ? 'selected' : ''}>308 Permanent (Keep Method)</option>
            <option value="410" ${filters.statusCode === '410' ? 'selected' : ''}>410 Gone</option>
          </select>
        </div>

        <!-- Match Type Filter -->
        <div class="w-full lg:w-48">
          <select
            name="matchType"
            onchange="applyFilter('matchType', this.value)"
            class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
          >
            <option value="">All Match Types</option>
            <option value="0" ${filters.matchType === '0' ? 'selected' : ''}>Exact</option>
            <option value="1" ${filters.matchType === '1' ? 'selected' : ''}>Wildcard</option>
            <option value="2" ${filters.matchType === '2' ? 'selected' : ''}>Regex</option>
          </select>
        </div>

        <!-- Active Status Filter -->
        <div class="w-full lg:w-48">
          <select
            name="isActive"
            onchange="applyFilter('isActive', this.value)"
            class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
          >
            <option value="">All Redirects</option>
            <option value="true" ${filters.isActive === 'true' ? 'selected' : ''}>Active Only</option>
            <option value="false" ${filters.isActive === 'false' ? 'selected' : ''}>Inactive Only</option>
          </select>
        </div>

        <!-- Clear Filters Button -->
        ${hasActiveFilters(filters) ? html`
          <button
            onclick="clearFilters()"
            class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
          >
            Clear Filters
          </button>
        ` : ''}
      </div>
    </div>

    <script>
      let searchTimeout;
      function debounceSearch(value, delay) {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          applyFilter('search', value);
        }, delay);
      }

      function applyFilter(name, value) {
        const params = new URLSearchParams(window.location.search);
        if (value) {
          params.set(name, value);
        } else {
          params.delete(name);
        }
        params.set('page', '1'); // Reset to page 1 on filter change
        window.location.href = window.location.pathname + '?' + params.toString();
      }

      function clearFilters() {
        window.location.href = window.location.pathname;
      }
    </script>
  `
}

/**
 * Check if any filters are active
 */
function hasActiveFilters(filters: RedirectListPageData['filters']): boolean {
  return !!(filters.search || filters.statusCode || filters.matchType || filters.isActive)
}

/**
 * Build query string from filters for export URL
 */
function buildQueryString(filters: RedirectListPageData['filters']): string {
  const params = new URLSearchParams()
  if (filters.search) params.set('search', filters.search)
  if (filters.statusCode) params.set('statusCode', filters.statusCode)
  if (filters.matchType) params.set('matchType', filters.matchType)
  if (filters.isActive) params.set('isActive', filters.isActive)
  const str = params.toString()
  return str ? `?${str}` : ''
}

/**
 * Render active filter chips showing current filters
 */
function renderActiveFilterChips(filters: RedirectListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  if (!hasActiveFilters(filters)) {
    return html``
  }

  const chips: (HtmlEscapedString | Promise<HtmlEscapedString>)[] = []

  // Search filter chip
  if (filters.search) {
    chips.push(html`
      <span class="inline-flex items-center gap-x-1 rounded-md bg-blue-50 dark:bg-blue-900/20 px-2 py-1 text-xs font-medium text-blue-700 dark:text-blue-300">
        Search: ${filters.search}
        <button onclick="removeFilter('search')" class="group relative -mr-1 h-4 w-4 rounded-sm hover:bg-blue-600/20" type="button">
          <svg class="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      </span>
    `)
  }

  // Status Code filter chip
  if (filters.statusCode) {
    const statusLabels: Record<string, string> = {
      '301': '301 Permanent',
      '302': '302 Temporary',
      '307': '307 Temp (Keep Method)',
      '308': '308 Perm (Keep Method)',
      '410': '410 Gone'
    }
    chips.push(html`
      <span class="inline-flex items-center gap-x-1 rounded-md bg-green-50 dark:bg-green-900/20 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-300">
        Status: ${statusLabels[filters.statusCode] || filters.statusCode}
        <button onclick="removeFilter('statusCode')" class="group relative -mr-1 h-4 w-4 rounded-sm hover:bg-green-600/20" type="button">
          <svg class="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      </span>
    `)
  }

  // Match Type filter chip
  if (filters.matchType) {
    const matchTypeLabels: Record<string, string> = {
      '0': 'Exact',
      '1': 'Wildcard',
      '2': 'Regex'
    }
    chips.push(html`
      <span class="inline-flex items-center gap-x-1 rounded-md bg-purple-50 dark:bg-purple-900/20 px-2 py-1 text-xs font-medium text-purple-700 dark:text-purple-300">
        Match: ${matchTypeLabels[filters.matchType] || filters.matchType}
        <button onclick="removeFilter('matchType')" class="group relative -mr-1 h-4 w-4 rounded-sm hover:bg-purple-600/20" type="button">
          <svg class="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      </span>
    `)
  }

  // Active status filter chip
  if (filters.isActive) {
    const activeLabel = filters.isActive === 'true' ? 'Active Only' : 'Inactive Only'
    chips.push(html`
      <span class="inline-flex items-center gap-x-1 rounded-md bg-amber-50 dark:bg-amber-900/20 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-300">
        Status: ${activeLabel}
        <button onclick="removeFilter('isActive')" class="group relative -mr-1 h-4 w-4 rounded-sm hover:bg-amber-600/20" type="button">
          <svg class="h-3 w-3" fill="currentColor" viewBox="0 0 20 20">
            <path d="M6.28 5.22a.75.75 0 00-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 101.06 1.06L10 11.06l3.72 3.72a.75.75 0 101.06-1.06L11.06 10l3.72-3.72a.75.75 0 00-1.06-1.06L10 8.94 6.28 5.22z" />
          </svg>
        </button>
      </span>
    `)
  }

  return html`
    <div class="mb-4 flex flex-wrap items-center gap-2">
      <span class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Active filters:</span>
      ${chips}
      <button
        onclick="clearFilters()"
        class="text-sm font-medium text-indigo-600 hover:text-indigo-500 dark:text-indigo-400 dark:hover:text-indigo-300"
      >
        Clear all
      </button>
    </div>

    <script>
      function removeFilter(name) {
        const params = new URLSearchParams(window.location.search);
        params.delete(name);
        params.set('page', '1');
        window.location.href = window.location.pathname + '?' + params.toString();
      }
    </script>
  `
}

/**
 * Render the redirects table
 */
function renderTable(redirects: Redirect[]): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <!-- Bulk Action Bar (hidden by default) -->
    <div id="bulkActionBar" class="hidden px-6 py-3 bg-indigo-50 dark:bg-indigo-900/20 border-b border-zinc-200 dark:border-zinc-800">
      <div class="flex items-center justify-between">
        <div class="text-sm text-zinc-900 dark:text-zinc-100">
          <span id="bulkSelectedCount">0</span> items selected
        </div>
        <button
          onclick="showBulkDeleteDialog()"
          class="inline-flex items-center px-3 py-1.5 text-sm font-semibold text-white bg-red-600 rounded-lg hover:bg-red-500"
        >
          Delete Selected
        </button>
      </div>
    </div>

    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800">
        <thead class="bg-zinc-50 dark:bg-zinc-800/50">
          <tr>
            <th scope="col" class="px-6 py-3 w-12">
              <input
                type="checkbox"
                id="selectAll"
                onchange="toggleSelectAll(this.checked)"
                class="h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
              />
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-700" onclick="sortTable('source')">
              Source URL
              <span id="sort-icon-source" class="ml-1 inline-block w-3">↕</span>
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-700" onclick="sortTable('destination')">
              Destination URL
              <span id="sort-icon-destination" class="ml-1 inline-block w-3">↕</span>
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-700" onclick="sortTable('statusCode')">
              Status
              <span id="sort-icon-statusCode" class="ml-1 inline-block w-3">↕</span>
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-700" onclick="sortTable('matchType')">
              Match Type
              <span id="sort-icon-matchType" class="ml-1 inline-block w-3">↕</span>
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-700" onclick="sortTable('isActive')">
              Active
              <span id="sort-icon-isActive" class="ml-1 inline-block w-3">↕</span>
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-zinc-700" onclick="sortTable('hitCount')">
              Hits
              <span id="sort-icon-hitCount" class="ml-1 inline-block w-3">↕</span>
            </th>
            <th scope="col" class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody class="bg-white dark:bg-zinc-900 divide-y divide-zinc-200 dark:divide-zinc-800" id="redirectTableBody">
          ${redirects.map(redirect => renderTableRow(redirect))}
        </tbody>
      </table>
    </div>

    <script>
      let sortDirection = {};
      let originalOrder = [];

      function sortTable(column) {
        const tbody = document.getElementById('redirectTableBody');
        const rows = Array.from(tbody.querySelectorAll('tr'));

        // Save original order on first interaction
        if (originalOrder.length === 0) {
          originalOrder = rows.map(row => row.cloneNode(true));
        }

        // Cycle through 3 states: none → asc → desc → none
        if (!sortDirection[column]) {
          // State 1: none → asc
          sortDirection[column] = 'asc';
        } else if (sortDirection[column] === 'asc') {
          // State 2: asc → desc
          sortDirection[column] = 'desc';
        } else {
          // State 3: desc → none
          sortDirection[column] = null;
        }

        // Reset to original order if sort is null
        if (sortDirection[column] === null) {
          tbody.innerHTML = '';
          originalOrder.forEach(row => tbody.appendChild(row.cloneNode(true)));
          updateSortIcons(column, null);
          return;
        }

        const ascending = sortDirection[column] === 'asc';

        rows.sort((a, b) => {
          const aValue = a.getAttribute('data-' + column);
          const bValue = b.getAttribute('data-' + column);

          if (aValue === bValue) return 0;
          if (aValue < bValue) return ascending ? -1 : 1;
          return ascending ? 1 : -1;
        });

        rows.forEach(row => tbody.appendChild(row));

        // Update sort icons
        updateSortIcons(column, ascending);
      }

      function updateSortIcons(column, ascending) {
        // Reset all icons to default
        const allColumns = ['source', 'destination', 'statusCode', 'matchType', 'isActive', 'hitCount'];
        allColumns.forEach(col => {
          const icon = document.getElementById('sort-icon-' + col);
          if (icon) {
            if (col === column) {
              if (ascending === null) {
                icon.textContent = '↕';
                icon.classList.remove('text-indigo-600', 'dark:text-indigo-400');
              } else {
                icon.textContent = ascending ? '↑' : '↓';
                icon.classList.add('text-indigo-600', 'dark:text-indigo-400');
              }
            } else {
              icon.textContent = '↕';
              icon.classList.remove('text-indigo-600', 'dark:text-indigo-400');
            }
          }
        });
      }
    </script>
  `
}

/**
 * Render a single table row
 */
function renderTableRow(redirect: Redirect): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <tr
      data-source="${redirect.source}"
      data-destination="${redirect.destination}"
      data-statuscode="${redirect.statusCode}"
      data-matchtype="${redirect.matchType}"
      data-isactive="${redirect.isActive ? '1' : '0'}"
      data-hitcount="${(redirect as any).hitCount || 0}"
      data-sourceplugin="${(redirect as any).sourcePlugin || ''}"
      data-id="${redirect.id}"
      class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
    >
      <td class="px-6 py-4 whitespace-nowrap">
        <input
          type="checkbox"
          class="redirect-checkbox h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
          value="${redirect.id}"
          onchange="updateBulkSelection()"
        />
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-900 dark:text-zinc-100">
        <div class="flex items-center">
          <span class="inline-block max-w-xs truncate" title="${redirect.source}">
            ${redirect.source}
          </span>
          ${renderSourcePluginBadge((redirect as any).sourcePlugin)}
        </div>
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-900 dark:text-zinc-100">
        <span class="inline-block max-w-xs truncate" title="${redirect.destination}">
          ${redirect.destination}
        </span>
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        ${renderStatusBadge(redirect.statusCode)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        ${renderMatchTypeBadge(redirect.matchType)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        ${renderActiveIndicator(redirect.isActive)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        ${renderHitCountBadge((redirect as any).hitCount || 0)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
        <a
          href="/admin/redirects/${redirect.id}/edit"
          class="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 mr-4"
        >
          Edit
        </a>
        <button
          onclick="confirmDelete('${redirect.id}', '${redirect.source.replace(/'/g, "\\'")}', '${redirect.destination.replace(/'/g, "\\'")}', ${(redirect as any).hitCount || 0})"
          class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
        >
          Delete
        </button>
      </td>
    </tr>
  `
}

/**
 * Render status code badge
 */
function renderStatusBadge(code: number): HtmlEscapedString | Promise<HtmlEscapedString> {
  const colors: Record<number, string> = {
    301: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
    302: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
    307: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
    308: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
    410: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400'
  }

  const colorClass = colors[code] || 'bg-zinc-100 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-300'

  return html`
    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}">
      ${code}
    </span>
  `
}

/**
 * Render match type badge
 */
function renderMatchTypeBadge(type: number): HtmlEscapedString | Promise<HtmlEscapedString> {
  const labels: Record<number, string> = {
    0: 'Exact',
    1: 'Wildcard',
    2: 'Regex'
  }

  return html`
    <span class="text-sm text-zinc-600 dark:text-zinc-400">
      ${labels[type] || 'Unknown'}
    </span>
  `
}

/**
 * Render active status indicator
 */
function renderActiveIndicator(active: boolean): HtmlEscapedString | Promise<HtmlEscapedString> {
  if (active) {
    return html`
      <span class="inline-flex items-center">
        <span class="h-2 w-2 rounded-full bg-green-500 mr-2"></span>
        <span class="text-sm text-zinc-900 dark:text-zinc-100">Active</span>
      </span>
    `
  } else {
    return html`
      <span class="inline-flex items-center">
        <span class="h-2 w-2 rounded-full bg-zinc-300 dark:bg-zinc-600 mr-2"></span>
        <span class="text-sm text-zinc-500 dark:text-zinc-400">Inactive</span>
      </span>
    `
  }
}

/**
 * Render hit count badge with color coding
 */
function renderHitCountBadge(hitCount: number): HtmlEscapedString | Promise<HtmlEscapedString> {
  // Color coding based on hit count ranges
  const colorClass = hitCount === 0
    ? 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'
    : hitCount < 10
    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400'
    : hitCount < 100
    ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400'
    : 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400'

  return html`
    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}">
      ${hitCount.toLocaleString()}
    </span>
  `
}

/**
 * Render source plugin badge (shows which plugin created the redirect)
 */
function renderSourcePluginBadge(sourcePlugin: string | null | undefined): HtmlEscapedString | Promise<HtmlEscapedString> {
  if (!sourcePlugin) {
    return html``
  }

  return html`
    <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800 dark:bg-amber-900/20 dark:text-amber-400" title="Created by ${sourcePlugin} plugin">
      ${sourcePlugin}
    </span>
  `
}

/**
 * Render empty state when no redirects exist
 */
function renderEmptyState(filters: RedirectListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  const hasFilters = hasActiveFilters(filters)

  return html`
    <div class="text-center py-12">
      <svg class="mx-auto h-12 w-12 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7l5 5m0 0l-5 5m5-5H6" />
      </svg>
      <h3 class="mt-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100">No redirects</h3>
      <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
        ${hasFilters
          ? 'No redirects match your filters. Try adjusting your search criteria.'
          : 'No redirects created yet. Click "New Redirect" to get started.'
        }
      </p>
      ${hasFilters ? html`
        <div class="mt-6">
          <button
            onclick="clearFilters()"
            class="inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
          >
            Clear Filters
          </button>
        </div>
      ` : html`
        <div class="mt-6">
          <a
            href="/admin/redirects/new"
            class="inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
          >
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
            </svg>
            New Redirect
          </a>
        </div>
      `}
    </div>
  `
}

/**
 * Render pagination controls
 */
function renderPagination(pagination: RedirectListPageData['pagination'], filters: RedirectListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { page, totalPages, total, limit } = pagination
  const startItem = (page - 1) * limit + 1
  const endItem = Math.min(page * limit, total)

  // Build base URL with filters
  const params = new URLSearchParams()
  if (filters.search) params.set('search', filters.search)
  if (filters.statusCode) params.set('statusCode', filters.statusCode)
  if (filters.matchType) params.set('matchType', filters.matchType)
  if (filters.isActive) params.set('isActive', filters.isActive)
  const baseUrl = '/admin/redirects' + (params.toString() ? '?' + params.toString() + '&' : '?')

  return html`
    <div class="bg-white dark:bg-zinc-900 px-4 py-3 flex items-center justify-between border-t border-zinc-200 dark:border-zinc-800 sm:px-6 rounded-b-xl">
      <div class="flex-1 flex justify-between sm:hidden">
        ${page > 1 ? html`
          <a href="${baseUrl}page=${page - 1}" class="relative inline-flex items-center px-4 py-2 border border-zinc-300 dark:border-zinc-700 text-sm font-medium rounded-lg text-zinc-700 dark:text-zinc-300 bg-white dark:bg-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-700">
            Previous
          </a>
        ` : ''}
        ${page < totalPages ? html`
          <a href="${baseUrl}page=${page + 1}" class="ml-3 relative inline-flex items-center px-4 py-2 border border-zinc-300 dark:border-zinc-700 text-sm font-medium rounded-lg text-zinc-700 dark:text-zinc-300 bg-white dark:bg-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-700">
            Next
          </a>
        ` : ''}
      </div>
      <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
        <div>
          <p class="text-sm text-zinc-700 dark:text-zinc-300">
            Showing <span class="font-medium">${startItem}</span> to <span class="font-medium">${endItem}</span> of{' '}
            <span class="font-medium">${total}</span> results
          </p>
        </div>
        <div>
          <nav class="relative z-0 inline-flex rounded-lg shadow-sm -space-x-px" aria-label="Pagination">
            ${page > 1 ? html`
              <a href="${baseUrl}page=${page - 1}" class="relative inline-flex items-center px-2 py-2 rounded-l-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm font-medium text-zinc-500 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-700">
                <span class="sr-only">Previous</span>
                ‹
              </a>
            ` : ''}

            ${Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
              let pageNum: number
              if (totalPages <= 5) {
                pageNum = i + 1
              } else if (page <= 3) {
                pageNum = i + 1
              } else if (page >= totalPages - 2) {
                pageNum = totalPages - 4 + i
              } else {
                pageNum = page - 2 + i
              }

              if (pageNum === page) {
                return html`
                  <span class="relative inline-flex items-center px-4 py-2 border border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20 text-sm font-medium text-indigo-600 dark:text-indigo-400">
                    ${pageNum}
                  </span>
                `
              } else {
                return html`
                  <a href="${baseUrl}page=${pageNum}" class="relative inline-flex items-center px-4 py-2 border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-700">
                    ${pageNum}
                  </a>
                `
              }
            })}

            ${page < totalPages ? html`
              <a href="${baseUrl}page=${page + 1}" class="relative inline-flex items-center px-2 py-2 rounded-r-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-sm font-medium text-zinc-500 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-700">
                <span class="sr-only">Next</span>
                ›
              </a>
            ` : ''}
          </nav>
        </div>
      </div>
    </div>
  `
}

/**
 * Get confirmation dialog script for delete operations
 */
function getConfirmationDialogScript(): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <!-- Single Delete Dialog -->
    <dialog id="deleteDialog" class="rounded-xl bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-0 max-w-md backdrop:bg-black backdrop:bg-opacity-50" style="margin: auto;">
      <div class="p-6">
        <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-2">Delete Redirect</h3>
        <p id="deleteMessage" class="text-sm text-zinc-600 dark:text-zinc-400 mb-6"></p>
        <div class="flex gap-3 justify-end">
          <button onclick="closeDeleteDialog()" class="px-4 py-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700">
            Cancel
          </button>
          <button id="confirmDeleteBtn" class="px-4 py-2 text-sm font-semibold text-white bg-red-600 rounded-lg hover:bg-red-500">
            Delete Redirect
          </button>
        </div>
      </div>
    </dialog>

    <!-- Bulk Delete Dialog -->
    <dialog id="bulkDeleteDialog" class="rounded-xl bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-0 max-w-md backdrop:bg-black backdrop:bg-opacity-50" style="margin: auto;">
      <div class="p-6">
        <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-2">Delete Multiple Redirects</h3>
        <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-6">
          Delete <span id="bulkDeleteCount" class="font-semibold">0</span> redirects? This action cannot be undone.
        </p>
        <div class="flex gap-3 justify-end">
          <button onclick="closeBulkDeleteDialog()" class="px-4 py-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700">
            Cancel
          </button>
          <button id="confirmBulkDeleteBtn" class="px-4 py-2 text-sm font-semibold text-white bg-red-600 rounded-lg hover:bg-red-500">
            Delete Selected
          </button>
        </div>
      </div>
    </dialog>

    <script>
      let deleteRedirectId = null;

      // Single delete
      function confirmDelete(id, source, destination, hitCount) {
        deleteRedirectId = id;
        const message = document.getElementById('deleteMessage');
        let text = 'Are you sure you want to delete the redirect from "' + source + '" to "' + destination + '"?';
        if (hitCount && hitCount > 0) {
          text += ' This redirect has been used ' + hitCount + ' times.';
        }
        text += ' This action cannot be undone.';
        message.textContent = text;
        document.getElementById('deleteDialog').showModal();
      }

      function closeDeleteDialog() {
        document.getElementById('deleteDialog').close();
        deleteRedirectId = null;
      }

      document.getElementById('confirmDeleteBtn').addEventListener('click', async () => {
        if (!deleteRedirectId) return;

        try {
          const authToken = document.cookie.split('; ').find(row => row.startsWith('auth_token='))?.split('=')[1];
          const headers = {};
          if (authToken) {
            headers['Authorization'] = 'Bearer ' + authToken;
          }

          const res = await fetch('/admin/redirects/' + deleteRedirectId, {
            method: 'DELETE',
            headers: headers,
            credentials: 'same-origin'
          });

          if (res.ok) {
            window.location.reload();
          } else {
            alert('Failed to delete redirect');
          }
        } catch (error) {
          console.error('Error deleting redirect:', error);
          alert('Failed to delete redirect');
        }

        closeDeleteDialog();
      });

      // Close dialog on backdrop click
      document.getElementById('deleteDialog').addEventListener('click', (e) => {
        if (e.target === document.getElementById('deleteDialog')) {
          closeDeleteDialog();
        }
      });

      // Bulk selection
      function toggleSelectAll(checked) {
        const checkboxes = document.querySelectorAll('.redirect-checkbox');
        checkboxes.forEach(checkbox => {
          checkbox.checked = checked;
        });
        updateBulkSelection();
      }

      function updateBulkSelection() {
        const checkboxes = document.querySelectorAll('.redirect-checkbox:checked');
        const count = checkboxes.length;
        const bulkActionBar = document.getElementById('bulkActionBar');
        const selectedCount = document.getElementById('bulkSelectedCount');
        const bulkDeleteCount = document.getElementById('bulkDeleteCount');
        const selectAll = document.getElementById('selectAll');

        selectedCount.textContent = count;
        bulkDeleteCount.textContent = count;

        if (count > 0) {
          bulkActionBar.classList.remove('hidden');
        } else {
          bulkActionBar.classList.add('hidden');
        }

        // Update select all checkbox state
        const allCheckboxes = document.querySelectorAll('.redirect-checkbox');
        selectAll.checked = count === allCheckboxes.length && count > 0;
        selectAll.indeterminate = count > 0 && count < allCheckboxes.length;
      }

      // Bulk delete
      function showBulkDeleteDialog() {
        document.getElementById('bulkDeleteDialog').showModal();
      }

      function closeBulkDeleteDialog() {
        document.getElementById('bulkDeleteDialog').close();
      }

      document.getElementById('confirmBulkDeleteBtn').addEventListener('click', async () => {
        const checkboxes = document.querySelectorAll('.redirect-checkbox:checked');
        const ids = Array.from(checkboxes).map(cb => cb.value);

        if (ids.length === 0) return;

        try {
          const authToken = document.cookie.split('; ').find(row => row.startsWith('auth_token='))?.split('=')[1];
          const headers = {
            'Content-Type': 'application/json'
          };
          if (authToken) {
            headers['Authorization'] = 'Bearer ' + authToken;
          }

          const res = await fetch('/admin/redirects/bulk-delete', {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin',
            body: JSON.stringify({ ids: ids })
          });

          if (res.ok) {
            window.location.reload();
          } else {
            const data = await res.json();
            alert('Failed to delete redirects: ' + (data.error || 'Unknown error'));
          }
        } catch (error) {
          console.error('Error deleting redirects:', error);
          alert('Failed to delete redirects');
        }

        closeBulkDeleteDialog();
      });

      // Close dialog on backdrop click
      document.getElementById('bulkDeleteDialog').addEventListener('click', (e) => {
        if (e.target === document.getElementById('bulkDeleteDialog')) {
          closeBulkDeleteDialog();
        }
      });
    </script>
  `
}

/**
 * Render page layout using shared admin layout template
 */
function renderLayout(title: string, content: any): HtmlEscapedString | Promise<HtmlEscapedString> {
  // Add custom styles for dialog backdrop
  const customStyles = `
    <style>
      dialog::backdrop {
        background: rgba(0, 0, 0, 0.5);
      }
    </style>
  `

  return renderAdminLayoutCatalyst({
    title,
    currentPath: '/admin/redirects',
    content: customStyles + content.toString()
  }) as HtmlEscapedString
}
