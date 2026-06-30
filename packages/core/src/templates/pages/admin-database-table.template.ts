import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'

export interface DatabaseTablePageData {
  user?: {
    name: string
    email: string
    role: string
  }
  tableName: string
  columns: string[]
  rows: any[]
  totalRows: number
  currentPage: number
  pageSize: number
  sortColumn?: string
  sortDirection?: 'asc' | 'desc'
  search?: string
}

export function renderDatabaseTablePage(data: DatabaseTablePageData): string {
  const totalPages = Math.ceil(data.totalRows / data.pageSize)
  const startRow = (data.currentPage - 1) * data.pageSize + 1
  const endRow = Math.min(data.currentPage * data.pageSize, data.totalRows)

  const pageContent = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div class="flex items-center space-x-3">
            <a
              href="/admin/settings/database-tools"
              class="inline-flex items-center text-sm/6 text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300"
            >
              <svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
              </svg>
              Back to Database Tools
            </a>
          </div>
          <h1 class="mt-2 text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Table: ${data.tableName}</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Showing ${startRow.toLocaleString()} - ${endRow.toLocaleString()} of ${data.totalRows.toLocaleString()} rows
          </p>
        </div>
        <div class="mt-4 sm:mt-0 flex items-center space-x-3">
          <div class="flex items-center space-x-2">
            <label for="pageSize" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">
              Rows per page:
            </label>
            <select
              id="pageSize"
              onchange="changePageSize(this.value)"
              class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm cursor-pointer"
            >
              <option value="10" ${data.pageSize === 10 ? 'selected' : ''}>10</option>
              <option value="20" ${data.pageSize === 20 ? 'selected' : ''}>20</option>
              <option value="50" ${data.pageSize === 50 ? 'selected' : ''}>50</option>
              <option value="100" ${data.pageSize === 100 ? 'selected' : ''}>100</option>
              <option value="200" ${data.pageSize === 200 ? 'selected' : ''}>200</option>
            </select>
          </div>
          <button
            onclick="refreshTableData()"
            class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm"
          >
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Search bar -->
      <div class="flex items-center gap-3">
        <div class="relative flex-1 max-w-xl">
          <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
            <svg class="h-4 w-4 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0"/>
            </svg>
          </div>
          <input
            id="searchInput"
            type="text"
            placeholder="Search all columns including JSON data..."
            value="${escapeHtml(data.search || '')}"
            class="block w-full rounded-lg border-0 py-2.5 pl-10 pr-10 text-sm text-zinc-900 dark:text-white bg-white dark:bg-zinc-800 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 placeholder:text-zinc-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600"
            onkeydown="if(event.key==='Enter') doSearch()"
          />
          ${data.search ? `
          <button
            onclick="clearSearch()"
            class="absolute inset-y-0 right-0 flex items-center pr-3 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
            title="Clear search"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
          ` : ''}
        </div>
        <button
          onclick="doSearch()"
          class="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 transition-colors shadow-sm"
        >
          Search
        </button>
        ${data.search ? `<span class="text-sm text-zinc-500 dark:text-zinc-400">Filtered: <strong class="text-zinc-900 dark:text-white">${escapeHtml(data.search)}</strong></span>` : ''}
      </div>

      <!-- Table Card -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
        <!-- Table -->
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-950/10 dark:divide-white/10">
            <thead class="bg-zinc-50 dark:bg-white/5">
              <tr>
                ${data.columns.map(col => `
                  <th
                    scope="col"
                    class="px-4 py-3.5 text-left text-xs font-semibold text-zinc-950 dark:text-white uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-white/10 transition-colors"
                    onclick="sortTable('${col}')"
                  >
                    <div class="flex items-center space-x-1">
                      <span>${col}</span>
                      ${data.sortColumn === col ? `
                        <svg class="w-4 h-4 ${data.sortDirection === 'asc' ? '' : 'rotate-180'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/>
                        </svg>
                      ` : `
                        <svg class="w-4 h-4 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/>
                        </svg>
                      `}
                    </div>
                  </th>
                `).join('')}
              </tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
              ${data.rows.length > 0
                ? data.rows.map((row, idx) => `
                  <tr class="${idx % 2 === 0 ? 'bg-white dark:bg-zinc-900' : 'bg-zinc-50 dark:bg-zinc-900/50'}">
                    ${data.columns.map(col => `
                      <td class="px-4 py-3 text-sm text-zinc-700 dark:text-zinc-300 whitespace-nowrap max-w-xs overflow-hidden text-ellipsis" title="${escapeHtml(String(row[col] ?? ''))}">
                        ${formatCellValue(row[col], col)}
                      </td>
                    `).join('')}
                  </tr>
                `).join('')
                : `
                  <tr>
                    <td colspan="${data.columns.length}" class="px-4 py-12 text-center text-sm text-zinc-500 dark:text-zinc-400">
                      <svg class="w-12 h-12 mx-auto mb-4 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
                      </svg>
                      <p>No data in this table</p>
                    </td>
                  </tr>
                `
              }
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        ${totalPages > 1 ? `
          <div class="flex items-center justify-between border-t border-zinc-950/10 dark:border-white/10 bg-zinc-50 dark:bg-zinc-900/50 px-4 py-3 sm:px-6">
            <div class="flex flex-1 justify-between sm:hidden">
              <button
                onclick="goToPage(${data.currentPage - 1})"
                ${data.currentPage === 1 ? 'disabled' : ''}
                class="relative inline-flex items-center rounded-lg px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onclick="goToPage(${data.currentPage + 1})"
                ${data.currentPage === totalPages ? 'disabled' : ''}
                class="relative ml-3 inline-flex items-center rounded-lg px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
            <div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
              <div>
                <p class="text-sm text-zinc-700 dark:text-zinc-300">
                  Page <span class="font-medium">${data.currentPage}</span> of <span class="font-medium">${totalPages}</span>
                </p>
              </div>
              <div>
                <nav class="isolate inline-flex -space-x-px rounded-lg shadow-sm" aria-label="Pagination">
                  <button
                    onclick="goToPage(${data.currentPage - 1})"
                    ${data.currentPage === 1 ? 'disabled' : ''}
                    class="relative inline-flex items-center rounded-l-lg px-2 py-2 text-zinc-400 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 focus:z-20 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span class="sr-only">Previous</span>
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
                    </svg>
                  </button>

                  ${generatePageNumbers(data.currentPage, totalPages)}

                  <button
                    onclick="goToPage(${data.currentPage + 1})"
                    ${data.currentPage === totalPages ? 'disabled' : ''}
                    class="relative inline-flex items-center rounded-r-lg px-2 py-2 text-zinc-400 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 focus:z-20 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span class="sr-only">Next</span>
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
                    </svg>
                  </button>
                </nav>
              </div>
            </div>
          </div>
        ` : ''}
      </div>
    </div>

    <!-- JSON Viewer Modal -->
    <div id="jsonModal" class="fixed inset-0 z-50 hidden" role="dialog" aria-modal="true">
      <div class="fixed inset-0 bg-black/60 backdrop-blur-sm" onclick="closeJsonModal()"></div>
      <div class="fixed inset-0 flex items-center justify-center p-4 pointer-events-none">
        <div class="pointer-events-auto relative w-full max-w-4xl max-h-[85vh] flex flex-col rounded-xl bg-white dark:bg-zinc-900 shadow-2xl ring-1 ring-zinc-950/10 dark:ring-white/10">
          <div class="flex items-center justify-between px-6 py-4 border-b border-zinc-200 dark:border-zinc-700">
            <div>
              <h3 id="jsonModalTitle" class="text-base font-semibold text-zinc-900 dark:text-white">Field Value</h3>
              <p id="jsonModalSubtitle" class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5"></p>
            </div>
            <div class="flex items-center gap-2">
              <button onclick="copyJsonValue()" class="inline-flex items-center gap-1.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-1.5 text-xs font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 transition-colors">
                <svg class="h-3.5 w-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/>
                </svg>
                Copy
              </button>
              <button onclick="closeJsonModal()" class="rounded-lg p-1.5 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
                <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                </svg>
              </button>
            </div>
          </div>
          <div class="flex-1 overflow-auto p-6">
            <pre id="jsonModalContent" class="text-sm font-mono text-zinc-800 dark:text-zinc-200 whitespace-pre-wrap break-words leading-relaxed"></pre>
          </div>
        </div>
      </div>
    </div>

    <script>
      const currentTableName = '${data.tableName}';
      let currentPage = ${data.currentPage};
      let currentPageSize = ${data.pageSize};
      let currentSort = '${data.sortColumn || ''}';
      let currentSortDir = '${data.sortDirection || 'asc'}';
      let currentSearch = ${JSON.stringify(data.search || '')};

      function buildParams(overrides = {}) {
        const params = new URLSearchParams();
        const p = { page: currentPage, pageSize: currentPageSize, sort: currentSort, dir: currentSortDir, search: currentSearch, ...overrides };
        if (p.page) params.set('page', p.page);
        if (p.pageSize) params.set('pageSize', p.pageSize);
        if (p.sort) { params.set('sort', p.sort); params.set('dir', p.dir || 'asc'); }
        if (p.search) params.set('search', p.search);
        return params;
      }

      function goToPage(page) {
        if (page < 1 || page > ${totalPages}) return;
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${buildParams({ page })}\`;
      }

      function sortTable(column) {
        const newDir = (currentSort === column && currentSortDir === 'asc') ? 'desc' : 'asc';
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${buildParams({ page: 1, sort: column, dir: newDir })}\`;
      }

      function changePageSize(newSize) {
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${buildParams({ page: 1, pageSize: newSize })}\`;
      }

      function refreshTableData() {
        window.location.reload();
      }

      function doSearch() {
        const val = document.getElementById('searchInput').value.trim();
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${buildParams({ page: 1, search: val })}\`;
      }

      function clearSearch() {
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${buildParams({ page: 1, search: '' })}\`;
      }

      // JSON viewer modal
      let _jsonModalValue = '';

      function openJsonModal(rawValue, colName) {
        // rawValue comes from dataset — browser already decoded HTML entities, so it's the original string
        _jsonModalValue = rawValue;
        document.getElementById('jsonModalTitle').textContent = colName;
        const el = document.getElementById('jsonModalContent');
        const subtitle = document.getElementById('jsonModalSubtitle');
        try {
          const parsed = JSON.parse(rawValue);
          const pretty = JSON.stringify(parsed, null, 2);
          subtitle.textContent = 'JSON • ' + rawValue.length + ' chars';
          el.innerHTML = syntaxHighlight(pretty);
        } catch {
          el.textContent = rawValue;
          subtitle.textContent = rawValue.length + ' chars';
        }
        document.getElementById('jsonModal').classList.remove('hidden');
        document.body.style.overflow = 'hidden';
      }

      function closeJsonModal() {
        document.getElementById('jsonModal').classList.add('hidden');
        document.body.style.overflow = '';
      }

      function copyJsonValue() {
        navigator.clipboard.writeText(_jsonModalValue).then(() => {
          const btn = event.currentTarget;
          const orig = btn.innerHTML;
          btn.textContent = 'Copied!';
          setTimeout(() => { btn.innerHTML = orig; }, 1500);
        });
      }

      function syntaxHighlight(json) {
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\\\u[a-zA-Z0-9]{4}|\\\\[^u]|[^\\\\"])*"(\\s*:)?|\\b(true|false|null)\\b|-?\\d+(?:\\.\\d*)?(?:[eE][+\\-]?\\d+)?)/g, function(match) {
          let cls = 'text-purple-600 dark:text-purple-400'; // number
          if (/^"/.test(match)) {
            if (/:$/.test(match)) {
              cls = 'text-blue-600 dark:text-blue-400 font-medium'; // key
            } else {
              cls = 'text-green-700 dark:text-green-400'; // string value
            }
          } else if (/true|false/.test(match)) {
            cls = 'text-orange-600 dark:text-orange-400';
          } else if (/null/.test(match)) {
            cls = 'text-zinc-400 italic';
          }
          return \`<span class="\${cls}">\${match}</span>\`;
        });
      }

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') closeJsonModal();
      });

      function escapeHtml(text) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return String(text).replace(/[&<>"']/g, m => map[m]);
      }
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: `Table: ${data.tableName}`,
    pageTitle: `Database: ${data.tableName}`,
    currentPath: `/admin/database-tools/tables/${data.tableName}`,
    user: data.user,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}

function generatePageNumbers(currentPage: number, totalPages: number): string {
  const pages: number[] = []
  const maxVisible = 7

  if (totalPages <= maxVisible) {
    for (let i = 1; i <= totalPages; i++) {
      pages.push(i)
    }
  } else {
    if (currentPage <= 4) {
      for (let i = 1; i <= 5; i++) pages.push(i)
      pages.push(-1) // ellipsis
      pages.push(totalPages)
    } else if (currentPage >= totalPages - 3) {
      pages.push(1)
      pages.push(-1) // ellipsis
      for (let i = totalPages - 4; i <= totalPages; i++) pages.push(i)
    } else {
      pages.push(1)
      pages.push(-1) // ellipsis
      for (let i = currentPage - 1; i <= currentPage + 1; i++) pages.push(i)
      pages.push(-1) // ellipsis
      pages.push(totalPages)
    }
  }

  return pages.map(page => {
    if (page === -1) {
      return `
        <span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700">
          ...
        </span>
      `
    }

    const isActive = page === currentPage
    return `
      <button
        onclick="goToPage(${page})"
        class="relative inline-flex items-center px-4 py-2 text-sm font-semibold ${
          isActive
            ? 'z-10 bg-indigo-600 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600'
            : 'text-zinc-900 dark:text-zinc-100 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800'
        }"
      >
        ${page}
      </button>
    `
  }).join('')
}

function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  }
  return String(text).replace(/[&<>"']/g, m => map[m] || m)
}

function isJsonString(str: string): boolean {
  const s = str.trim()
  return (s.startsWith('{') || s.startsWith('[')) && (s.endsWith('}') || s.endsWith(']'))
}

function jsonButton(raw: string, colName: string): string {
  const preview = raw.length > 60 ? escapeHtml(raw.substring(0, 60)) + '…' : escapeHtml(raw)
  // Store raw value in data attribute — browser auto-unescapes on dataset read, no double-escape issue
  return `<button data-json-val="${escapeHtml(raw)}" data-col-name="${escapeHtml(colName)}" onclick="openJsonModal(this.dataset.jsonVal, this.dataset.colName)" class="text-left text-xs font-mono text-indigo-600 dark:text-indigo-400 hover:underline">${preview}</button>`
}

function formatCellValue(value: any, colName?: string): string {
  const col = colName || 'value'
  if (value === null || value === undefined) {
    return '<span class="text-zinc-400 dark:text-zinc-500 italic">null</span>'
  }
  if (typeof value === 'boolean') {
    return `<span class="px-2 py-0.5 rounded text-xs font-medium ${value ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-zinc-100 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-400'}">${value}</span>`
  }
  if (typeof value === 'object') {
    return jsonButton(JSON.stringify(value), col)
  }
  const str = String(value)
  if (isJsonString(str)) {
    return jsonButton(str, col)
  }
  if (str.length > 120) {
    const preview = escapeHtml(str.substring(0, 120)) + '…'
    return `<button data-json-val="${escapeHtml(str)}" data-col-name="${escapeHtml(col)}" onclick="openJsonModal(this.dataset.jsonVal, this.dataset.colName)" class="text-left text-sm text-zinc-700 dark:text-zinc-300 hover:underline">${preview}</button>`
  }
  return escapeHtml(str)
}
