export interface PaginationData {
  currentPage: number
  totalPages: number
  totalItems: number
  /** Render the total as "N+" (lower bound) instead of an exact count. */
  totalItemsCapped?: boolean
  itemsPerPage: number
  startItem: number
  endItem: number
  baseUrl: string
  queryParams?: Record<string, string>
  showPageNumbers?: boolean
  maxPageNumbers?: number
  showPageSizeSelector?: boolean
  pageSizeOptions?: number[]
}

export function renderPagination(data: PaginationData): string {
  // Show pagination if there are multiple pages OR if page size selector is enabled
  const shouldShowPagination = data.totalPages > 1 || (data.showPageSizeSelector !== false && data.totalItems > 0)

  if (!shouldShowPagination) {
    return ''
  }

  const buildUrl = (page: number, limit?: number): string => {
    const params = new URLSearchParams(data.queryParams || {})
    params.set('page', page.toString())
    if (limit) {
      params.set('limit', limit.toString())
    } else if (data.itemsPerPage !== 20) {
      params.set('limit', data.itemsPerPage.toString())
    }
    return `${data.baseUrl}?${params.toString()}`
  }

  const buildPageSizeUrl = (limit: number): string => {
    const params = new URLSearchParams(data.queryParams || {})
    params.set('page', '1') // Reset to page 1 when changing page size
    params.set('limit', limit.toString())
    return `${data.baseUrl}?${params.toString()}`
  }

  const generatePageNumbers = (): number[] => {
    const maxNumbers = data.maxPageNumbers || 5
    const half = Math.floor(maxNumbers / 2)
    let start = Math.max(1, data.currentPage - half)
    let end = Math.min(data.totalPages, start + maxNumbers - 1)

    // Adjust start if we're near the end
    if (end - start + 1 < maxNumbers) {
      start = Math.max(1, end - maxNumbers + 1)
    }

    const pages: number[] = []
    for (let i = start; i <= end; i++) {
      pages.push(i)
    }
    return pages
  }

  return `
    <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 px-4 py-3 flex items-center justify-between mt-4">
      ${data.totalPages > 1 ? `
        <!-- Mobile Pagination -->
        <div class="flex-1 flex justify-between sm:hidden">
          ${data.currentPage > 1 ? `
            <a href="${buildUrl(data.currentPage - 1)}" class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Previous
            </a>
          ` : `
            <span class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-400 dark:text-zinc-600 shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 opacity-50 cursor-not-allowed">Previous</span>
          `}

          ${data.currentPage < data.totalPages ? `
            <a href="${buildUrl(data.currentPage + 1)}" class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Next
            </a>
          ` : `
            <span class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-400 dark:text-zinc-600 shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 opacity-50 cursor-not-allowed">Next</span>
          `}
        </div>
      ` : ''}

      <!-- Desktop Pagination -->
      <div class="hidden sm:flex-1 sm:flex sm:items-center sm:justify-between">
        <div class="flex items-center gap-4">
          <p class="text-sm text-zinc-500 dark:text-zinc-400">
            Showing <span class="font-medium text-zinc-950 dark:text-white">${data.startItem}</span> to
            <span class="font-medium text-zinc-950 dark:text-white">${data.endItem}</span> of
            <span class="font-medium text-zinc-950 dark:text-white">${data.totalItems}${data.totalItemsCapped ? '+' : ''}</span> results
          </p>
          ${data.showPageSizeSelector !== false ? `
            <div class="flex items-center gap-2">
              <label for="page-size" class="text-sm text-zinc-500 dark:text-zinc-400">Per page:</label>
              <div class="grid grid-cols-1">
                <select
                  id="page-size"
                  onchange="window.location.href = this.value"
                  class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400"
                >
                  ${(data.pageSizeOptions || [10, 20, 50, 100]).map(size => `
                    <option value="${buildPageSizeUrl(size)}" ${size === data.itemsPerPage ? 'selected' : ''}>
                      ${size}
                    </option>
                  `).join('')}
                </select>
                <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-4 self-center justify-self-end text-zinc-600 dark:text-zinc-400">
                  <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
              </div>
            </div>
          ` : ''}
        </div>

        ${data.totalPages > 1 ? `
          <div class="flex items-center gap-x-1">
            <!-- Previous Button -->
            ${data.currentPage > 1 ? `
            <a href="${buildUrl(data.currentPage - 1)}"
               class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Previous
            </a>
          ` : ''}

          <!-- Page Numbers -->
          ${data.showPageNumbers !== false ? `
            <!-- First page if not in range -->
            ${(() => {
              const pageNumbers = generatePageNumbers()
              const firstPage = pageNumbers.length > 0 ? pageNumbers[0] : null
              return firstPage && firstPage > 1 ? `
                <a href="${buildUrl(1)}"
                   class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  1
                </a>
                ${firstPage > 2 ? `
                  <span class="px-2 text-sm text-zinc-500 dark:text-zinc-400">...</span>
                ` : ''}
              ` : ''
            })()}

            <!-- Page number buttons -->
            ${generatePageNumbers().map(pageNum => `
              ${pageNum === data.currentPage ? `
                <span class="rounded-lg bg-zinc-950 dark:bg-white px-3 py-2 text-sm font-semibold text-white dark:text-zinc-950">
                  ${pageNum}
                </span>
              ` : `
                <a href="${buildUrl(pageNum)}"
                   class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  ${pageNum}
                </a>
              `}
            `).join('')}

            <!-- Last page if not in range -->
            ${(() => {
              const pageNumbers = generatePageNumbers()
              const lastPageNum = pageNumbers.length > 0 ? pageNumbers.slice(-1)[0] : null
              return lastPageNum && lastPageNum < data.totalPages ? `
                ${lastPageNum < data.totalPages - 1 ? `
                  <span class="px-2 text-sm text-zinc-500 dark:text-zinc-400">...</span>
                ` : ''}
                <a href="${buildUrl(data.totalPages)}"
                   class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                  ${data.totalPages}
                </a>
              ` : ''
            })()}
          ` : ''}

          <!-- Next Button -->
          ${data.currentPage < data.totalPages ? `
            <a href="${buildUrl(data.currentPage + 1)}"
               class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Next
            </a>
          ` : ''}
          </div>
        ` : ''}
      </div>
    </div>
  `
}