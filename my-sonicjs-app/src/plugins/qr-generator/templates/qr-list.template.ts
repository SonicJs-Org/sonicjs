import { html } from 'hono/html'
import type { HtmlEscapedString } from 'hono/utils/html'
import type { QRCode } from '../types'
import { renderAdminLayoutCatalyst } from '@sonicjs-cms/core/templates'

export interface QRListPageData {
  qrCodes: QRCode[]
  pagination: {
    page: number
    limit: number
    total: number
    totalPages: number
  }
  filters: {
    search?: string
  }
  user: any
  successMessage?: string
}

/**
 * Render the QR codes list page with table, search, and pagination
 */
export function renderQRListPage(data: QRListPageData): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { qrCodes, pagination, filters, successMessage } = data

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
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">QR Codes</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Create and manage QR codes with tracking
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 flex items-center gap-3">
          <!-- New QR Code Button -->
          <a href="/admin/qr-codes/new" class="inline-flex items-center justify-center rounded-lg bg-indigo-600 px-3.5 py-2.5 text-sm font-semibold text-white hover:bg-indigo-500 shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
            </svg>
            New QR Code
          </a>
        </div>
      </div>

      <!-- Search Bar -->
      ${renderSearchBar(filters)}

      <!-- Table Card -->
      <div id="qr-table-container" class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
        ${qrCodes.length > 0 ? renderTable(qrCodes) : renderEmptyState(filters)}
      </div>

      <!-- Pagination -->
      ${pagination.totalPages > 1 ? renderPagination(pagination, filters) : ''}
    </div>

    ${getDeleteDialogScript()}
  `

  return renderLayout('QR Codes', content)
}

/**
 * Render search bar with HTMX for instant filtering
 */
function renderSearchBar(filters: QRListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <div class="mb-6 rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-4">
      <div class="flex flex-col lg:flex-row gap-4">
        <!-- Search Box with HTMX -->
        <div class="flex-1">
          <input
            type="text"
            id="searchInput"
            name="search"
            placeholder="Search by name or URL..."
            value="${filters.search || ''}"
            hx-get="/admin/qr-codes"
            hx-trigger="input changed delay:300ms, search"
            hx-target="#qr-table-container"
            hx-push-url="true"
            hx-select="#qr-table-container"
            class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10"
          />
        </div>

        <!-- Clear Search Button -->
        ${filters.search ? html`
          <button
            onclick="clearSearch()"
            class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
          >
            Clear Search
          </button>
        ` : ''}
      </div>
    </div>

    <script>
      function clearSearch() {
        window.location.href = '/admin/qr-codes';
      }
    </script>
  `
}

/**
 * Render the QR codes table
 */
function renderTable(qrCodes: QRCode[]): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <div class="overflow-x-auto">
      <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800">
        <thead class="bg-zinc-50 dark:bg-zinc-800/50">
          <tr>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider w-16">
              Preview
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              Name
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              Destination URL
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              Scans
            </th>
            <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              Created
            </th>
            <th scope="col" class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody class="bg-white dark:bg-zinc-900 divide-y divide-zinc-200 dark:divide-zinc-800" id="qrTableBody">
          ${qrCodes.map(qrCode => renderTableRow(qrCode))}
        </tbody>
      </table>
    </div>
  `
}

/**
 * Render a single table row
 */
function renderTableRow(qrCode: QRCode): HtmlEscapedString | Promise<HtmlEscapedString> {
  const displayName = qrCode.name || 'Untitled QR Code'
  const truncatedUrl = truncateUrl(qrCode.destinationUrl, 40)
  const relativeTime = formatRelativeTime(qrCode.createdAt)
  const scanCount = qrCode.scanCount ?? 0
  const escapedName = displayName.replace(/'/g, "\\'")

  return html`
    <tr
      data-id="${qrCode.id}"
      data-name="${displayName}"
      data-scancount="${scanCount}"
      class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50"
    >
      <td class="px-6 py-4 whitespace-nowrap">
        <!-- QR Code Thumbnail Placeholder -->
        <div class="w-10 h-10 rounded bg-zinc-100 dark:bg-zinc-800 flex items-center justify-center">
          <svg class="w-6 h-6 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"/>
          </svg>
        </div>
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        <a href="/admin/qr-codes/${qrCode.id}/edit" class="text-sm font-medium text-zinc-900 dark:text-zinc-100 hover:text-indigo-600 dark:hover:text-indigo-400">
          ${displayName}
        </a>
        ${qrCode.shortCode ? html`
          <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">/qr/${qrCode.shortCode}</p>
        ` : ''}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-900 dark:text-zinc-100">
        <span class="inline-block max-w-xs truncate" title="${qrCode.destinationUrl}">
          ${truncatedUrl}
        </span>
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        ${renderScanCountBadge(scanCount)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-500 dark:text-zinc-400">
        ${relativeTime}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
        <a
          href="/admin/qr-codes/${qrCode.id}/edit"
          class="text-indigo-600 hover:text-indigo-900 dark:text-indigo-400 dark:hover:text-indigo-300 mr-4"
        >
          Edit
        </a>
        <button
          onclick="confirmDelete('${qrCode.id}', '${escapedName}', ${scanCount})"
          class="text-red-600 hover:text-red-900 dark:text-red-400 dark:hover:text-red-300"
        >
          Delete
        </button>
      </td>
    </tr>
  `
}

/**
 * Render scan count badge with color coding
 */
function renderScanCountBadge(scanCount: number): HtmlEscapedString | Promise<HtmlEscapedString> {
  // Color coding based on scan count ranges
  const colorClass = scanCount === 0
    ? 'bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400'
    : scanCount < 10
    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400'
    : scanCount < 100
    ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400'
    : 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-400'

  return html`
    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${colorClass}">
      ${scanCount.toLocaleString()}
    </span>
  `
}

/**
 * Format relative time from timestamp
 */
function formatRelativeTime(timestamp: number): string {
  const now = Date.now()
  const diff = now - timestamp
  const seconds = Math.floor(diff / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  const weeks = Math.floor(days / 7)
  const months = Math.floor(days / 30)

  if (seconds < 60) return 'just now'
  if (minutes < 60) return `${minutes} min ago`
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`
  if (days < 7) return `${days} day${days === 1 ? '' : 's'} ago`
  if (weeks < 4) return `${weeks} week${weeks === 1 ? '' : 's'} ago`
  if (months < 12) return `${months} month${months === 1 ? '' : 's'} ago`

  // Format as date for older entries
  const date = new Date(timestamp)
  return date.toLocaleDateString()
}

/**
 * Truncate URL for display
 */
function truncateUrl(url: string, maxLength: number): string {
  if (url.length <= maxLength) return url
  return url.substring(0, maxLength - 3) + '...'
}

/**
 * Build query string from filters for pagination links
 */
function buildQueryString(filters: QRListPageData['filters']): string {
  const params = new URLSearchParams()
  if (filters.search) params.set('search', filters.search)
  const str = params.toString()
  return str ? `?${str}` : ''
}

/**
 * Render empty state when no QR codes exist
 */
function renderEmptyState(filters: QRListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  const hasSearch = !!filters.search

  return html`
    <div class="text-center py-12">
      <svg class="mx-auto h-12 w-12 text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"/>
      </svg>
      <h3 class="mt-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100">No QR codes</h3>
      <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
        ${hasSearch
          ? 'No QR codes match your search. Try adjusting your search terms.'
          : 'Get started by creating your first QR code.'
        }
      </p>
      ${hasSearch ? html`
        <div class="mt-6">
          <button
            onclick="clearSearch()"
            class="inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
          >
            Clear Search
          </button>
        </div>
      ` : html`
        <div class="mt-6">
          <a
            href="/admin/qr-codes/new"
            class="inline-flex items-center rounded-lg bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
          >
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
            </svg>
            New QR Code
          </a>
        </div>
      `}
    </div>
  `
}

/**
 * Render pagination controls
 */
function renderPagination(pagination: QRListPageData['pagination'], filters: QRListPageData['filters']): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { page, totalPages, total, limit } = pagination
  const startItem = (page - 1) * limit + 1
  const endItem = Math.min(page * limit, total)

  // Build base URL with filters
  const params = new URLSearchParams()
  if (filters.search) params.set('search', filters.search)
  const baseUrl = '/admin/qr-codes' + (params.toString() ? '?' + params.toString() + '&' : '?')

  return html`
    <div class="bg-white dark:bg-zinc-900 px-4 py-3 flex items-center justify-between border-t border-zinc-200 dark:border-zinc-800 sm:px-6 rounded-b-xl mt-4">
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
                &#8249;
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
                &#8250;
              </a>
            ` : ''}
          </nav>
        </div>
      </div>
    </div>
  `
}

/**
 * Get delete confirmation dialog script
 */
function getDeleteDialogScript(): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <!-- Delete Dialog -->
    <dialog id="deleteDialog" class="rounded-xl bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-0 max-w-md backdrop:bg-black backdrop:bg-opacity-50" style="margin: auto;">
      <div class="p-6">
        <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-2">Delete QR Code</h3>
        <p id="deleteMessage" class="text-sm text-zinc-600 dark:text-zinc-400 mb-6"></p>
        <div class="flex gap-3 justify-end">
          <button onclick="closeDeleteDialog()" class="px-4 py-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700">
            Cancel
          </button>
          <button id="confirmDeleteBtn" class="px-4 py-2 text-sm font-semibold text-white bg-red-600 rounded-lg hover:bg-red-500">
            Delete QR Code
          </button>
        </div>
      </div>
    </dialog>

    <script>
      let deleteQRId = null;

      function confirmDelete(id, name, scanCount) {
        deleteQRId = id;
        const message = document.getElementById('deleteMessage');
        let text = 'Are you sure you want to delete "' + name + '"?';
        if (scanCount && scanCount > 0) {
          text += ' This QR code has been scanned ' + scanCount + ' time' + (scanCount === 1 ? '' : 's') + '.';
        }
        text += ' This action cannot be undone.';
        message.textContent = text;
        document.getElementById('deleteDialog').showModal();
      }

      function closeDeleteDialog() {
        document.getElementById('deleteDialog').close();
        deleteQRId = null;
      }

      document.getElementById('confirmDeleteBtn').addEventListener('click', async () => {
        if (!deleteQRId) return;

        try {
          const authToken = document.cookie.split('; ').find(row => row.startsWith('auth_token='))?.split('=')[1];
          const headers = {};
          if (authToken) {
            headers['Authorization'] = 'Bearer ' + authToken;
          }

          const res = await fetch('/admin/qr-codes/' + deleteQRId, {
            method: 'DELETE',
            headers: headers,
            credentials: 'same-origin'
          });

          if (res.ok) {
            window.location.reload();
          } else {
            const data = await res.json();
            alert('Failed to delete QR code: ' + (data.error || 'Unknown error'));
          }
        } catch (error) {
          console.error('Error deleting QR code:', error);
          alert('Failed to delete QR code');
        }

        closeDeleteDialog();
      });

      // Close dialog on backdrop click
      document.getElementById('deleteDialog').addEventListener('click', (e) => {
        if (e.target === document.getElementById('deleteDialog')) {
          closeDeleteDialog();
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
    currentPath: '/admin/qr-codes',
    content: customStyles + content.toString()
  }) as HtmlEscapedString
}
