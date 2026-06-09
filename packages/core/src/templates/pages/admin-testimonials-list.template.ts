import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderPagination } from '../pagination.template'
import { renderAlert } from '../alert.template'
import { renderTable } from '../table.template'
import { escapeHtml } from '../../utils/sanitize'

interface Testimonial {
  id: string
  author_name: string
  author_title?: string
  author_company?: string
  testimonial_text: string
  rating?: number
  isPublished: boolean
  sortOrder: number
  created_at: number
  updated_at: number
}

interface TestimonialsListData {
  testimonials: Testimonial[]
  totalCount: number
  currentPage: number
  totalPages: number
  user?: { name: string; email: string; role: string }
  message?: string
  messageType?: 'success' | 'error' | 'warning' | 'info'
}

export function renderTestimonialsList(data: TestimonialsListData): string {
  const { testimonials, totalCount, currentPage, totalPages, message, messageType } = data

  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Testimonials</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage customer testimonials and reviews</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="/admin/testimonials/new"
             class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            Add Testimonial
          </a>
        </div>
      </div>

      ${message ? renderAlert({ type: messageType || 'info', message, dismissible: true }) : ''}

      <!-- Filters -->
      <div class="relative rounded-xl overflow-hidden mb-6">
        <!-- Gradient Background -->
        <div class="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 dark:from-cyan-400/20 dark:via-blue-400/20 dark:to-purple-400/20"></div>

        <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
          <div class="px-6 py-5">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4 flex-1">
                <div>
                  <label for="published" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Status</label>
                  <div class="mt-2 grid grid-cols-1">
                    <select
                      name="published"
                      id="published"
                      hx-get="/admin/testimonials"
                      hx-trigger="change"
                      hx-target="#testimonials-list"
                      hx-include="[name='minRating'], [name='search']"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-cyan-500/30 dark:outline-cyan-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-cyan-500 dark:focus-visible:outline-cyan-400 sm:text-sm/6 min-w-48"
                    >
                      <option value="">All</option>
                      <option value="true">Published</option>
                      <option value="false">Draft</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-cyan-600 dark:text-cyan-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div>
                  <label for="minRating" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Min Rating</label>
                  <div class="mt-2 grid grid-cols-1">
                    <select
                      name="minRating"
                      id="minRating"
                      hx-get="/admin/testimonials"
                      hx-trigger="change"
                      hx-target="#testimonials-list"
                      hx-include="[name='published'], [name='search']"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-cyan-500/30 dark:outline-cyan-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-cyan-500 dark:focus-visible:outline-cyan-400 sm:text-sm/6 min-w-48"
                    >
                      <option value="">All Ratings</option>
                      <option value="5">5 Stars</option>
                      <option value="4">4+ Stars</option>
                      <option value="3">3+ Stars</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-cyan-600 dark:text-cyan-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>
                <div class="flex-1 max-w-md">
                  <label for="search" class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search</label>
                  <div class="relative group">
                    <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 dark:from-cyan-300 dark:to-blue-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                      <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                      </svg>
                    </div>
                    <input
                      type="text"
                      name="search"
                      id="search"
                      placeholder="Search testimonials..."
                      hx-get="/admin/testimonials"
                      hx-trigger="keyup changed delay:300ms"
                      hx-target="#testimonials-list"
                      hx-include="[name='published'], [name='minRating']"
                      class="w-full rounded-full bg-transparent px-11 py-2 text-sm text-zinc-950 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 border-2 border-cyan-200/50 dark:border-cyan-700/50 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400 focus:shadow-lg focus:shadow-cyan-500/20 dark:focus:shadow-cyan-400/20 transition-all duration-300"
                    />
                  </div>
                </div>
              </div>
              <div class="flex items-center gap-x-3 ml-4">
                <span class="text-sm/6 font-medium text-zinc-700 dark:text-zinc-300 px-3 py-1.5 rounded-full bg-white/60 dark:bg-zinc-800/60 backdrop-blur-sm">${totalCount} ${totalCount === 1 ? 'item' : 'items'}</span>
                <button
                  onclick="location.reload()"
                  class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-cyan-200/50 dark:ring-cyan-700/50 hover:bg-gradient-to-r hover:from-cyan-50 hover:to-blue-50 dark:hover:from-cyan-900/30 dark:hover:to-blue-900/30 hover:ring-cyan-300 dark:hover:ring-cyan-600 transition-all duration-200"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                  </svg>
                  Refresh
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Testimonials List -->
      <div id="testimonials-list">
        ${testimonials.length > 0 ? renderTable({
          tableId: 'testimonials-table',
          rowClickable: true,
          rowClickUrl: (row: any) => `/admin/testimonials/${row.id}`,
          columns: [
            { key: 'author', label: 'Author', sortable: true, sortType: 'string' },
            { key: 'testimonial', label: 'Testimonial', sortable: false },
            { key: 'status', label: 'Status', sortable: true, sortType: 'boolean' },
            { key: 'sortOrder', label: 'Order', sortable: true, sortType: 'number' },
            { key: 'created_at', label: 'Created', sortable: true, sortType: 'date' }
          ],
          rows: testimonials.map(testimonial => {
            const rating = testimonial.rating ? '⭐'.repeat(testimonial.rating) : ''
            const truncated = testimonial.testimonial_text.length > 100
              ? testimonial.testimonial_text.substring(0, 100) + '...'
              : testimonial.testimonial_text
            // Escape all user-controlled values (R8 — these render into the admin list = stored-XSS sink).
            const safeName = escapeHtml(testimonial.author_name)
            const safeMeta = escapeHtml([testimonial.author_title, testimonial.author_company].filter(Boolean).join(' · '))
            const safeTruncated = escapeHtml(truncated)

            return {
              id: testimonial.id,
              author: `
                <div class="flex flex-col">
                  <div class="font-medium text-zinc-950 dark:text-white">${safeName}</div>
                  ${testimonial.author_title || testimonial.author_company ? `
                    <div class="text-xs text-zinc-500 dark:text-zinc-400">
                      ${safeMeta}
                    </div>
                  ` : ''}
                  ${rating ? `<div class="text-xs mt-1">${rating}</div>` : ''}
                </div>
              `,
              testimonial: `<div class="text-sm text-zinc-700 dark:text-zinc-300 max-w-md">${safeTruncated}</div>`,
              status: testimonial.isPublished
                ? '<span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">Published</span>'
                : '<span class="inline-flex items-center rounded-md bg-zinc-50 dark:bg-zinc-500/10 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/20 dark:ring-zinc-500/20">Draft</span>',
              sortOrder: testimonial.sortOrder.toString(),
              created_at: new Date(testimonial.created_at * 1000).toLocaleDateString()
            }
          }),
          selectable: true
        }) : `
          <div class="text-center py-12 bg-white dark:bg-zinc-900 rounded-lg shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
            <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
            </svg>
            <h3 class="mt-2 text-sm font-semibold text-zinc-950 dark:text-white">No testimonials</h3>
            <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Get started by creating a new testimonial.</p>
            <div class="mt-6">
              <a href="/admin/testimonials/new" class="inline-flex items-center rounded-md bg-zinc-950 dark:bg-white px-3 py-2 text-sm font-semibold text-white dark:text-zinc-950 shadow-sm hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                  <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
                </svg>
                New Testimonial
              </a>
            </div>
          </div>
        `}
      </div>

      ${totalPages > 1 ? renderPagination({
        currentPage,
        totalPages,
        totalItems: totalCount,
        itemsPerPage: 20,
        startItem: (currentPage - 1) * 20 + 1,
        endItem: Math.min(currentPage * 20, totalCount),
        baseUrl: '/admin/testimonials'
      }) : ''}
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Testimonials',
    pageTitle: 'Testimonials',
    currentPath: '/admin/testimonials',
    user: data.user,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
