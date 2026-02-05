import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderPagination, PaginationData } from '../pagination.template'
import { renderTable, TableData, TableColumn } from '../table.template'
import type { FilterBarData } from '../filter-bar.template'
import { renderConfirmationDialog, getConfirmationDialogScript } from '../confirmation-dialog.template'

export interface ContentItem {
  id: string
  title: string
  slug: string
  modelName: string
  collectionSourceType?: string
  statusBadge: string
  authorName: string
  formattedDate: string
  availableActions: string[]
  submitterEmail?: string
  submitterIp?: string
}

export interface ContentListPageData {
  modelName: string
  status: string
  page: number
  search?: string
  models: Array<{
    name: string
    displayName: string
    sourceType?: string
  }>
  contentItems: ContentItem[]
  totalItems: number
  itemsPerPage: number
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderContentListPage(data: ContentListPageData): string {
  // Build current URL parameters to pass to edit page
  const urlParams = new URLSearchParams()
  if (data.modelName && data.modelName !== 'all') urlParams.set('model', data.modelName)
  if (data.status && data.status !== 'all') urlParams.set('status', data.status)
  if (data.search) urlParams.set('search', data.search)
  if (data.page && data.page !== 1) urlParams.set('page', data.page.toString())
  const currentParams = urlParams.toString()

  // Check if filters are active (not in default state)
  const hasActiveFilters = data.modelName !== 'all' || data.status !== 'all' || !!data.search

  // Prepare filter bar data
  const filterBarData: FilterBarData = {
    filters: [
      {
        name: 'model',
        label: 'Model',
        options: [
          { value: 'all', label: 'All Models', selected: data.modelName === 'all' },
          ...data.models.map(model => ({
            value: model.name,
            label: model.displayName,
            selected: data.modelName === model.name
          }))
        ]
      },
      {
        name: 'status',
        label: 'Status',
        options: [
          { value: 'all', label: 'All Status', selected: data.status === 'all' },
          { value: 'draft', label: 'Draft', selected: data.status === 'draft' },
          { value: 'review', label: 'Under Review', selected: data.status === 'review' },
          { value: 'scheduled', label: 'Scheduled', selected: data.status === 'scheduled' },
          { value: 'published', label: 'Published', selected: data.status === 'published' },
          { value: 'archived', label: 'Archived', selected: data.status === 'archived' },
          { value: 'deleted', label: 'Deleted', selected: data.status === 'deleted' }
        ]
      }
    ],
    actions: [
      {
        label: 'Advanced Search',
        className: 'btn-primary',
        onclick: 'openAdvancedSearch()'
      },
      {
        label: 'Refresh',
        className: 'btn-secondary',
        onclick: 'location.reload()'
      }
    ],
    bulkActions: [
      { label: 'Publish', value: 'publish', icon: 'check-circle' },
      { label: 'Unpublish', value: 'unpublish', icon: 'x-circle' },
      { label: 'Delete', value: 'delete', icon: 'trash', className: 'text-pink-600' }
    ]
  }

  // Prepare table data
  const tableColumns: TableColumn[] = [
    {
      key: 'title',
      label: 'Title',
      sortable: true,
      sortType: 'string',
      render: (value, row) => `
        <div class="flex items-center">
          <div>
            <div class="text-sm font-medium text-zinc-950 dark:text-white">
              <a href="/admin/content/${row.id}/edit${currentParams ? `?ref=${encodeURIComponent(currentParams)}` : ''}" class="hover:text-blue-600 dark:hover:text-blue-400 transition-colors">${row.title}</a>
            </div>
            <div class="text-sm text-zinc-500 dark:text-zinc-400">${row.slug}</div>
          </div>
        </div>
      `
    },
    {
      key: 'modelName',
      label: 'Model',
      sortable: true,
      sortType: 'string',
      className: 'text-sm text-zinc-500 dark:text-zinc-400',
      render: (value, row) => {
        const isForm = row.collectionSourceType === 'form'
        return `<span>${value}</span>${isForm ? ' <span class="inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-medium bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-400 ring-1 ring-inset ring-indigo-600/20 dark:ring-indigo-500/20">Form</span>' : ''}`
      }
    },
    {
      key: 'statusBadge',
      label: 'Status',
      sortable: true,
      sortType: 'string',
      render: (value) => value
    },
    {
      key: 'authorName',
      label: 'Author',
      sortable: true,
      sortType: 'string',
      className: 'text-sm text-zinc-500 dark:text-zinc-400'
    },
    {
      key: 'formattedDate',
      label: 'Updated',
      sortable: true,
      sortType: 'date',
      className: 'text-sm text-zinc-500 dark:text-zinc-400'
    },
    {
      key: 'actions',
      label: 'Actions',
      sortable: false,
      className: 'text-sm font-medium',
      render: (value, row) => `
        <div class="flex space-x-2">
          <button
            class="inline-flex items-center justify-center p-1.5 rounded-lg bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 ring-1 ring-inset ring-cyan-600/20 dark:ring-cyan-500/20 hover:bg-cyan-100 dark:hover:bg-cyan-500/20 transition-colors"
            onclick="window.location.href='/admin/content/${row.id}/edit${currentParams ? `?ref=${encodeURIComponent(currentParams)}` : ''}'"
            title="Edit"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z"/>
            </svg>
          </button>
          <button
            class="inline-flex items-center justify-center p-1.5 rounded-lg bg-purple-50 dark:bg-purple-500/10 text-purple-700 dark:text-purple-400 ring-1 ring-inset ring-purple-600/20 dark:ring-purple-500/20 hover:bg-purple-100 dark:hover:bg-purple-500/20 transition-colors"
            onclick="window.open('/api/content/${row.id}', '_blank')"
            title="View API"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"/>
            </svg>
          </button>
          <button
            class="inline-flex items-center justify-center p-1.5 rounded-lg bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20 hover:bg-red-100 dark:hover:bg-red-500/20 transition-colors"
            hx-delete="/admin/content/${row.id}"
            hx-confirm="Are you sure you want to delete this content item?"
            hx-target="#content-list"
            hx-swap="outerHTML"
            title="Delete"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
          </button>
        </div>
      `
    }
  ]

  const tableData: TableData<ContentItem> = {
    tableId: 'content-table',
    columns: tableColumns,
    rows: data.contentItems,
    selectable: true,
    rowClickable: true,
    rowClickUrl: (row: ContentItem) => `/admin/content/${row.id}/edit${currentParams ? `?ref=${encodeURIComponent(currentParams)}` : ''}`,
    emptyMessage: 'No content found. Create your first content item to get started.'
  }

  // Prepare pagination data
  const totalPages = Math.ceil(data.totalItems / data.itemsPerPage)
  const startItem = (data.page - 1) * data.itemsPerPage + 1
  const endItem = Math.min(data.page * data.itemsPerPage, data.totalItems)

  const paginationData: PaginationData = {
    currentPage: data.page,
    totalPages,
    totalItems: data.totalItems,
    itemsPerPage: data.itemsPerPage,
    startItem,
    endItem,
    baseUrl: '/admin/content',
    queryParams: {
      model: data.modelName,
      status: data.status,
      ...(data.search ? { search: data.search } : {})
    },
    showPageSizeSelector: true,
    pageSizeOptions: [10, 20, 50, 100]
  }

  // Generate page content
  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Content Management</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage and organize your content items</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="/admin/content/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            New Content
          </a>
        </div>
      </div>
      <!-- Filters -->
      <div class="relative rounded-xl mb-6">
        <!-- Gradient Background -->
        <div class="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 dark:from-cyan-400/20 dark:via-blue-400/20 dark:to-purple-400/20 rounded-xl"></div>

        <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 rounded-xl">
          <div class="px-6 py-5">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4 flex-1">
                <!-- Model Filter -->
                <div>
                  <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Model</label>
                  <div class="grid grid-cols-1">
                    <select
                      name="model"
                      onchange="updateContentFilters('model', this.value)"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-lg bg-white/5 dark:bg-white/5 py-2 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-cyan-500/30 dark:outline-cyan-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-cyan-500 dark:focus-visible:outline-cyan-400 min-w-40"
                    >
                      <option value="all" ${data.modelName === 'all' ? 'selected' : ''}>All Models</option>
                      ${data.models.map(model => `
                        <option value="${model.name}" ${data.modelName === model.name ? 'selected' : ''}>
                          ${model.displayName}
                        </option>
                      `).join('')}
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-cyan-600 dark:text-cyan-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>

                <!-- Status Filter -->
                <div>
                  <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Status</label>
                  <div class="grid grid-cols-1">
                    <select
                      name="status"
                      onchange="updateContentFilters('status', this.value)"
                      class="col-start-1 row-start-1 w-full appearance-none rounded-lg bg-white/5 dark:bg-white/5 py-2 pl-3 pr-8 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-cyan-500/30 dark:outline-cyan-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-cyan-500 dark:focus-visible:outline-cyan-400 min-w-40"
                    >
                      <option value="all" ${data.status === 'all' ? 'selected' : ''}>All Status</option>
                      <option value="draft" ${data.status === 'draft' ? 'selected' : ''}>Draft</option>
                      <option value="review" ${data.status === 'review' ? 'selected' : ''}>Under Review</option>
                      <option value="scheduled" ${data.status === 'scheduled' ? 'selected' : ''}>Scheduled</option>
                      <option value="published" ${data.status === 'published' ? 'selected' : ''}>Published</option>
                      <option value="archived" ${data.status === 'archived' ? 'selected' : ''}>Archived</option>
                      <option value="deleted" ${data.status === 'deleted' ? 'selected' : ''}>Deleted</option>
                    </select>
                    <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-cyan-600 dark:text-cyan-400 sm:size-4">
                      <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                    </svg>
                  </div>
                </div>

                <!-- Search Input -->
                <div class="flex-1 max-w-md">
                  <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search</label>
                  <form onsubmit="performContentSearch(event)" class="flex items-center space-x-2">
                    <div class="relative group flex-1">
                      <input
                        type="text"
                        name="search"
                        id="content-search-input"
                        value="${data.search || ''}"
                        oninput="toggleContentClearButton()"
                        placeholder="Search content..."
                        class="w-full rounded-full bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm px-4 py-2.5 pl-11 pr-10 text-sm text-zinc-950 dark:text-white border-2 border-cyan-200/50 dark:border-cyan-700/50 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400 focus:bg-white dark:focus:bg-zinc-800 focus:shadow-lg focus:shadow-cyan-500/20 dark:focus:shadow-cyan-400/20 transition-all duration-300"
                      >
                      <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 dark:from-cyan-300 dark:to-blue-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                        <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                        </svg>
                      </div>
                      <button
                        type="button"
                        id="clear-content-search"
                        onclick="clearContentSearch()"
                        class="${data.search ? '' : 'hidden'} absolute right-3 top-3 flex items-center justify-center w-5 h-5 rounded-full bg-zinc-400/20 dark:bg-zinc-500/20 hover:bg-zinc-400/30 dark:hover:bg-zinc-500/30 transition-colors"
                      >
                        <svg class="h-3 w-3 text-zinc-600 dark:text-zinc-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                        </svg>
                      </button>
                    </div>
                    <button
                      type="submit"
                      class="inline-flex items-center gap-x-1.5 px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-500 dark:from-cyan-400 dark:to-blue-400 text-white text-sm font-medium rounded-full hover:from-cyan-600 hover:to-blue-600 dark:hover:from-cyan-500 dark:hover:to-blue-500 shadow-md hover:shadow-lg transition-all duration-200"
                    >
                      <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                      </svg>
                      Search
                    </button>
                  </form>
                  <script>
                    function performContentSearch(event) {
                      event.preventDefault();
                      const searchInput = document.getElementById('content-search-input');
                      const value = searchInput.value.trim();
                      const params = new URLSearchParams(window.location.search);
                      if (value) {
                        params.set('search', value);
                      } else {
                        params.delete('search');
                      }
                      params.set('page', '1');
                      window.location.href = window.location.pathname + '?' + params.toString();
                    }

                    function clearContentSearch() {
                      const params = new URLSearchParams(window.location.search);
                      params.delete('search');
                      params.set('page', '1');
                      window.location.href = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
                    }

                    function toggleContentClearButton() {
                      const searchInput = document.getElementById('content-search-input');
                      const clearButton = document.getElementById('clear-content-search');
                      if (searchInput.value.trim()) {
                        clearButton.classList.remove('hidden');
                      } else {
                        clearButton.classList.add('hidden');
                      }
                    }

                    function updateContentFilters(filterName, filterValue) {
                      const params = new URLSearchParams(window.location.search);
                      params.set(filterName, filterValue);
                      params.set('page', '1');
                      window.location.href = window.location.pathname + '?' + params.toString();
                    }

                    function clearAllFilters() {
                      window.location.href = window.location.pathname;
                    }
                  </script>
                </div>
              </div>
              <div class="flex items-center gap-x-3">
                <span class="text-sm/6 font-medium text-zinc-700 dark:text-zinc-300 px-3 py-1.5 rounded-full bg-white/60 dark:bg-zinc-800/60 backdrop-blur-sm">${data.totalItems} ${data.totalItems === 1 ? 'item' : 'items'}</span>
                ${filterBarData.actions?.map(action => `
                  <button
                    ${action.onclick ? `onclick="${action.onclick}"` : ''}
                    ${action.hxGet ? `hx-get="${action.hxGet}"` : ''}
                    ${action.hxTarget ? `hx-target="${action.hxTarget}"` : ''}
                    class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-cyan-200/50 dark:ring-cyan-700/50 hover:bg-gradient-to-r hover:from-cyan-50 hover:to-blue-50 dark:hover:from-cyan-900/30 dark:hover:to-blue-900/30 hover:ring-cyan-300 dark:hover:ring-cyan-600 transition-all duration-200"
                  >
                    ${action.label === 'Refresh' ? `
                      <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
                      </svg>
                    ` : ''}
                    ${action.label}
                  </button>
                `).join('') || ''}
                ${filterBarData.bulkActions && filterBarData.bulkActions.length > 0 ? `
                  <div class="relative inline-block" id="bulk-actions-dropdown">
                    <button
                      id="bulk-actions-btn"
                      onclick="toggleBulkActionsDropdown()"
                      class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-zinc-100/60 dark:bg-zinc-800/60 backdrop-blur-sm text-zinc-400 dark:text-zinc-600 text-sm font-medium rounded-full ring-1 ring-inset ring-zinc-200/50 dark:ring-zinc-700/50 cursor-not-allowed"
                      disabled
                    >
                      Bulk Actions
                      <svg viewBox="0 0 20 20" fill="currentColor" class="size-4">
                        <path d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                      </svg>
                    </button>

                    <div
                      id="bulk-actions-menu"
                      class="hidden absolute right-0 mt-2 w-56 origin-top-right divide-y divide-zinc-200 dark:divide-white/10 rounded-lg bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 z-50 transition-all duration-100 scale-95 opacity-0"
                      style="transition-behavior: allow-discrete;"
                    >
                      <div class="py-1">
                        <button
                          onclick="performBulkAction('publish')"
                          class="group/item flex w-full items-center px-4 py-2 text-sm text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-white/5 hover:text-zinc-950 dark:hover:text-white transition-colors"
                        >
                          <svg viewBox="0 0 20 20" fill="currentColor" class="mr-3 size-5 text-zinc-400 dark:text-zinc-500 group-hover/item:text-zinc-950 dark:group-hover/item:text-white">
                            <path fill-rule="evenodd" d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z" clip-rule="evenodd" />
                          </svg>
                          Publish Selected
                        </button>
                        <button
                          onclick="performBulkAction('draft')"
                          class="group/item flex w-full items-center px-4 py-2 text-sm text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-white/5 hover:text-zinc-950 dark:hover:text-white transition-colors"
                        >
                          <svg viewBox="0 0 20 20" fill="currentColor" class="mr-3 size-5 text-zinc-400 dark:text-zinc-500 group-hover/item:text-zinc-950 dark:group-hover/item:text-white">
                            <path d="m5.433 13.917 1.262-3.155A4 4 0 0 1 7.58 9.42l6.92-6.918a2.121 2.121 0 0 1 3 3l-6.92 6.918c-.383.383-.84.685-1.343.886l-3.154 1.262a.5.5 0 0 1-.65-.65Z" />
                            <path d="M3.5 5.75c0-.69.56-1.25 1.25-1.25H10A.75.75 0 0 0 10 3H4.75A2.75 2.75 0 0 0 2 5.75v9.5A2.75 2.75 0 0 0 4.75 18h9.5A2.75 2.75 0 0 0 17 15.25V10a.75.75 0 0 0-1.5 0v5.25c0 .69-.56 1.25-1.25 1.25h-9.5c-.69 0-1.25-.56-1.25-1.25v-9.5Z" />
                          </svg>
                          Move to Draft
                        </button>
                      </div>
                      <div class="py-1">
                        <button
                          onclick="performBulkAction('delete')"
                          class="group/item flex w-full items-center px-4 py-2 text-sm text-zinc-700 dark:text-zinc-300 hover:bg-red-50 dark:hover:bg-red-500/10 hover:text-red-600 dark:hover:text-red-400 transition-colors"
                        >
                          <svg viewBox="0 0 20 20" fill="currentColor" class="mr-3 size-5 text-zinc-400 dark:text-zinc-500 group-hover/item:text-red-600 dark:group-hover/item:text-red-400">
                            <path fill-rule="evenodd" d="M8.75 1A2.75 2.75 0 0 0 6 3.75v.443c-.795.077-1.584.176-2.365.298a.75.75 0 1 0 .23 1.482l.149-.022.841 10.518A2.75 2.75 0 0 0 7.596 19h4.807a2.75 2.75 0 0 0 2.742-2.53l.841-10.52.149.023a.75.75 0 0 0 .23-1.482A41.03 41.03 0 0 0 14 4.193V3.75A2.75 2.75 0 0 0 11.25 1h-2.5ZM10 4c.84 0 1.673.025 2.5.075V3.75c0-.69-.56-1.25-1.25-1.25h-2.5c-.69 0-1.25.56-1.25 1.25v.325C8.327 4.025 9.16 4 10 4ZM8.58 7.72a.75.75 0 0 0-1.5.06l.3 7.5a.75.75 0 1 0 1.5-.06l-.3-7.5Zm4.34.06a.75.75 0 1 0-1.5-.06l-.3 7.5a.75.75 0 1 0 1.5.06l.3-7.5Z" clip-rule="evenodd" fill-rule="evenodd" />
                          </svg>
                          Delete Selected
                        </button>
                      </div>
                    </div>
                  </div>
                ` : ''}
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Content List -->
      <div id="content-list">
        ${renderTable(tableData)}
        ${renderPagination(paginationData)}
      </div>
      
    </div>
    
    <!-- Modals -->
    <div id="bulk-actions-modal"></div>
    <div id="versions-modal"></div>
    
    <script>
      // Update bulk actions button state
      function updateBulkActionsButton() {
        const checkboxes = document.querySelectorAll('input[type="checkbox"].row-checkbox');
        const checkedCount = Array.from(checkboxes).filter(cb => cb.checked).length;
        const btn = document.getElementById('bulk-actions-btn');
        const menu = document.getElementById('bulk-actions-menu');

        if (!btn) return;

        if (checkedCount > 0) {
          btn.disabled = false;
          btn.className = 'inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-cyan-200/50 dark:ring-cyan-700/50 hover:bg-gradient-to-r hover:from-cyan-50 hover:to-blue-50 dark:hover:from-cyan-900/30 dark:hover:to-blue-900/30 hover:ring-cyan-300 dark:hover:ring-cyan-600 transition-all duration-200';
        } else {
          btn.disabled = true;
          btn.className = 'inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-zinc-100/60 dark:bg-zinc-800/60 backdrop-blur-sm text-zinc-400 dark:text-zinc-600 text-sm font-medium rounded-full ring-1 ring-inset ring-zinc-200/50 dark:ring-zinc-700/50 cursor-not-allowed';
          // Hide menu when no items selected
          if (menu) {
            menu.classList.remove('scale-100', 'opacity-100');
            menu.classList.add('scale-95', 'opacity-0', 'hidden');
          }
        }
      }

      // Select all functionality
      document.addEventListener('change', function(e) {
        if (e.target.id === 'select-all') {
          const checkboxes = document.querySelectorAll('.row-checkbox');
          checkboxes.forEach(cb => cb.checked = e.target.checked);
          updateBulkActionsButton();
        } else if (e.target.classList.contains('row-checkbox')) {
          updateBulkActionsButton();
        }
      });

      // Initialize button state on page load
      document.addEventListener('DOMContentLoaded', function() {
        updateBulkActionsButton();
      });

      // Toggle bulk actions dropdown
      function toggleBulkActionsDropdown() {
        const checkboxes = document.querySelectorAll('input[type="checkbox"].row-checkbox');
        const checkedCount = Array.from(checkboxes).filter(cb => cb.checked).length;

        if (checkedCount === 0) return;

        const menu = document.getElementById('bulk-actions-menu');
        const isHidden = menu.classList.contains('hidden');

        if (isHidden) {
          menu.classList.remove('hidden');
          setTimeout(() => {
            menu.classList.remove('scale-95', 'opacity-0');
            menu.classList.add('scale-100', 'opacity-100');
          }, 10);
        } else {
          menu.classList.remove('scale-100', 'opacity-100');
          menu.classList.add('scale-95', 'opacity-0');
          setTimeout(() => {
            menu.classList.add('hidden');
          }, 100);
        }
      }

      // Close dropdown when clicking outside
      document.addEventListener('click', function(e) {
        const dropdown = document.getElementById('bulk-actions-dropdown');
        const menu = document.getElementById('bulk-actions-menu');
        if (dropdown && menu && !dropdown.contains(e.target)) {
          menu.classList.remove('scale-100', 'opacity-100');
          menu.classList.add('scale-95', 'opacity-0');
          setTimeout(() => {
            menu.classList.add('hidden');
          }, 100);
        }
      });

      // Store current bulk action context
      // Using var instead of let to avoid redeclaration errors when HTMX re-executes script tags
      var currentBulkAction = null;
      var currentSelectedIds = [];

      // Perform bulk action
      function performBulkAction(action) {
        const selectedIds = Array.from(document.querySelectorAll('input[type="checkbox"].row-checkbox:checked'))
          .map(cb => cb.value)
          .filter(id => id);

        if (selectedIds.length === 0) {
          alert('Please select at least one item');
          return;
        }

        // Store context for confirmation
        currentBulkAction = action;
        currentSelectedIds = selectedIds;

        // Update dialog content based on action
        updateDialogContent(action, selectedIds.length);

        // Show confirmation dialog
        showConfirmDialog('bulk-action-confirm');
      }

      // Update dialog content dynamically
      function updateDialogContent(action, count) {
        const dialog = document.getElementById('bulk-action-confirm');
        const titleEl = dialog.querySelector('h3');
        const messageEl = dialog.querySelector('p');
        const confirmBtn = dialog.querySelector('.confirm-button');

        let title, message, btnText, btnClass;

        switch(action) {
          case 'delete':
            title = 'Confirm Bulk Delete';
            message = 'Are you sure you want to delete ' + count + ' selected item' + (count > 1 ? 's' : '') + '? This action cannot be undone.';
            btnText = 'Delete';
            btnClass = 'bg-red-500 hover:bg-red-400';
            break;
          case 'publish':
            title = 'Confirm Bulk Publish';
            message = 'Are you sure you want to publish ' + count + ' selected item' + (count > 1 ? 's' : '') + '? They will become publicly visible.';
            btnText = 'Publish';
            btnClass = 'bg-green-500 hover:bg-green-400';
            break;
          case 'draft':
            title = 'Confirm Bulk Draft';
            message = 'Are you sure you want to move ' + count + ' selected item' + (count > 1 ? 's' : '') + ' to draft status? They will be unpublished.';
            btnText = 'Move to Draft';
            btnClass = 'bg-blue-500 hover:bg-blue-400';
            break;
          default:
            title = 'Confirm Bulk Action';
            message = 'Are you sure you want to perform this action on ' + count + ' selected item' + (count > 1 ? 's' : '') + '?';
            btnText = 'Confirm';
            btnClass = 'bg-blue-500 hover:bg-blue-400';
        }

        titleEl.textContent = title;
        messageEl.textContent = message;
        confirmBtn.textContent = btnText;
        confirmBtn.className = confirmBtn.className.replace(/bg-\w+-\d+\s+hover:bg-\w+-\d+/, btnClass);
      }

      // Execute the bulk action after confirmation
      function executeBulkAction() {
        if (!currentBulkAction || currentSelectedIds.length === 0) return;

        // Close dropdown
        const menu = document.getElementById('bulk-actions-menu');
        menu.classList.add('hidden');

        fetch('/admin/content/bulk-action', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            action: currentBulkAction,
            ids: currentSelectedIds
          })
        })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            location.reload();
          } else {
            alert('Error: ' + (data.error || 'Unknown error'));
          }
        })
        .catch(err => {
          console.error('Bulk action error:', err);
          alert('Failed to perform bulk action');
        })
        .finally(() => {
          // Clear context
          currentBulkAction = null;
          currentSelectedIds = [];
        });
      }

      // Helper to get action text for display
      function getActionText(action) {
        const actionCount = currentSelectedIds.length;
        switch(action) {
          case 'publish':
            return \`publish \${actionCount} item\${actionCount > 1 ? 's' : ''}\`;
          case 'draft':
            return \`move \${actionCount} item\${actionCount > 1 ? 's' : ''} to draft\`;
          case 'delete':
            return \`delete \${actionCount} item\${actionCount > 1 ? 's' : ''}\`;
          default:
            return \`perform action on \${actionCount} item\${actionCount > 1 ? 's' : ''}\`;
        }
      }

    </script>

    <!-- Confirmation Dialog for Bulk Actions -->
    ${renderConfirmationDialog({
      id: 'bulk-action-confirm',
      title: 'Confirm Bulk Action',
      message: 'Are you sure you want to perform this action? This operation will affect multiple items.',
      confirmText: 'Confirm',
      cancelText: 'Cancel',
      confirmClass: 'bg-blue-500 hover:bg-blue-400',
      iconColor: 'blue',
      onConfirm: 'executeBulkAction()'
    })}

    <!-- Confirmation Dialog Script -->
    ${getConfirmationDialogScript()}

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
                    <input type="radio" name="mode" value="ai" checked class="mr-2">
                    <span class="text-sm text-zinc-950 dark:text-white">🤖 AI Search (Semantic)</span>
                  </label>
                  <label class="flex items-center">
                    <input type="radio" name="mode" value="keyword" class="mr-2">
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
                      ${data.models.map(
                        (model) => `
                          <option value="${model.name}">${model.displayName}</option>
                        `
                      ).join('')}
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
      // Using var instead of let to avoid redeclaration errors when HTMX re-executes script tags
      var autocompleteTimeout;
      var searchQueryInput = document.getElementById('searchQuery');
      if (searchQueryInput) {
        searchQueryInput.addEventListener('input', (e) => {
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
                  <div class="px-4 py-2 hover:bg-zinc-100 dark:hover:bg-zinc-700 cursor-pointer" onclick="selectSuggestion('\${s.replace(/'/g, "\\'")}')">\${s}</div>
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
      }

      function selectSuggestion(suggestion) {
        document.getElementById('searchQuery').value = suggestion;
        document.getElementById('searchSuggestions').classList.add('hidden');
      }

      // Hide suggestions when clicking outside
      document.addEventListener('click', (e) => {
        const suggestionsDiv = document.getElementById('searchSuggestions');
        if (!e.target.closest('#searchQuery') && !e.target.closest('#searchSuggestions')) {
          suggestionsDiv.classList.add('hidden');
        }
      });

      // Form submission
      var advancedSearchForm = document.getElementById('advancedSearchForm');
      if (advancedSearchForm) {
        advancedSearchForm.addEventListener('submit', async (e) => {
          e.preventDefault();
          
          const formData = new FormData(e.target);
          const query = formData.get('query');
          const mode = formData.get('mode') || 'ai';
          
          // Build filters
          const filters = {};
          
          const collections = Array.from(formData.getAll('collections')).filter(c => c !== '');
          if (collections.length > 0) {
            // Need to convert collection names to IDs - for now, pass names
            filters.collections = collections;
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
              displaySearchResults(data);
            }
          } catch (error) {
            console.error('Search error:', error);
            alert('Search failed. Please try again.');
          }
        });
      }

      function displaySearchResults(searchData) {
        const resultsDiv = document.getElementById('searchResultsContent');
        const resultsSection = document.getElementById('searchResults');
        
        if (searchData.results.length === 0) {
          resultsDiv.innerHTML = '<p class="text-sm text-zinc-500 dark:text-zinc-400">No results found.</p>';
        } else {
          resultsDiv.innerHTML = searchData.results.map(result => \`
            <div class="p-4 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800">
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <h4 class="text-sm font-semibold text-zinc-950 dark:text-white mb-1">
                    <a href="/admin/content/\${result.id}/edit" class="hover:text-indigo-600 dark:hover:text-indigo-400">\${result.title || 'Untitled'}</a>
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
    </script>
  `

  // Prepare layout data
  const layoutData: AdminLayoutCatalystData = {
    title: 'Content Management',
    pageTitle: 'Content Management',
    currentPath: '/admin/content',
    user: data.user,
    version: data.version,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
