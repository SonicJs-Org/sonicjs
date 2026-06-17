import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderTable } from '../components/table.template'

export interface Collection {
  id: string
  name: string
  display_name: string
  description?: string
  created_at: number
  formattedDate: string
  field_count?: number
  managed?: boolean
  source_type?: string | null
  internal?: boolean
  versioning?: boolean
}

export interface CollectionsListPageData {
  collections: Collection[]
  search?: string
  showInternal?: boolean
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderCollectionsListPage(data: CollectionsListPageData): string {
  const showInternal = data.showInternal ?? false
  const tableData: any = {
    tableId: 'collections-table',
    rowClickable: true,
    rowClickUrl: (collection: Collection) => `/admin/collections/${collection.id}`,
    columns: [
      {
        key: 'name',
        label: 'Name',
        sortable: true,
        sortType: 'string',
        render: (_value: any, collection: any) => `
            <div class="flex items-center gap-2 ml-2">
                <span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-500/10 px-2.5 py-1 text-sm font-medium text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-400/20">
                  ${collection.name}
                </span>
                ${collection.managed ? `
                  <span class="inline-flex items-center rounded-md bg-purple-50 dark:bg-purple-500/10 px-2 py-0.5 text-xs font-medium text-purple-700 dark:text-purple-300 ring-1 ring-inset ring-purple-700/10 dark:ring-purple-400/20" title="Config-managed collection (read-only in UI)">
                    <svg class="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                      <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/>
                    </svg>
                    Config
                  </span>
                ` : ''}
                ${collection.internal ? `
                  <span class="inline-flex items-center rounded-md bg-zinc-100 dark:bg-zinc-700/50 px-2 py-0.5 text-xs font-medium text-zinc-500 dark:text-zinc-400 ring-1 ring-inset ring-zinc-300/50 dark:ring-zinc-600/50" title="Internal system collection">
                    Internal
                  </span>
                ` : ''}
            </div>
          `
      },
      {
        key: 'display_name',
        label: 'Display Name',
        sortable: true,
        sortType: 'string'
      },
      {
        key: 'description',
        label: 'Description',
        sortable: true,
        sortType: 'string',
        render: (_value: any, collection: any) => collection.description || '<span class="text-zinc-500 dark:text-zinc-400">-</span>'
      },
      {
        key: 'field_count',
        label: 'Fields',
        sortable: true,
        sortType: 'number',
        render: (_value: any, collection: any) => {
          const count = collection.field_count || 0
          return `
            <div class="flex items-center">
              <span class="inline-flex items-center rounded-md bg-pink-50 dark:bg-pink-500/10 px-2.5 py-1 text-sm font-medium text-pink-700 dark:text-pink-300 ring-1 ring-inset ring-pink-700/10 dark:ring-pink-400/20">
                ${count} ${count === 1 ? 'field' : 'fields'}
              </span>
            </div>
          `
        }
      },
      {
        key: 'versioning',
        label: 'Versioning',
        sortable: true,
        sortType: 'string',
        render: (_value: any, collection: any) => {
          if (collection.versioning) {
            return `<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20">On</span>`
          }
          return `<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium bg-zinc-50 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-400 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20">Off</span>`
        }
      },
      {
        key: 'actions',
        label: 'Content',
        sortable: false,
        render: (_value: any, collection: any) => {
          if (!collection || !collection.id) return '<span class="text-zinc-500 dark:text-zinc-400">-</span>'
          return `
            <div class="flex items-center space-x-2">
              <a href="/admin/content?model=${collection.name}" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-lg bg-zinc-950 dark:bg-white text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                </svg>
              </a>
            </div>
          `
        }
      }
    ],
    rows: data.collections,
    emptyMessage: 'No collections found.'
  }

  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Collections</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage your content collections and their schemas</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="/admin/collections/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            New Collection
          </a>
        </div>
      </div>

      <!-- Filters -->
      <div class="relative rounded-xl overflow-hidden mb-6">
        <!-- Gradient Background -->
        <div class="absolute inset-0 bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 dark:from-cyan-400/20 dark:via-blue-400/20 dark:to-purple-400/20"></div>

        <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
          <div class="px-6 py-5">
            <div class="flex items-center justify-between">
              <div class="flex items-center space-x-4">
                <form onsubmit="performSearch(event)" class="flex items-center space-x-2">
                  <div class="relative group">
                    <input
                      id="collections-search"
                      type="text"
                      placeholder="Search collections..."
                      value="${data.search || ''}"
                      oninput="toggleClearButton()"
                      class="rounded-full bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm px-4 py-2.5 pl-11 pr-10 text-sm w-72 text-zinc-950 dark:text-white border-2 border-cyan-200/50 dark:border-cyan-700/50 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400 focus:bg-white dark:focus:bg-zinc-800 focus:shadow-lg focus:shadow-cyan-500/20 dark:focus:shadow-cyan-400/20 transition-all duration-300"
                    >
                    <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 dark:from-cyan-300 dark:to-blue-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                      <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                      </svg>
                    </div>
                    <button
                      type="button"
                      id="clear-search"
                      onclick="clearSearch()"
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
                  function performSearch(event) {
                    event.preventDefault();
                    const searchInput = document.getElementById('collections-search');
                    const value = searchInput.value.trim();
                    const params = new URLSearchParams(window.location.search);
                    if (value) {
                      params.set('search', value);
                    } else {
                      params.delete('search');
                    }
                    window.location.href = window.location.pathname + '?' + params.toString();
                  }

                  function clearSearch() {
                    const params = new URLSearchParams(window.location.search);
                    params.delete('search');
                    window.location.href = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
                  }

                  function toggleClearButton() {
                    const searchInput = document.getElementById('collections-search');
                    const clearButton = document.getElementById('clear-search');
                    if (searchInput.value.trim()) {
                      clearButton.classList.remove('hidden');
                    } else {
                      clearButton.classList.add('hidden');
                    }
                  }

                  function toggleInternalCollections(checked) {
                    const params = new URLSearchParams(window.location.search);
                    if (checked) {
                      params.set('showInternal', '1');
                    } else {
                      params.delete('showInternal');
                    }
                    window.location.href = window.location.pathname + (params.toString() ? '?' + params.toString() : '');
                  }
                </script>
              </div>
              <div class="flex items-center gap-x-3">
                <span class="text-sm/6 font-medium text-zinc-700 dark:text-zinc-300 px-3 py-1.5 rounded-full bg-white/60 dark:bg-zinc-800/60 backdrop-blur-sm">${data.collections.length} ${data.collections.length === 1 ? 'collection' : 'collections'}</span>
                <label class="inline-flex items-center gap-x-2 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-zinc-200/50 dark:ring-zinc-700/50 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-700/50 transition-all duration-200" title="Show internal system collections">
                  <input
                    type="checkbox"
                    id="show-internal"
                    ${showInternal ? 'checked' : ''}
                    onchange="toggleInternalCollections(this.checked)"
                    class="h-4 w-4 rounded border-zinc-300 dark:border-zinc-600 text-cyan-600 focus:ring-cyan-500 cursor-pointer"
                  >
                  <span>Show internal</span>
                </label>
                <button
                  class="inline-flex items-center gap-x-1.5 px-3 py-1.5 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-cyan-200/50 dark:ring-cyan-700/50 hover:bg-gradient-to-r hover:from-cyan-50 hover:to-blue-50 dark:hover:from-cyan-900/30 dark:hover:to-blue-900/30 hover:ring-cyan-300 dark:hover:ring-cyan-600 transition-all duration-200"
                  onclick="location.reload()"
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

      <!-- Collections List -->
      <div id="collections-list">
        ${renderTable(tableData)}
      </div>

      <!-- Empty State -->
      ${data.collections.length === 0 ? `
        <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-12 text-center">
          <svg class="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
          </svg>
          <h3 class="mt-4 text-base/7 font-semibold text-zinc-950 dark:text-white">No collections found</h3>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Get started by creating your first collection</p>
          <div class="mt-6">
            <a href="/admin/collections/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
              <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
              </svg>
              New Collection
            </a>
          </div>
        </div>
      ` : ''}
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Collections',
    pageTitle: 'Collections',
    currentPath: '/admin/collections',
    user: data.user,
    version: data.version,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
