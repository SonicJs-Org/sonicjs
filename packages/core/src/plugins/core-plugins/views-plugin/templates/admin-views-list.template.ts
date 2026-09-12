import { renderAdminLayoutCatalyst, type AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { renderTable } from '../../../../templates/components/table.template'
import { escapeHtml } from '../../../../utils/sanitize'

export interface ViewListItem {
  id: string
  name: string
  display_name: string | null
  collection_name: string | null
  filter_count: number
  page_size: number
  created_at: number
}

/**
 * A collection resolved as build-ready at list-render time. The cold-start
 * empty state branches on this set — it is the runtime collection-resolution
 * mechanism, not a static seed: a view can only target a collection that
 * actually exists and is `schema_status = 'ready'` right now, which is a
 * runtime fact (a fresh install has none; "the first ready collection" is
 * whatever the route resolves at render time).
 */
export interface ReadyCollectionOption {
  id: string
  name: string
  display_name: string
}

export interface ViewsListPageData {
  views: ViewListItem[]
  /** Build-ready collections resolved at render time; drives the empty state. */
  readyCollections: ReadyCollectionOption[]
  user?: { name: string; email: string; role: string }
  version?: string
}

/** Plus-circle glyph reused by the cold-start call-to-action buttons. */
const PLUS_ICON = `<svg class="-ml-0.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"/></svg>`

/**
 * Cold-start empty state. Branches on the runtime-resolved set of build-ready
 * collections: with at least one, the operator can create a view immediately;
 * with none, the only sensible next step is to create a collection first (a
 * view has nothing to query otherwise). This is the runtime collection
 * resolution — the route resolves "what is ready right now" at render time —
 * which is why the starter view cannot be a static seed.
 */
function renderViewsEmptyState(readyCollections: ReadyCollectionOption[]): string {
  const gridIcon = `<svg class="mx-auto h-12 w-12 text-zinc-300 dark:text-zinc-600" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25A2.25 2.25 0 0113.5 8.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" /></svg>`

  if (readyCollections.length === 0) {
    // No collection is ready, so a view would have nothing to query. The honest
    // cold-start path is "create a collection first", not "create a view".
    return `
      <div class="rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700 px-6 py-16 text-center">
        ${gridIcon}
        <h3 class="mt-4 text-base font-semibold text-zinc-950 dark:text-white">No collections to build on yet</h3>
        <p class="mx-auto mt-2 max-w-md text-sm text-zinc-500 dark:text-zinc-400">
          A view runs queries over a collection's content, so you need a collection first.
          Create one and add a few fields, then come back to build a view over it.
        </p>
        <div class="mt-6">
          <a href="/admin/collections/new"
             class="inline-flex items-center gap-x-1.5 rounded-md bg-cyan-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600">
            ${PLUS_ICON}
            Create a collection
          </a>
        </div>
      </div>
    `
  }

  // At least one ready collection: surface up to three by name so the next
  // step is concrete, then send the operator straight into the builder.
  const chips = readyCollections
    .slice(0, 3)
    .map(
      (co) =>
        `<span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-900/30 px-2 py-1 text-xs font-medium text-cyan-700 dark:text-cyan-300">${escapeHtml(co.display_name || co.name)}</span>`
    )
    .join(' ')
  const more =
    readyCollections.length > 3
      ? `<span class="text-xs text-zinc-400 dark:text-zinc-500">+${readyCollections.length - 3} more</span>`
      : ''

  return `
    <div class="rounded-lg border border-dashed border-zinc-300 dark:border-zinc-700 px-6 py-16 text-center">
      ${gridIcon}
      <h3 class="mt-4 text-base font-semibold text-zinc-950 dark:text-white">Create your first view</h3>
      <p class="mx-auto mt-2 max-w-md text-sm text-zinc-500 dark:text-zinc-400">
        A view turns a collection into a filtered, sorted REST endpoint &mdash; no code, no JSON.
        Pick one of your ready collections to start.
      </p>
      <div class="mt-4 flex flex-wrap items-center justify-center gap-2">${chips} ${more}</div>
      <div class="mt-6">
        <a href="/admin/views/new"
           class="inline-flex items-center gap-x-1.5 rounded-md bg-cyan-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600">
          ${PLUS_ICON}
          New View
        </a>
      </div>
    </div>
  `
}

export function renderViewsListPage(data: ViewsListPageData): string {
  const tableData = {
    tableId: 'views-table',
    rowClickable: true,
    rowClickUrl: (view: ViewListItem) => `/admin/views/${view.id}`,
    columns: [
      {
        key: 'name',
        label: 'Name',
        sortable: true,
        render: (_: unknown, view: ViewListItem) => `
          <div>
            <span class="font-medium text-zinc-950 dark:text-white">${escapeHtml(view.display_name || view.name)}</span>
            <span class="ml-2 text-xs text-zinc-400 dark:text-zinc-500 font-mono">${escapeHtml(view.name)}</span>
          </div>
        `,
      },
      {
        key: 'collection_name',
        label: 'Collection',
        sortable: true,
        render: (val: string | null) =>
          val
            ? `<span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-900/30 px-2 py-1 text-xs font-medium text-cyan-700 dark:text-cyan-300">${escapeHtml(val)}</span>`
            : '<span class="text-zinc-400 text-xs">Not assigned</span>',
      },
      {
        key: 'filter_count',
        label: 'Filters',
        sortable: true,
        sortType: 'number' as const,
        render: (val: number) =>
          val > 0
            ? `<span class="text-xs">${val} rule${val !== 1 ? 's' : ''}</span>`
            : '<span class="text-zinc-400 text-xs">None</span>',
      },
      {
        key: 'page_size',
        label: 'Page Size',
        sortable: true,
        sortType: 'number' as const,
      },
      {
        key: 'created_at',
        label: 'Created',
        sortable: true,
        sortType: 'date' as const,
        render: (val: number) => {
          const d = new Date(val)
          return `<span class="text-xs text-zinc-500">${d.toLocaleDateString()}</span>`
        },
      },
      {
        key: 'actions',
        label: '',
        sortable: false,
        render: (_: unknown, view: ViewListItem) => `
          <a href="/admin/views/${encodeURIComponent(view.id)}/display"
             class="text-xs text-cyan-600 dark:text-cyan-400 hover:underline"
             onclick="event.stopPropagation()">
            Open
          </a>
          <a href="/api/views/${encodeURIComponent(view.name)}" target="_blank"
             class="ml-3 text-xs text-cyan-600 dark:text-cyan-400 hover:underline"
             onclick="event.stopPropagation()">
            API
          </a>
        `,
      },
    ],
    rows: data.views,
    emptyMessage: 'No views yet. Create one to build a no-code API endpoint.',
  }

  const content = `
    <div class="mx-auto max-w-7xl">
      <!-- Header -->
      <div class="sm:flex sm:items-center sm:justify-between mb-8">
        <div>
          <h1 class="text-2xl font-bold text-zinc-950 dark:text-white">Views</h1>
          <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
            No-code API endpoints. Define filters, sort, and columns &mdash; get a live REST endpoint.
          </p>
        </div>
        <div class="mt-4 sm:mt-0">
          <a href="/admin/views/new"
             class="inline-flex items-center gap-x-1.5 rounded-md bg-cyan-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-cyan-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600">
            <svg class="-ml-0.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z"/>
            </svg>
            New View
          </a>
        </div>
      </div>

      ${
        data.views.length === 0
          ? renderViewsEmptyState(data.readyCollections)
          : `
      <!-- Count -->
      <div class="mb-4 text-sm text-zinc-500 dark:text-zinc-400">
        ${data.views.length} view${data.views.length !== 1 ? 's' : ''}
      </div>

      <!-- Table -->
      ${renderTable(tableData)}
      `
      }
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Views',
    currentPath: '/admin/views',
    user: data.user,
    version: data.version,
    content,
  }

  return renderAdminLayoutCatalyst(layoutData)
}
