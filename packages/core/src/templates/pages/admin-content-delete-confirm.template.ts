import { escapeHtml } from '../../utils/sanitize'
import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'

export interface ContentDeleteConfirmData {
  id: string
  title: string
  slug?: string
  collectionName: string
  collectionDisplayName: string
  status: string
  createdAt?: number
  updatedAt?: number
  publishedAt?: number
  authorName?: string
  referrerParams?: string
  /** Overrides the default edit-page Cancel link, e.g. to return to the originating list. */
  cancelUrl?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

function formatDate(timestamp?: number): string {
  if (!timestamp) return 'N/A'
  const date = new Date(timestamp * 1000)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

function getStatusBadge(status: string): string {
  const badges: Record<string, string> = {
    published: 'bg-lime-500/10 text-lime-400 ring-lime-500/20',
    draft: 'bg-zinc-500/10 text-zinc-400 ring-zinc-500/20',
    archived: 'bg-amber-500/10 text-amber-400 ring-amber-500/20',
  }
  const badgeClass = badges[status] || badges.draft
  return `<span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${badgeClass}">${escapeHtml(status)}</span>`
}

export function renderContentDeleteConfirmPage(data: ContentDeleteConfirmData): string {
  const backUrl = data.cancelUrl ?? (data.referrerParams
    ? `/admin/content/${data.id}/edit?ref=${encodeURIComponent(data.referrerParams)}`
    : `/admin/content/${data.id}/edit`)

  const content = `
    <div class="mx-auto max-w-2xl px-4 py-8 sm:px-6 lg:px-8">
      <div class="rounded-xl bg-zinc-900 ring-1 ring-white/10 shadow-lg overflow-hidden">
        <!-- Header -->
        <div class="bg-red-500/10 border-b border-red-500/20 px-6 py-5">
          <div class="flex items-center gap-4">
            <div class="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-red-500/20">
              <svg class="h-6 w-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/>
              </svg>
            </div>
            <div>
              <h1 class="text-xl font-semibold text-white">Delete Content</h1>
              <p class="mt-1 text-sm text-zinc-400">Review before permanently removing this content</p>
            </div>
          </div>
        </div>

        <!-- Content Details -->
        <div class="px-6 py-6 space-y-6">
          <!-- Warning -->
          <div class="rounded-lg bg-red-500/5 border border-red-500/20 p-4">
            <div class="flex gap-3">
              <svg class="h-5 w-5 text-red-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"/>
              </svg>
              <div>
                <h3 class="text-sm font-medium text-red-400">Warning</h3>
                <p class="mt-1 text-sm text-zinc-400">This content will be removed from the site and hidden from all lists. It will no longer be publicly accessible.</p>
              </div>
            </div>
          </div>

          <!-- Content Info Card -->
          <div class="rounded-lg bg-zinc-800/50 ring-1 ring-white/5 overflow-hidden">
            <dl class="divide-y divide-white/5">
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Title</dt>
                <dd class="mt-1 text-sm text-white sm:col-span-2 sm:mt-0 font-medium">${escapeHtml(data.title || 'Untitled')}</dd>
              </div>
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Collection</dt>
                <dd class="mt-1 text-sm text-white sm:col-span-2 sm:mt-0">${escapeHtml(data.collectionDisplayName)}</dd>
              </div>
              ${data.slug ? `
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Slug</dt>
                <dd class="mt-1 text-sm text-zinc-300 sm:col-span-2 sm:mt-0 font-mono text-xs">${escapeHtml(data.slug)}</dd>
              </div>
              ` : ''}
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Status</dt>
                <dd class="mt-1 text-sm sm:col-span-2 sm:mt-0">${getStatusBadge(data.status)}</dd>
              </div>
              ${data.authorName ? `
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Author</dt>
                <dd class="mt-1 text-sm text-zinc-300 sm:col-span-2 sm:mt-0">${escapeHtml(data.authorName)}</dd>
              </div>
              ` : ''}
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Created</dt>
                <dd class="mt-1 text-sm text-zinc-300 sm:col-span-2 sm:mt-0">${formatDate(data.createdAt)}</dd>
              </div>
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Last Updated</dt>
                <dd class="mt-1 text-sm text-zinc-300 sm:col-span-2 sm:mt-0">${formatDate(data.updatedAt)}</dd>
              </div>
              ${data.publishedAt ? `
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">Published</dt>
                <dd class="mt-1 text-sm text-zinc-300 sm:col-span-2 sm:mt-0">${formatDate(data.publishedAt)}</dd>
              </div>
              ` : ''}
              <div class="px-4 py-4 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-6">
                <dt class="text-sm font-medium text-zinc-400">ID</dt>
                <dd class="mt-1 text-sm text-zinc-500 sm:col-span-2 sm:mt-0 font-mono text-xs">${escapeHtml(data.id)}</dd>
              </div>
            </dl>
          </div>
        </div>

        <!-- Actions -->
        <div class="bg-zinc-800/30 border-t border-white/5 px-6 py-4 flex items-center justify-between gap-4">
          <a
            href="${escapeHtml(backUrl)}"
            class="inline-flex items-center gap-2 rounded-lg bg-zinc-800 px-4 py-2.5 text-sm font-semibold text-white ring-1 ring-inset ring-white/10 hover:bg-zinc-700 transition-colors"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18"/>
            </svg>
            Cancel
          </a>

          <form method="POST" action="/admin/content/${data.id}/delete">
            <input type="hidden" name="collection" value="${escapeHtml(data.collectionName)}">
            ${data.referrerParams ? `<input type="hidden" name="referrer" value="${escapeHtml(data.referrerParams)}">` : ''}
            <button
              type="submit"
              class="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-red-500 transition-colors shadow-sm"
            >
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/>
              </svg>
              Delete Content
            </button>
          </form>
        </div>
      </div>
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: `Delete: ${escapeHtml(data.title || 'Content')}`,
    pageTitle: 'Delete Content',
    currentPath: '/admin/content',
    version: data.version,
    user: data.user,
    content
  }

  return renderAdminLayoutCatalyst(layoutData)
}
