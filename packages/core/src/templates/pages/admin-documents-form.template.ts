import { renderAdminLayoutCatalyst } from '../layouts/admin-layout-catalyst.template'
import { renderAlert } from '../components/alert.template'
import { escapeHtml } from '../../utils/sanitize'
import type { Document, DocumentType, QueryableField } from '../../schemas/document'

export interface DocumentFormData {
  docType: DocumentType
  doc?: Document
  publishedDoc?: Document | null  // Published revision when different from current draft
  isEdit: boolean
  errors?: Record<string, string>
  message?: string
  messageType?: 'success' | 'error' | 'warning' | 'info'
  user?: { name: string; email: string; role: string }
  version?: string
}

function inputClass(error?: string): string {
  const base = 'block w-full rounded-lg border bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white placeholder:text-zinc-400 focus:outline-none focus:ring-2 focus:ring-blue-500 transition-colors'
  return error
    ? `${base} border-red-400 dark:border-red-500`
    : `${base} border-zinc-300 dark:border-zinc-700`
}

function renderFieldInput(field: QueryableField, value: unknown, error?: string): string {
  const id = `data_${field.name}`
  const name = `data[${field.name}]`
  const label = field.name.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase())
  const strVal = value != null ? String(value) : ''

  let input: string
  if (field.type === 'integer' || field.type === 'number') {
    input = `<input type="number" id="${id}" name="${name}" value="${escapeHtml(strVal)}"
              step="${field.type === 'integer' ? '1' : 'any'}"
              class="${inputClass(error)}">`
  } else if (field.type === 'boolean') {
    // Hidden 'false' before the checkbox: an unchecked checkbox submits nothing, so without this a
    // boolean could never be set back to false (D15). When checked, the checkbox value wins.
    input = `<div class="flex items-center gap-2">
               <input type="hidden" name="${name}" value="false">
               <input type="checkbox" id="${id}" name="${name}" value="true" ${strVal === 'true' ? 'checked' : ''}
                 class="h-4 w-4 rounded border-zinc-300 dark:border-zinc-600 text-blue-600 focus:ring-blue-500">
               <span class="text-sm text-zinc-700 dark:text-zinc-300">${label}</span>
             </div>`
    return `
      <div>
        ${input}
        ${error ? `<p class="mt-1 text-xs text-red-500">${escapeHtml(error)}</p>` : ''}
      </div>`
  } else if (field.kind === 'facet') {
    // Multi-value: comma-separated list
    const arrVal = Array.isArray(value) ? (value as string[]).join(', ') : strVal
    input = `<input type="text" id="${id}" name="${name}" value="${escapeHtml(arrVal)}"
              placeholder="Comma-separated values"
              class="${inputClass(error)}">`
  } else {
    input = `<input type="text" id="${id}" name="${name}" value="${escapeHtml(strVal)}"
              class="${inputClass(error)}">`
  }

  return `
    <div>
      <label for="${id}" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">
        ${label}
      </label>
      ${input}
      ${error ? `<p class="mt-1 text-xs text-red-500">${escapeHtml(error)}</p>` : ''}
    </div>`
}

function renderRemainingFields(
  allData: Record<string, unknown>,
  queryableFields: QueryableField[],
  errors: Record<string, string>,
): string {
  const knownNames = new Set(queryableFields.map(f => f.name))
  const remainingKeys = Object.keys(allData).filter(k => !knownNames.has(k))
  if (remainingKeys.length === 0) return ''

  const inputs = remainingKeys.map(key => {
    const val = allData[key]
    const id = `data_${key}`
    const name = `data[${key}]`
    const label = key.replace(/([A-Z])/g, ' $1').replace(/^./, s => s.toUpperCase())
    const strVal = typeof val === 'object' ? JSON.stringify(val, null, 2) : String(val ?? '')
    const isMultiline = strVal.includes('\n') || strVal.length > 100

    return `
      <div>
        <label for="${id}" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">${escapeHtml(label)}</label>
        ${isMultiline
          ? `<textarea id="${id}" name="${name}" rows="4" class="${inputClass(errors[key])}">${escapeHtml(strVal)}</textarea>`
          : `<input type="text" id="${id}" name="${name}" value="${escapeHtml(strVal)}" class="${inputClass(errors[key])}">`
        }
        ${errors[key] ? `<p class="mt-1 text-xs text-red-500">${escapeHtml(errors[key])}</p>` : ''}
      </div>`
  }).join('')

  return `
    <div class="border-t border-zinc-200 dark:border-zinc-700 pt-6">
      <h3 class="text-sm font-medium text-zinc-500 dark:text-zinc-400 mb-4">Additional Fields</h3>
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">${inputs}</div>
    </div>`
}

export function renderDocumentFormPage(data: DocumentFormData): string {
  const { docType, doc, publishedDoc, isEdit, errors = {} } = data
  const queryableFields = docType.queryableFields ?? []
  const docData = (doc?.data ?? {}) as Record<string, unknown>

  const isAdmin = data.user?.role === 'admin'
  const isEditor = isAdmin || data.user?.role === 'editor'

  const hasNewerDraft = isEdit && doc && !doc.isPublished && publishedDoc
  const isPublishedAndDraft = isEdit && doc?.isPublished && doc?.isCurrentDraft

  // Real document CRUD lives under /admin/content/documents/:typeId/... (admin-content.ts), NOT
  // /admin/documents/ui (those are GET redirects only). Edit/save POSTs to :rootId; create to /new.
  const formAction = isEdit
    ? `/admin/content/documents/${escapeHtml(docType.id)}/${escapeHtml(doc!.rootId)}`
    : `/admin/content/documents/${escapeHtml(docType.id)}/new`

  const publishBannerHtml = (() => {
    if (!isEdit || !doc) return ''
    if (isPublishedAndDraft) {
      return renderAlert({
        type: 'success',
        message: 'This document is live. Saving creates a new draft. Use "Publish" to push changes live.',
      })
    }
    if (hasNewerDraft) {
      return renderAlert({
        type: 'info',
        message: `A published version (v${publishedDoc!.versionNumber}) is still live. This is an unpublished draft (v${doc.versionNumber}).`,
      })
    }
    return ''
  })()

  // Reference-kind fields are intentionally not rendered yet (D27) — fine for FAQ/testimonial, which
  // have none. When media references land (Phase 6), render a root-id picker here.
  const queryableInputs = queryableFields
    .filter(f => f.kind !== 'reference')
    .map(f => renderFieldInput(f, docData[f.name], errors[`data.${f.name}`]))
    .join('')

  const remainingHtml = renderRemainingFields(docData, queryableFields, errors)

  const content = `
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6 space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div class="flex items-center gap-2 text-sm text-zinc-500 dark:text-zinc-400 mb-1">
            <a href="/admin/content" class="hover:text-zinc-950 dark:hover:text-white">Content</a>
            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.22 5.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L11.94 10 8.22 6.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd"/></svg>
            <a href="/admin/content?model=doc:${escapeHtml(docType.id)}" class="hover:text-zinc-950 dark:hover:text-white">${escapeHtml(docType.displayName)}</a>
            <svg class="h-4 w-4" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M8.22 5.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L11.94 10 8.22 6.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd"/></svg>
            <span class="text-zinc-950 dark:text-white font-medium">${isEdit ? 'Edit' : 'New'}</span>
          </div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">
            ${isEdit ? `Edit ${escapeHtml(docType.displayName)}` : `New ${escapeHtml(docType.displayName)}`}
          </h1>
          ${isEdit && doc ? `<p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">v${doc.versionNumber} · root: <code class="font-mono">${escapeHtml(doc.rootId)}</code></p>` : ''}
        </div>

        <!-- Publish controls (edit mode only) -->
        ${isEdit && doc && isEditor ? `
        <div class="mt-4 sm:mt-0 flex gap-2">
          ${!doc.isPublished ? `
          <form method="POST" action="/admin/content/documents/${escapeHtml(docType.id)}/${escapeHtml(doc.id)}/publish">
            <button type="submit"
              class="inline-flex items-center rounded-lg bg-green-600 px-3.5 py-2.5 text-sm font-semibold text-white hover:bg-green-500 transition-colors shadow-sm">
              Publish
            </button>
          </form>` : `
          <form method="POST" action="/admin/content/documents/${escapeHtml(docType.id)}/${escapeHtml(doc.id)}/unpublish">
            <button type="submit"
              class="inline-flex items-center rounded-lg bg-amber-500 px-3.5 py-2.5 text-sm font-semibold text-white hover:bg-amber-400 transition-colors shadow-sm">
              Unpublish
            </button>
          </form>`}
        </div>` : ''}
      </div>

      ${publishBannerHtml}
      ${data.message ? renderAlert({ type: data.messageType ?? 'info', message: data.message, dismissible: true }) : ''}

      <!-- Form -->
      <form method="POST" action="${formAction}">
        ${isEdit ? `<input type="hidden" name="_method" value="PUT">` : ''}

        <div class="relative rounded-xl">
          <div class="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-purple-500/5 dark:from-blue-400/10 dark:to-purple-400/10 rounded-xl"></div>
          <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 rounded-xl p-6 space-y-6">

            <!-- Standard fields -->
            <div>
              <h3 class="text-sm font-semibold text-zinc-700 dark:text-zinc-200 mb-4">Document</h3>
              <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label for="title" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Title</label>
                  <input type="text" id="title" name="title" value="${escapeHtml(doc?.title ?? '')}"
                    class="${inputClass(errors.title)}">
                  ${errors.title ? `<p class="mt-1 text-xs text-red-500">${escapeHtml(errors.title)}</p>` : ''}
                </div>
                <div>
                  <label for="slug" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Slug</label>
                  <input type="text" id="slug" name="slug" value="${escapeHtml(doc?.slug ?? '')}"
                    placeholder="auto-generated-if-empty"
                    class="${inputClass(errors.slug)}">
                  ${errors.slug ? `<p class="mt-1 text-xs text-red-500">${escapeHtml(errors.slug)}</p>` : ''}
                </div>
              </div>
            </div>

            <!-- Queryable data fields -->
            ${queryableFields.length > 0 ? `
            <div class="border-t border-zinc-200 dark:border-zinc-700 pt-6">
              <h3 class="text-sm font-semibold text-zinc-700 dark:text-zinc-200 mb-4">Content</h3>
              <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                ${queryableInputs}
              </div>
            </div>` : ''}

            <!-- Remaining data fields not in queryable fields -->
            ${remainingHtml}

            <!-- Actions -->
            <div class="border-t border-zinc-200 dark:border-zinc-700 pt-6 flex items-center justify-between">
              <a href="/admin/content?model=doc:${escapeHtml(docType.id)}"
                class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-700 dark:text-zinc-200 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                Cancel
              </a>
              <div class="flex gap-3">
                <button type="submit"
                  class="inline-flex items-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
                  ${isEdit ? 'Save Draft' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </form>

      <!-- Version history (edit mode) -->
      ${isEdit && doc ? `
      <details class="group">
        <summary class="cursor-pointer text-sm text-zinc-500 dark:text-zinc-400 hover:text-zinc-950 dark:hover:text-white flex items-center gap-2 py-2">
          <svg class="h-4 w-4 transition-transform group-open:rotate-90" viewBox="0 0 20 20" fill="currentColor">
            <path fill-rule="evenodd" d="M8.22 5.22a.75.75 0 0 1 1.06 0l4.25 4.25a.75.75 0 0 1 0 1.06l-4.25 4.25a.75.75 0 0 1-1.06-1.06L11.94 10 8.22 6.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd"/>
          </svg>
          Version history
        </summary>
        <div class="mt-3 rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
          <div id="version-history-placeholder" class="px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400"
               hx-get="/admin/content/documents/${escapeHtml(docType.id)}/${escapeHtml(doc.rootId)}/versions"
               hx-trigger="revealed"
               hx-swap="outerHTML">
            Loading version history…
          </div>
        </div>
      </details>` : ''}
    </div>
  `

  return renderAdminLayoutCatalyst({
    title: `${isEdit ? 'Edit' : 'New'} ${docType.displayName} — Documents`,
    currentPath: '/admin/content',
    user: data.user,
    version: data.version,
    content,
  })
}

// ─── Version history fragment (HTMX target) ──────────────────────────────────

export interface VersionHistoryData {
  versions: Array<{
    id: string
    versionNumber: number
    isCurrentDraft: boolean
    isPublished: boolean
    status: string
    updatedAt: number
    createdBy: string | null
  }>
  docType: DocumentType
  rootId: string
}

export function renderVersionHistoryFragment(data: VersionHistoryData): string {
  if (data.versions.length === 0) {
    return `<div class="px-6 py-4 text-sm text-zinc-500 dark:text-zinc-400">No versions found.</div>`
  }

  const rows = data.versions.map(v => `
    <div class="flex items-center justify-between px-6 py-3 border-b border-zinc-100 dark:border-zinc-800 last:border-0">
      <div class="flex items-center gap-3">
        <span class="text-sm font-medium text-zinc-950 dark:text-white">v${v.versionNumber}</span>
        ${v.isPublished ? `<span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-1.5 py-0.5 text-xs font-medium text-green-700 dark:text-green-400">live</span>` : ''}
        ${v.isCurrentDraft ? `<span class="inline-flex items-center rounded-md bg-blue-50 dark:bg-blue-500/10 px-1.5 py-0.5 text-xs font-medium text-blue-700 dark:text-blue-400">draft</span>` : ''}
      </div>
      <div class="flex items-center gap-4 text-xs text-zinc-500 dark:text-zinc-400">
        <span>${v.createdBy ?? '—'}</span>
        <span>${new Date(v.updatedAt * 1000).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' })}</span>
      </div>
    </div>
  `).join('')

  return `<div>${rows}</div>`
}
