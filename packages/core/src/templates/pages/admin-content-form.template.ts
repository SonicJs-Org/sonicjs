import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderAlert } from '../alert.template'
import { renderDynamicField, renderFieldGroup, FieldDefinition } from '../components/dynamic-field.template'
import { renderConfirmationDialog, getConfirmationDialogScript } from '../confirmation-dialog.template'
import { getTinyMCEScript, getTinyMCEInitScript } from '../../plugins/available/tinymce-plugin'
import { getQuillCDN, getQuillInitScript } from '../../plugins/core-plugins/quill-editor'
import { getMDXEditorScripts, getMDXEditorInitScript } from '../../plugins/available/easy-mdx'

export interface Collection {
  id: string
  name: string
  display_name: string
  description?: string
  schema: any
}

export interface ContentFormData {
  id?: string
  title?: string
  slug?: string
  data?: any
  status?: string
  scheduled_publish_at?: number
  scheduled_unpublish_at?: number
  review_status?: string
  meta_title?: string
  meta_description?: string
  collection: Collection
  fields: FieldDefinition[]
  isEdit?: boolean
  error?: string
  success?: string
  validationErrors?: Record<string, string[]>
  workflowEnabled?: boolean // New flag to indicate if workflow plugin is active
  tinymceEnabled?: boolean // Flag to indicate if TinyMCE plugin is active
  tinymceSettings?: {
    apiKey?: string
    defaultHeight?: number
    defaultToolbar?: string
    skin?: string
  }
  quillEnabled?: boolean // Flag to indicate if Quill plugin is active
  quillSettings?: {
    version?: string
    defaultHeight?: number
    defaultToolbar?: string
    theme?: string
  }
  mdxeditorEnabled?: boolean // Flag to indicate if MDXEditor plugin is active
  mdxeditorSettings?: {
    defaultHeight?: number
    theme?: string
    toolbar?: string
    placeholder?: string
  }
  referrerParams?: string // URL parameters to preserve filters when returning to list
  collectionSourceType?: string // 'user' or 'form'
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderContentFormPage(data: ContentFormData): string {
  const isEdit = data.isEdit || !!data.id
  const title = isEdit ? `Edit: ${data.title || 'Content'}` : `New ${data.collection.display_name}`

  // Construct back URL with preserved filters
  const backUrl = data.referrerParams
    ? `/admin/content?${data.referrerParams}`
    : `/admin/content?collection=${data.collection.id}`

  // Group fields by category
  const coreFields = data.fields.filter(f => ['title', 'slug', 'content'].includes(f.field_name))
  const contentFields = data.fields.filter(f => !['title', 'slug', 'content'].includes(f.field_name) && !f.field_name.startsWith('meta_'))
  const metaFields = data.fields.filter(f => f.field_name.startsWith('meta_'))
  
  // Helper function to get field value - title and slug are stored as columns, others in data JSON
  const getFieldValue = (fieldName: string) => {
    if (fieldName === 'title') return data.title || data.data?.[fieldName] || ''
    if (fieldName === 'slug') return data.slug || data.data?.[fieldName] || ''
    return data.data?.[fieldName] || ''
  }

  // Prepare plugin statuses for field rendering
  const pluginStatuses = {
    quillEnabled: data.quillEnabled || false,
    mdxeditorEnabled: data.mdxeditorEnabled || false,
    tinymceEnabled: data.tinymceEnabled || false
  }

  // Render field groups
  const coreFieldsHTML = coreFields
    .sort((a, b) => a.field_order - b.field_order)
    .map(field => renderDynamicField(field, {
      value: getFieldValue(field.field_name),
      errors: data.validationErrors?.[field.field_name] || [],
      pluginStatuses,
      collectionId: data.collection.id,
      contentId: data.id // Pass content ID when editing
    }))

  const contentFieldsHTML = contentFields
    .sort((a, b) => a.field_order - b.field_order)
    .map(field => renderDynamicField(field, {
      value: getFieldValue(field.field_name),
      errors: data.validationErrors?.[field.field_name] || [],
      pluginStatuses,
      collectionId: data.collection.id,
      contentId: data.id
    }))

  const metaFieldsHTML = metaFields
    .sort((a, b) => a.field_order - b.field_order)
    .map(field => renderDynamicField(field, {
      value: getFieldValue(field.field_name),
      errors: data.validationErrors?.[field.field_name] || [],
      pluginStatuses,
      collectionId: data.collection.id,
      contentId: data.id
    }))

  const pageContent = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">${isEdit ? 'Edit Content' : 'New Content'}</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            ${data.collection.description || `Manage ${data.collection.display_name.toLowerCase()} content`}
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none">
          <a href="${backUrl}" class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back to Content
          </a>
        </div>
      </div>

      <!-- Form Container -->
      <div class="rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
        <!-- Form Header -->
        <div class="border-b border-zinc-950/5 dark:border-white/10 px-6 py-6">
          <div class="flex items-center gap-x-3">
            <div class="flex h-12 w-12 items-center justify-center rounded-lg bg-zinc-50 dark:bg-zinc-800 ring-1 ring-zinc-950/10 dark:ring-white/10">
              <svg class="h-6 w-6 text-zinc-950 dark:text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"/>
              </svg>
            </div>
            <div>
              <h2 class="text-base/7 font-semibold text-zinc-950 dark:text-white">${data.collection.display_name}</h2>
              <p class="text-sm/6 text-zinc-500 dark:text-zinc-400">${isEdit ? 'Update your content' : 'Create new content'}</p>
            </div>
          </div>
        </div>

        <!-- Form Content -->
        <div class="px-6 py-6">
          <div id="form-messages">
            ${data.error ? renderAlert({ type: 'error', message: data.error, dismissible: true }) : ''}
            ${data.success ? renderAlert({ type: 'success', message: data.success, dismissible: true }) : ''}
          </div>

          <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Main Content Form -->
        <div class="lg:col-span-2">
          <form
            id="content-form"
            ${isEdit ? `hx-put="/admin/content/${data.id}"` : `hx-post="/admin/content"`}
            hx-target="#form-messages"
            hx-encoding="multipart/form-data"
            class="space-y-6"
          >
            <input type="hidden" name="collection_id" value="${data.collection.id}">
            ${isEdit ? `<input type="hidden" name="id" value="${data.id}">` : ''}
            ${data.referrerParams ? `<input type="hidden" name="referrer_params" value="${data.referrerParams}">` : ''}
            
            <!-- Core Fields -->
            ${renderFieldGroup('Basic Information', coreFieldsHTML)}
            
            <!-- Content Fields -->
            ${contentFields.length > 0 ? renderFieldGroup('Content Details', contentFieldsHTML) : ''}
            
            <!-- SEO & Meta Fields -->
            ${metaFields.length > 0 ? renderFieldGroup('SEO & Metadata', metaFieldsHTML, true) : ''}
            
            <div id="form-messages"></div>
          </form>
        </div>

        <!-- Sidebar -->
        <div class="lg:col-span-1 space-y-6">
          <!-- Publishing Options -->
          <div class="rounded-lg bg-zinc-50 dark:bg-zinc-800/50 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white mb-4">Publishing</h3>

            ${data.workflowEnabled ? `
              <!-- Workflow Status (when workflow plugin is enabled) -->
              <div class="mb-4">
                <label for="status" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Status</label>
                <div class="mt-2 grid grid-cols-1">
                  <select
                    id="status"
                    name="status"
                    form="content-form"
                    class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 sm:text-sm/6"
                  >
                    <option value="draft" ${data.status === 'draft' ? 'selected' : ''}>Draft</option>
                    <option value="review" ${data.status === 'review' ? 'selected' : ''}>Under Review</option>
                    <option value="published" ${data.status === 'published' ? 'selected' : ''}>Published</option>
                    <option value="archived" ${data.status === 'archived' ? 'selected' : ''}>Archived</option>
                  </select>
                  <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-600 dark:text-zinc-400 sm:size-4">
                    <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                  </svg>
                </div>
              </div>

              <!-- Scheduled Publishing -->
              <div class="mb-4">
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Schedule Publish</label>
                <input
                  type="datetime-local"
                  name="scheduled_publish_at"
                  form="content-form"
                  value="${data.scheduled_publish_at ? new Date(data.scheduled_publish_at).toISOString().slice(0, 16) : ''}"
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                >
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">Leave empty to publish immediately</p>
              </div>

              <!-- Scheduled Unpublishing -->
              <div class="mb-6">
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Schedule Unpublish</label>
                <input
                  type="datetime-local"
                  name="scheduled_unpublish_at"
                  form="content-form"
                  value="${data.scheduled_unpublish_at ? new Date(data.scheduled_unpublish_at).toISOString().slice(0, 16) : ''}"
                  class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                >
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">Automatically unpublish at this time</p>
              </div>
            ` : `
              <!-- Simple Status (when workflow plugin is disabled) -->
              <div class="mb-6">
                <label for="status" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Status</label>
                <div class="mt-2 grid grid-cols-1">
                  <select
                    id="status"
                    name="status"
                    form="content-form"
                    class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 sm:text-sm/6"
                  >
                    <option value="draft" ${data.status === 'draft' ? 'selected' : ''}>Draft</option>
                    <option value="published" ${data.status === 'published' ? 'selected' : ''}>Published</option>
                  </select>
                  <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-600 dark:text-zinc-400 sm:size-4">
                    <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                  </svg>
                </div>
                <p class="text-xs text-zinc-500 dark:text-zinc-400 mt-1">Enable Workflow plugin for advanced status management</p>
              </div>
            `}
          </div>

          <!-- Content Info -->
          ${isEdit ? `
            <div class="rounded-lg bg-zinc-50 dark:bg-zinc-800/50 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
              <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white mb-4">Content Info</h3>

              <dl class="space-y-3 text-sm">
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Created</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${data.data?.created_at ? new Date(data.data.created_at).toLocaleDateString() : 'Unknown'}</dd>
                </div>
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Last Modified</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${data.data?.updated_at ? new Date(data.data.updated_at).toLocaleDateString() : 'Unknown'}</dd>
                </div>
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Author</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${data.data?.author || 'Unknown'}</dd>
                </div>
                ${data.data?.published_at ? `
                  <div>
                    <dt class="text-zinc-500 dark:text-zinc-400">Published</dt>
                    <dd class="mt-1 text-zinc-950 dark:text-white">${new Date(data.data.published_at).toLocaleDateString()}</dd>
                  </div>
                ` : ''}
              </dl>

              <div class="mt-4 pt-4 border-t border-zinc-950/5 dark:border-white/10">
                <button
                  type="button"
                  onclick="showVersionHistory('${data.id}')"
                  class="inline-flex items-center gap-x-1.5 text-sm font-medium text-zinc-950 dark:text-white hover:text-zinc-600 dark:hover:text-zinc-300 transition-colors"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z"/>
                  </svg>
                  View Version History
                </button>
              </div>
            </div>
          ` : ''}

          ${(() => {
            // Form submission metadata panel
            const submissionMeta = data.collectionSourceType === 'form' && data.data?._submission_metadata
              ? data.data._submission_metadata
              : null
            if (!submissionMeta) return ''
            return `
          <!-- Form Submission Metadata -->
          <div class="rounded-lg bg-indigo-50 dark:bg-indigo-900/20 shadow-sm ring-1 ring-indigo-200 dark:ring-indigo-500/20 p-6">
            <div class="flex items-center gap-2 mb-4">
              <svg class="h-5 w-5 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25z"/>
              </svg>
              <h3 class="text-base/7 font-semibold text-indigo-900 dark:text-indigo-300">Submission Info</h3>
            </div>
            <dl class="space-y-3 text-sm">
              ${submissionMeta.formName ? `
              <div>
                <dt class="text-indigo-600 dark:text-indigo-400">Form</dt>
                <dd class="mt-1 text-indigo-900 dark:text-indigo-200">${submissionMeta.formName}</dd>
              </div>` : ''}
              ${submissionMeta.email ? `
              <div>
                <dt class="text-indigo-600 dark:text-indigo-400">Submitter Email</dt>
                <dd class="mt-1 text-indigo-900 dark:text-indigo-200">${submissionMeta.email}</dd>
              </div>` : ''}
              ${submissionMeta.ipAddress ? `
              <div>
                <dt class="text-indigo-600 dark:text-indigo-400">IP Address</dt>
                <dd class="mt-1 text-indigo-900 dark:text-indigo-200 font-mono text-xs">${submissionMeta.ipAddress}</dd>
              </div>` : ''}
              ${submissionMeta.userAgent ? `
              <div>
                <dt class="text-indigo-600 dark:text-indigo-400">User Agent</dt>
                <dd class="mt-1 text-indigo-900 dark:text-indigo-200 text-xs break-all">${submissionMeta.userAgent}</dd>
              </div>` : ''}
              ${submissionMeta.submittedAt ? `
              <div>
                <dt class="text-indigo-600 dark:text-indigo-400">Submitted</dt>
                <dd class="mt-1 text-indigo-900 dark:text-indigo-200">${new Date(submissionMeta.submittedAt).toLocaleString()}</dd>
              </div>` : ''}
              ${submissionMeta.submissionId ? `
              <div>
                <dt class="text-indigo-600 dark:text-indigo-400">Submission ID</dt>
                <dd class="mt-1 text-indigo-900 dark:text-indigo-200 font-mono text-xs">${submissionMeta.submissionId}</dd>
              </div>` : ''}
            </dl>
          </div>
            `
          })()}

          <!-- Quick Actions -->
          <div class="rounded-lg bg-zinc-50 dark:bg-zinc-800/50 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
            <h3 class="text-base/7 font-semibold text-zinc-950 dark:text-white mb-4">Quick Actions</h3>

            <div class="space-y-2">
              <button
                type="button"
                onclick="previewContent()"
                class="w-full inline-flex items-center gap-x-2 px-3 py-2 text-sm font-medium text-zinc-950 dark:text-white hover:bg-zinc-100 dark:hover:bg-zinc-700 rounded-lg transition-colors"
              >
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                  <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>
                </svg>
                Preview Content
              </button>

              <button
                type="button"
                onclick="duplicateContent()"
                class="w-full inline-flex items-center gap-x-2 px-3 py-2 text-sm font-medium text-zinc-950 dark:text-white hover:bg-zinc-100 dark:hover:bg-zinc-700 rounded-lg transition-colors"
              >
                <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                </svg>
                Duplicate Content
              </button>

              ${isEdit ? `
                <button
                  type="button"
                  onclick="deleteContent('${data.id}')"
                  class="w-full inline-flex items-center gap-x-2 px-3 py-2 text-sm font-medium text-pink-700 dark:text-pink-300 hover:bg-pink-50 dark:hover:bg-pink-900/20 rounded-lg transition-colors"
                >
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0"/>
                  </svg>
                  Delete Content
                </button>
              ` : ''}
            </div>
          </div>
        </div>

        <!-- Action Buttons -->
        <div class="mt-6 pt-6 border-t border-zinc-950/5 dark:border-white/10 flex items-center justify-between">
          <a href="${backUrl}" class="inline-flex items-center justify-center gap-x-1.5 rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
            Cancel
          </a>

          <div class="flex items-center gap-x-3">
            <button
              type="submit"
              form="content-form"
              name="action"
              value="save"
              class="inline-flex items-center justify-center gap-x-1.5 rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm"
            >
              <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7"/>
              </svg>
              ${isEdit ? 'Update' : 'Save'}
            </button>

            ${data.user?.role !== 'viewer' ? `
              <button
                type="submit"
                form="content-form"
                name="action"
                value="save_and_publish"
                class="inline-flex items-center justify-center gap-x-1.5 rounded-lg bg-lime-600 dark:bg-lime-500 px-3.5 py-2.5 text-sm font-semibold text-white hover:bg-lime-700 dark:hover:bg-lime-600 transition-colors shadow-sm"
              >
                <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                ${isEdit ? 'Update' : 'Save'} & Publish
              </button>
            ` : ''}
          </div>
        </div>
      </div>
      </div>
    </div>

    <!-- Confirmation Dialogs -->
    ${renderConfirmationDialog({
      id: 'duplicate-content-confirm',
      title: 'Duplicate Content',
      message: 'Create a copy of this content?',
      confirmText: 'Duplicate',
      cancelText: 'Cancel',
      iconColor: 'blue',
      confirmClass: 'bg-blue-500 hover:bg-blue-400',
      onConfirm: 'performDuplicateContent()'
    })}

    ${renderConfirmationDialog({
      id: 'delete-content-confirm',
      title: 'Delete Content',
      message: 'Are you sure you want to delete this content? This action cannot be undone.',
      confirmText: 'Delete',
      cancelText: 'Cancel',
      iconColor: 'red',
      confirmClass: 'bg-red-500 hover:bg-red-400',
      onConfirm: `performDeleteContent('${data.id}')`
    })}

    ${getConfirmationDialogScript()}

    ${data.tinymceEnabled ? getTinyMCEScript(data.tinymceSettings?.apiKey) : '<!-- TinyMCE plugin not active -->'}

    ${data.quillEnabled ? getQuillCDN(data.quillSettings?.version) : '<!-- Quill plugin not active -->'}

    ${data.quillEnabled ? getQuillInitScript() : '<!-- Quill init script not needed -->'}

    ${data.mdxeditorEnabled ? getMDXEditorScripts() : '<!-- MDXEditor plugin not active -->'}

    <!-- Dynamic Field Scripts -->
    <script>
      // Field group toggle
      function toggleFieldGroup(groupId) {
        const content = document.getElementById(groupId + '-content');
        const icon = document.getElementById(groupId + '-icon');
        
        if (content.classList.contains('hidden')) {
          content.classList.remove('hidden');
          icon.classList.remove('rotate-[-90deg]');
        } else {
          content.classList.add('hidden');
          icon.classList.add('rotate-[-90deg]');
        }
      }

      // Media field functions
      let currentMediaFieldId = null;

      function openMediaSelector(fieldId) {
        currentMediaFieldId = fieldId;
        // Store the original value in case user cancels
        const originalValue = document.getElementById(fieldId)?.value || '';

        // Open media library modal
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50';
        modal.id = 'media-selector-modal';
        modal.innerHTML = \`
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Select Media</h3>
            <div id="media-grid-container" hx-get="/admin/media/selector" hx-trigger="load"></div>
            <div class="mt-4 flex justify-end space-x-2">
              <button
                onclick="cancelMediaSelection('\${fieldId}', '\${originalValue}')"
                class="rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
                Cancel
              </button>
              <button
                onclick="closeMediaSelector()"
                class="rounded-lg bg-zinc-950 dark:bg-white px-4 py-2 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors">
                OK
              </button>
            </div>
          </div>
        \`;
        document.body.appendChild(modal);
        // Trigger HTMX for the modal content
        if (window.htmx) {
          htmx.process(modal);
        }
      }

      function closeMediaSelector() {
        const modal = document.getElementById('media-selector-modal');
        if (modal) {
          modal.remove();
        }
        currentMediaFieldId = null;
      }

      function cancelMediaSelection(fieldId, originalValue) {
        // Restore original value
        const hiddenInput = document.getElementById(fieldId);
        if (hiddenInput) {
          hiddenInput.value = originalValue;
        }

        // If original value was empty, hide the preview and show select button
        if (!originalValue) {
          const preview = document.getElementById(fieldId + '-preview');
          if (preview) {
            preview.classList.add('hidden');
          }
        }

        // Close modal
        closeMediaSelector();
      }

      function clearMediaField(fieldId) {
        const hiddenInput = document.getElementById(fieldId);
        const preview = document.getElementById(fieldId + '-preview');

        if (hiddenInput) {
          hiddenInput.value = '';
        }

        if (preview) {
          // Clear all children if it's a grid, or hide it
          if (preview.classList.contains('media-preview-grid')) {
            preview.innerHTML = '';
          }
          preview.classList.add('hidden');
        }
      }

      // Global function to remove a single media from multiple selection
      window.removeMediaFromMultiple = function(fieldId, urlToRemove) {
        const hiddenInput = document.getElementById(fieldId);
        if (!hiddenInput) return;

        const values = hiddenInput.value.split(',').filter(url => url !== urlToRemove);
        hiddenInput.value = values.join(',');

        // Remove preview item
        const previewItem = document.querySelector(\`[data-url="\${urlToRemove}"]\`);
        if (previewItem) {
          previewItem.remove();
        }

        // Hide preview grid if empty
        if (values.length === 0) {
          const preview = document.getElementById(fieldId + '-preview');
          if (preview) {
            preview.classList.add('hidden');
          }
        }
      };

      // Global function called by media selector buttons
      window.selectMediaFile = function(mediaId, mediaUrl, filename) {
        if (!currentMediaFieldId) {
          console.error('No field ID set for media selection');
          return;
        }

        const fieldId = currentMediaFieldId;

        // Set the hidden input value to the media URL (not ID)
        const hiddenInput = document.getElementById(fieldId);
        if (hiddenInput) {
          hiddenInput.value = mediaUrl;
        }

        // Update the preview
        const preview = document.getElementById(fieldId + '-preview');
        if (preview) {
          preview.innerHTML = \`<img src="\${mediaUrl}" alt="\${filename}" class="w-32 h-32 object-cover rounded-lg border border-white/20">\`;
          preview.classList.remove('hidden');
        }

        // Show the remove button by finding the media actions container and updating it
        const mediaField = hiddenInput?.closest('.media-field-container');
        if (mediaField) {
          const actionsDiv = mediaField.querySelector('.media-actions');
          if (actionsDiv && !actionsDiv.querySelector('button:has-text("Remove")')) {
            const removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.onclick = () => clearMediaField(fieldId);
            removeBtn.className = 'inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-xl hover:bg-red-700 transition-all';
            removeBtn.textContent = 'Remove';
            actionsDiv.appendChild(removeBtn);
          }
        }

        // DON'T close the modal - let user click OK button
        // Visual feedback: highlight the selected item
        document.querySelectorAll('#media-selector-grid [data-media-id]').forEach(el => {
          el.classList.remove('ring-2', 'ring-lime-500', 'dark:ring-lime-400');
        });
        const selectedItem = document.querySelector(\`#media-selector-grid [data-media-id="\${mediaId}"]\`);
        if (selectedItem) {
          selectedItem.classList.add('ring-2', 'ring-lime-500', 'dark:ring-lime-400');
        }
      };

      function setMediaField(fieldId, mediaUrl) {
        document.getElementById(fieldId).value = mediaUrl;
        const preview = document.getElementById(fieldId + '-preview');
        preview.innerHTML = \`<img src="\${mediaUrl}" alt="Selected media" class="w-32 h-32 object-cover rounded-lg ring-1 ring-zinc-950/10 dark:ring-white/10">\`;
        preview.classList.remove('hidden');

        // Close modal
        document.querySelector('.fixed.inset-0')?.remove();
      }

      // Reference field functions
      let currentReferenceFieldId = null;
      let referenceSearchTimeout = null;

      function getReferenceContainer(fieldId) {
        const input = document.getElementById(fieldId);
        return input ? input.closest('[data-reference-field]') : null;
      }

      function getReferenceCollections(container) {
        if (!container) return [];
        const rawCollections = container.dataset.referenceCollections || '';
        const collections = rawCollections
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean);
        if (collections.length > 0) {
          return collections;
        }
        const singleCollection = container.dataset.referenceCollection;
        return singleCollection ? [singleCollection] : [];
      }

      async function fetchReferenceItems(collections, search = '', limit = 20) {
        const params = new URLSearchParams({ limit: String(limit) });
        collections.forEach((collection) => params.append('collection', collection));
        if (search) {
          params.set('search', search);
        }
        const response = await fetch('/admin/api/references?' + params.toString());
        if (!response.ok) {
          throw new Error('Failed to load references');
        }
        const data = await response.json();
        return data?.data || [];
      }

      async function fetchReferenceById(collections, id) {
        if (!id) return null;
        const params = new URLSearchParams({ id });
        collections.forEach((collection) => params.append('collection', collection));
        const response = await fetch('/admin/api/references?' + params.toString());
        if (!response.ok) {
          return null;
        }
        const data = await response.json();
        return data?.data || null;
      }

      function renderReferenceDisplay(container, item, fallbackMessage = 'No reference selected.') {
        const display = container.querySelector('[data-reference-display]');
        const removeButton = container.querySelector('[data-reference-clear]');
        if (!display) return;

        display.innerHTML = '';

        if (!item) {
          display.textContent = fallbackMessage;
          if (removeButton) {
            removeButton.disabled = true;
          }
          return;
        }

        const title = item.title || item.slug || item.id || 'Untitled';
        const titleEl = document.createElement('div');
        titleEl.className = 'font-medium text-zinc-900 dark:text-white';
        titleEl.textContent = title;

        const row = document.createElement('div');
        row.className = 'flex flex-wrap items-center justify-between gap-2';
        row.appendChild(titleEl);

        const metaRow = document.createElement('div');
        metaRow.className = 'flex flex-wrap items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400';

        if (item.collection?.display_name || item.collection?.name) {
          const collectionLabel = document.createElement('span');
          collectionLabel.className = 'inline-flex items-center rounded-full bg-zinc-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-600 dark:bg-white/10 dark:text-zinc-200';
          collectionLabel.textContent = item.collection.display_name || item.collection.name;
          metaRow.appendChild(collectionLabel);
        }

        if (item.slug) {
          const slugEl = document.createElement('span');
          slugEl.textContent = item.slug;
          metaRow.appendChild(slugEl);
        }

        if (metaRow.childElementCount > 0) {
          row.appendChild(metaRow);
        }

        display.appendChild(row);

        if (removeButton) {
          removeButton.disabled = false;
        }
      }

      function updateReferenceField(fieldId, item) {
        const input = document.getElementById(fieldId);
        const container = getReferenceContainer(fieldId);
        if (!input || !container) return;

        input.value = item?.id || '';
        renderReferenceDisplay(container, item, 'No reference selected.');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }

      function clearReferenceField(fieldId) {
        updateReferenceField(fieldId, null);
      }

      function closeReferenceSelector() {
        const modal = document.getElementById('reference-selector-modal');
        if (modal) {
          modal.remove();
        }
        currentReferenceFieldId = null;
      }

      function openReferenceSelector(fieldId) {
        const container = getReferenceContainer(fieldId);
        const collections = getReferenceCollections(container);
        if (!container || collections.length === 0) {
          console.error('Reference collection is missing for field', fieldId);
          return;
        }

        currentReferenceFieldId = fieldId;

        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50';
        modal.id = 'reference-selector-modal';
        modal.innerHTML = \`
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 w-full max-w-3xl max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between gap-3">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white">Select Reference</h3>
              <button
                type="button"
                onclick="closeReferenceSelector()"
                class="rounded-md text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
                aria-label="Close"
              >
                ✕
              </button>
            </div>
            <div class="mt-4">
              <input
                type="search"
                id="reference-search-input"
                placeholder="Search by title or slug..."
                class="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 shadow-sm focus:border-cyan-500 focus:ring-cyan-500 dark:border-white/10 dark:bg-zinc-900 dark:text-white"
              >
            </div>
            <div id="reference-results" class="mt-4 space-y-2"></div>
            <div class="mt-4 flex justify-end">
              <button
                type="button"
                onclick="closeReferenceSelector()"
                class="rounded-lg bg-zinc-950 dark:bg-white px-4 py-2 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        \`;

        document.body.appendChild(modal);

        const resultsContainer = modal.querySelector('#reference-results');
        const searchInput = modal.querySelector('#reference-search-input');

        const renderResults = (items) => {
          resultsContainer.innerHTML = '';
          if (!items || items.length === 0) {
            resultsContainer.innerHTML = '<div class="rounded-lg border border-dashed border-zinc-200 p-4 text-sm text-zinc-500 dark:border-white/10 dark:text-zinc-400">No items found.</div>';
            return;
          }

          const selectedId = document.getElementById(fieldId)?.value;

          items.forEach((item) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'w-full text-left rounded-lg border border-zinc-200 px-4 py-3 text-sm text-zinc-700 hover:bg-zinc-50 dark:border-white/10 dark:text-zinc-200 dark:hover:bg-white/5';
            if (item.id === selectedId) {
              button.classList.add('ring-2', 'ring-cyan-500', 'dark:ring-cyan-400');
            }

            const title = item.title || item.slug || item.id || 'Untitled';
            const titleEl = document.createElement('div');
            titleEl.className = 'font-medium text-zinc-900 dark:text-white';
            titleEl.textContent = title;

            button.appendChild(titleEl);

            const metaRow = document.createElement('div');
            metaRow.className = 'mt-1 flex flex-wrap items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400';

            if (item.collection?.display_name || item.collection?.name) {
              const collectionLabel = document.createElement('span');
              collectionLabel.className = 'inline-flex items-center rounded-full bg-zinc-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-zinc-600 dark:bg-white/10 dark:text-zinc-200';
              collectionLabel.textContent = item.collection.display_name || item.collection.name;
              metaRow.appendChild(collectionLabel);
            }

            if (item.slug) {
              const slugEl = document.createElement('span');
              slugEl.textContent = item.slug;
              metaRow.appendChild(slugEl);
            }

            if (metaRow.childElementCount > 0) {
              button.appendChild(metaRow);
            }

            button.addEventListener('click', () => {
              updateReferenceField(fieldId, item);
              closeReferenceSelector();
            });

            resultsContainer.appendChild(button);
          });
        };

        const loadResults = async (searchValue = '') => {
          try {
            const items = await fetchReferenceItems(collections, searchValue);
            renderResults(items);
          } catch (error) {
            resultsContainer.innerHTML = '<div class="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700 dark:border-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200">Failed to load references.</div>';
          }
        };

        loadResults();

        searchInput.addEventListener('input', () => {
          if (referenceSearchTimeout) {
            clearTimeout(referenceSearchTimeout);
          }
          referenceSearchTimeout = setTimeout(() => {
            loadResults(searchInput.value.trim());
          }, 250);
        });
      }

      document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('[data-reference-field]').forEach(async (container) => {
          const input = container.querySelector('input[type="hidden"]');
          const collections = getReferenceCollections(container);
          if (!input || collections.length === 0) return;

          if (!input.value) {
            renderReferenceDisplay(container, null, 'No reference selected.');
            return;
          }

          const item = await fetchReferenceById(collections, input.value);
          if (item) {
            renderReferenceDisplay(container, item);
          } else {
            renderReferenceDisplay(container, null, 'Reference not found.');
          }
        });
      });

      document.addEventListener('click', (event) => {
        const trigger = event.target.closest('[data-reference-trigger]');
        if (!trigger) return;
        const container = trigger.closest('[data-reference-field]');
        if (!container || container.dataset.referenceEnabled !== 'true') return;
        const input = container.querySelector('input[type="hidden"]');
        if (!input) return;
        openReferenceSelector(input.id);
      });

      document.addEventListener('keydown', (event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        const trigger = event.target.closest('[data-reference-trigger]');
        if (!trigger) return;
        const container = trigger.closest('[data-reference-field]');
        if (!container || container.dataset.referenceEnabled !== 'true') return;
        const input = container.querySelector('input[type="hidden"]');
        if (!input) return;
        event.preventDefault();
        openReferenceSelector(input.id);
      });

      // Custom select options
      function addCustomOption(input, selectId) {
        const value = input.value.trim();
        if (value) {
          const select = document.getElementById(selectId);
          const option = document.createElement('option');
          option.value = value;
          option.text = value;
          option.selected = true;
          select.appendChild(option);
          input.value = '';
        }
      }

      // Quick actions
      function previewContent() {
        const form = document.getElementById('content-form');
        const formData = new FormData(form);
        
        // Open preview in new window
        const preview = window.open('', '_blank');
        preview.document.write('<p>Loading preview...</p>');
        
        fetch('/admin/content/preview', {
          method: 'POST',
          body: formData
        })
        .then(response => response.text())
        .then(html => {
          preview.document.open();
          preview.document.write(html);
          preview.document.close();
        })
        .catch(error => {
          preview.document.write('<p>Error loading preview</p>');
        });
      }

      function duplicateContent() {
        showConfirmDialog('duplicate-content-confirm');
      }

      function performDuplicateContent() {
        const form = document.getElementById('content-form');
        const formData = new FormData(form);
        formData.append('action', 'duplicate');

        fetch('/admin/content/duplicate', {
          method: 'POST',
          body: formData
        })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            window.location.href = \`/admin/content/\${data.id}/edit\`;
          } else {
            alert('Error duplicating content');
          }
        });
      }

      function deleteContent(contentId) {
        showConfirmDialog('delete-content-confirm');
      }

      function performDeleteContent(contentId) {
        fetch(\`/admin/content/\${contentId}\`, {
          method: 'DELETE'
        })
        .then(response => {
          if (response.ok) {
            window.location.href = '/admin/content';
          } else {
            alert('Error deleting content');
          }
        });
      }

      function showVersionHistory(contentId) {
        // Create and show version history modal
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50';
        modal.innerHTML = \`
          <div id="version-history-content">
            <div class="flex items-center justify-center h-32">
              <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
            </div>
          </div>
        \`;
        document.body.appendChild(modal);

        // Load version history
        fetch(\`/admin/content/\${contentId}/versions\`)
        .then(response => response.text())
        .then(html => {
          document.getElementById('version-history-content').innerHTML = html;
        })
        .catch(error => {
          console.error('Error loading version history:', error);
          document.getElementById('version-history-content').innerHTML = '<p class="text-zinc-950 dark:text-white">Error loading version history</p>';
        });
      }

      // Auto-save functionality
      let autoSaveTimeout;
      function scheduleAutoSave() {
        clearTimeout(autoSaveTimeout);
        autoSaveTimeout = setTimeout(() => {
          const form = document.getElementById('content-form');
          const formData = new FormData(form);
          formData.append('action', 'autosave');
          
          fetch(form.action, {
            method: 'POST',
            body: formData
          })
          .then(response => {
            if (response.ok) {
              console.log('Auto-saved');
            }
          })
          .catch(error => console.error('Auto-save failed:', error));
        }, 30000); // Auto-save every 30 seconds
      }

      // Bind auto-save to form changes
      document.addEventListener('DOMContentLoaded', function() {
        const form = document.getElementById('content-form');
        form.addEventListener('input', scheduleAutoSave);
        form.addEventListener('change', scheduleAutoSave);
      });

      ${data.tinymceEnabled ? getTinyMCEInitScript({
        skin: data.tinymceSettings?.skin,
        defaultHeight: data.tinymceSettings?.defaultHeight,
        defaultToolbar: data.tinymceSettings?.defaultToolbar
      }) : ''}

      ${data.mdxeditorEnabled ? getMDXEditorInitScript({
        defaultHeight: data.mdxeditorSettings?.defaultHeight,
        toolbar: data.mdxeditorSettings?.toolbar,
        placeholder: data.mdxeditorSettings?.placeholder
      }) : ''}
    </script>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: title,
    pageTitle: 'Content Management',
    currentPath: '/admin/content',
    user: data.user,
    content: pageContent,
    version: data.version
  }

  return renderAdminLayoutCatalyst(layoutData)
}
