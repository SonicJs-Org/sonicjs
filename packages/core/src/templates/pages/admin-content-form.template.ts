import { getMDXEditorInitScript, getMDXEditorScripts } from '../../plugins/available/easy-mdx'
import { getTinyMCEInitScript, getTinyMCEScript } from '../../plugins/available/tinymce-plugin'
import { getQuillCDN, getQuillInitScript } from '../../plugins/core-plugins/quill-editor'
import { renderAlert } from '../alert.template'
import { FieldDefinition, renderDynamicField, renderFieldGroup } from '../components/dynamic-field.template'
import { getConfirmationDialogScript, renderConfirmationDialog } from '../confirmation-dialog.template'
import { AdminLayoutCatalystData, renderAdminLayoutCatalyst } from '../layouts/admin-layout-catalyst.template'

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
  created_at?: number
  updated_at?: number
  published_at?: number
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
  const hasValidationErrors = Boolean(data.validationErrors && Object.keys(data.validationErrors).length > 0)

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
            data-has-validation-errors="${hasValidationErrors ? 'true' : 'false'}"
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
                  <dd class="mt-1 text-zinc-950 dark:text-white">${data.created_at ? new Date(data.created_at).toLocaleDateString() : 'Unknown'}</dd>
                </div>
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Last Modified</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${data.updated_at ? new Date(data.updated_at).toLocaleDateString() : 'Unknown'}</dd>
                </div>
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Author</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${data.data?.author || 'Unknown'}</dd>
                </div>
                ${data.published_at ? `
                  <div>
                    <dt class="text-zinc-500 dark:text-zinc-400">Published</dt>
                    <dd class="mt-1 text-zinc-950 dark:text-white">${new Date(data.published_at).toLocaleDateString()}</dd>
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

    ${renderConfirmationDialog({
      id: 'delete-repeater-item-confirm',
      title: 'Delete Item',
      message: 'Are you sure you want to delete this item? This action cannot be undone.',
      confirmText: 'Delete',
      cancelText: 'Cancel',
      iconColor: 'red',
      confirmClass: 'bg-red-500 hover:bg-red-400',
      onConfirm: 'performRepeaterDelete()'
    })}

    ${renderConfirmationDialog({
      id: 'delete-block-confirm',
      title: 'Delete Block',
      message: 'Are you sure you want to delete this block? This action cannot be undone.',
      confirmText: 'Delete',
      cancelText: 'Cancel',
      iconColor: 'red',
      confirmClass: 'bg-red-500 hover:bg-red-400',
      onConfirm: 'performRepeaterDelete()'
    })}

    ${getConfirmationDialogScript()}

    ${data.tinymceEnabled ? getTinyMCEScript(data.tinymceSettings?.apiKey) : '<!-- TinyMCE plugin not active -->'}

    ${data.quillEnabled ? getQuillCDN(data.quillSettings?.version) : '<!-- Quill plugin not active -->'}

    ${data.quillEnabled ? getQuillInitScript() : '<!-- Quill init script not needed -->'}

    ${data.mdxeditorEnabled ? getMDXEditorScripts() : '<!-- MDXEditor plugin not active -->'}

    <!-- Dynamic Field Scripts -->
    <script>
      const contentFormCollectionId = ${JSON.stringify(data.collection.id)};

      function getFieldGroupScope() {
        const url = new URL(window.location.href);
        const urlCollectionId = url.searchParams.get('collection');
        const effectiveCollectionId = urlCollectionId || contentFormCollectionId || '';
        return window.location.pathname + ':' + effectiveCollectionId;
      }

      function getItemPosition(itemSelector, item) {
        if (!(item instanceof Element)) return -1;
        const parent = item.parentElement;
        if (!parent) return -1;
        return Array.from(parent.querySelectorAll(':scope > ' + itemSelector)).indexOf(item);
      }

      function stripIndexedFieldPrefix(fullFieldName, prefix) {
        if (!fullFieldName || !prefix || !fullFieldName.startsWith(prefix)) {
          return fullFieldName;
        }

        const remainder = fullFieldName.slice(prefix.length);
        const indexMatch = remainder.match(/^(\\d+)(-|__)(.*)$/);
        if (!indexMatch) {
          return fullFieldName;
        }

        return indexMatch[3];
      }

      function getFieldGroupStorageKey(groupOrId) {
        const defaultGroupId = typeof groupOrId === 'string' ? groupOrId : (groupOrId?.getAttribute('data-group-id') || 'unknown');
        const group = typeof groupOrId === 'string'
          ? document.querySelector('.field-group[data-group-id="' + defaultGroupId + '"]')
          : groupOrId;

        const scopePrefix = 'sonic:ui:objects:' + getFieldGroupScope() + ':';
        if (!(group instanceof Element)) {
          return scopePrefix + defaultGroupId;
        }

        const fullFieldName = group.getAttribute('data-field-name') || '';

        const blocksField = group.closest('.blocks-field');
        const blockItem = group.closest('.blocks-item');
        if (blocksField instanceof Element && blockItem instanceof Element) {
          const blocksFieldName = blocksField.getAttribute('data-field-name') || 'unknown';
          const blockPosition = getItemPosition('.blocks-item', blockItem);
          const relativePath = stripIndexedFieldPrefix(fullFieldName, 'block-' + blocksFieldName + '-') || defaultGroupId;
          return scopePrefix + 'blocks:' + blocksFieldName + ':' + blockPosition + ':' + relativePath;
        }

        const arrayField = group.closest('[data-structured-array][data-field-name]');
        const arrayItem = group.closest('.structured-array-item');
        if (arrayField instanceof Element && arrayItem instanceof Element) {
          const arrayFieldName = arrayField.getAttribute('data-field-name') || 'unknown';
          const itemPosition = getItemPosition('.structured-array-item', arrayItem);
          const relativePath = stripIndexedFieldPrefix(fullFieldName, 'array-' + arrayFieldName + '-') || defaultGroupId;
          return scopePrefix + 'repeaters:' + arrayFieldName + ':' + itemPosition + ':' + relativePath;
        }

        return scopePrefix + defaultGroupId;
      }

      function loadFieldGroupState(group) {
        try {
          const value = sessionStorage.getItem(getFieldGroupStorageKey(group));
          if (value === '1') return true;
          if (value === '0') return false;
        } catch {}
        return null;
      }

      function saveFieldGroupState(group, isCollapsed) {
        try {
          sessionStorage.setItem(getFieldGroupStorageKey(group), isCollapsed ? '1' : '0');
        } catch {}
      }

      function resolveFieldGroupElements(groupOrId) {
        let group = null;

        if (groupOrId instanceof Element) {
          group = groupOrId.classList.contains('field-group')
            ? groupOrId
            : groupOrId.closest('.field-group[data-group-id]');
        } else if (typeof groupOrId === 'string' && groupOrId) {
          group = document.querySelector('.field-group[data-group-id="' + groupOrId + '"]');
        }

        let content = null;
        let icon = null;

        if (group instanceof Element) {
          content = group.querySelector(':scope > .field-group-content');
          icon = group.querySelector(':scope > .field-group-header svg[id$="-icon"]');
        }

        // Legacy fallback for any existing calls still passing string IDs.
        if (!(content instanceof HTMLElement) && typeof groupOrId === 'string') {
          content = document.getElementById(groupOrId + '-content');
        }
        if (!(icon instanceof Element) && typeof groupOrId === 'string') {
          icon = document.getElementById(groupOrId + '-icon');
        }

        if (!(group instanceof Element) && content instanceof Element) {
          group = content.closest('.field-group[data-group-id]');
        }

        return { group, content, icon };
      }

      function applyFieldGroupState(groupOrId, isCollapsed) {
        const { content, icon } = resolveFieldGroupElements(groupOrId);
        if (!(content instanceof HTMLElement) || !(icon instanceof Element)) return;
        content.classList.toggle('hidden', isCollapsed);
        icon.classList.toggle('-rotate-90', isCollapsed);
      }

      function restoreFieldGroupStates() {
        document.querySelectorAll('.field-group[data-group-id]').forEach((group) => {
          const savedState = loadFieldGroupState(group);
          if (savedState === null) return;
          applyFieldGroupState(group, savedState);
        });
      }

      function persistAllFieldGroupStates() {
        document.querySelectorAll('.field-group[data-group-id]').forEach((group) => {
          const { content } = resolveFieldGroupElements(group);
          if (!(content instanceof HTMLElement)) return;
          saveFieldGroupState(group, content.classList.contains('hidden'));
        });
      }

      function setValidationHeaderIndicator(container) {
        if (!(container instanceof Element)) return;
        let header = null;
        let markerTarget = null;

        if (container.classList.contains('field-group')) {
          header = container.querySelector(':scope > .field-group-header');
          markerTarget = container.querySelector(':scope > .field-group-header h3');
        } else if (container.classList.contains('structured-array-item')) {
          header = container.querySelector('[data-action="toggle-item"]');
          markerTarget = header;
        } else if (container.classList.contains('blocks-item')) {
          header = container.querySelector('[data-action="toggle-block"]');
          markerTarget = header;
        }

        if (!(header instanceof HTMLElement)) return;
        if (!(markerTarget instanceof HTMLElement)) {
          markerTarget = header;
        }

        header.dataset.validationHeaderError = 'true';
        header.classList.add('text-pink-700', 'dark:text-pink-300');

        if (!markerTarget.querySelector('[data-validation-indicator]')) {
          const marker = document.createElement('span');
          marker.setAttribute('data-validation-indicator', 'true');
          marker.className = 'ml-2 inline-block h-2 w-2 rounded-full bg-pink-500 align-middle';
          marker.setAttribute('aria-hidden', 'true');
          markerTarget.appendChild(marker);
        }
      }

      function clearValidationIndicators() {
        document.querySelectorAll('[data-validation-header-error="true"]').forEach((el) => {
          if (!(el instanceof HTMLElement)) return;
          delete el.dataset.validationHeaderError;
          el.classList.remove('text-pink-700', 'dark:text-pink-300');
        });

        document.querySelectorAll('[data-validation-indicator]').forEach((el) => el.remove());
      }

      function expandContainerForValidation(container) {
        if (!(container instanceof Element)) return;

        if (container.classList.contains('field-group')) {
          applyFieldGroupState(container, false);
          return;
        }

        if (container.classList.contains('structured-array-item')) {
          const content = container.querySelector('[data-array-item-fields]');
          const icon = container.querySelector('[data-item-toggle-icon]');
          if (content instanceof HTMLElement) {
            content.classList.remove('hidden');
          }
          if (icon instanceof Element) {
            icon.classList.remove('-rotate-90');
          }
          return;
        }

        if (container.classList.contains('blocks-item')) {
          const content = container.querySelector('[data-block-content]');
          const icon = container.querySelector('[data-block-toggle-icon]');
          if (content instanceof HTMLElement) {
            content.classList.remove('hidden');
          }
          if (icon instanceof Element) {
            icon.classList.remove('-rotate-90');
          }
        }
      }

      function walkErrorContainers(node, expand) {
        if (!(node instanceof Element)) return;
        const visited = new Set();
        let cursor = node;
        while (cursor) {
          const candidates = [
            cursor.closest('.structured-array-item'),
            cursor.closest('.blocks-item'),
            cursor.closest('.field-group[data-group-id]')
          ].filter((c) => c instanceof Element && !visited.has(c));

          if (candidates.length === 0) break;

          // Pick nearest ancestor container to preserve "first-error path only".
          let nearest = candidates[0];
          let bestDistance = Number.MAX_SAFE_INTEGER;
          for (const candidate of candidates) {
            let distance = 0;
            let walker = cursor;
            while (walker && walker !== candidate) {
              walker = walker.parentElement;
              distance += 1;
            }
            if (distance < bestDistance) {
              bestDistance = distance;
              nearest = candidate;
            }
          }

          visited.add(nearest);
          setValidationHeaderIndicator(nearest);
          if (expand) {
            expandContainerForValidation(nearest);
          }
          cursor = nearest.parentElement;
        }
      }

      function getFocusableTargetFromErrorGroup(group) {
        if (!(group instanceof Element)) return null;
        return (
          group.querySelector('input:not([type="hidden"]):not([disabled]), textarea:not([disabled]), select:not([disabled]), [contenteditable="true"]') ||
          group.querySelector('button:not([disabled])')
        );
      }

      function revealServerValidationErrors() {
        clearValidationIndicators();

        const errorGroups = Array.from(document.querySelectorAll('.form-group[data-has-errors="true"]'));
        if (errorGroups.length === 0) return;

        // Add indicators for all errored sections, expand only first-error path.
        errorGroups.forEach((group, index) => {
          walkErrorContainers(group, index === 0);
        });

        const firstTarget = getFocusableTargetFromErrorGroup(errorGroups[0]);
        if (firstTarget instanceof HTMLElement) {
          firstTarget.scrollIntoView({ behavior: 'smooth', block: 'center' });
          firstTarget.focus({ preventScroll: true });
        }
      }

      function revealNativeValidationErrors(form) {
        if (!(form instanceof HTMLFormElement)) return;
        clearValidationIndicators();

        const invalidControls = Array.from(form.querySelectorAll(':invalid'));
        if (invalidControls.length === 0) return;

        invalidControls.forEach((control, index) => {
          walkErrorContainers(control, index === 0);
        });

        const first = invalidControls[0];
        if (first instanceof HTMLElement) {
          first.scrollIntoView({ behavior: 'smooth', block: 'center' });
          first.focus({ preventScroll: true });
        }
      }

      // Field group toggle
      function toggleFieldGroup(groupOrTrigger) {
        const { group, content } = resolveFieldGroupElements(groupOrTrigger);
        if (!(group instanceof Element)) return;
        if (!(content instanceof HTMLElement)) return;

        const isCollapsed = !content.classList.contains('hidden');
        applyFieldGroupState(group, isCollapsed);
        saveFieldGroupState(group, isCollapsed);
      }

      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
          restoreFieldGroupStates();
          const form = document.getElementById('content-form');
          if (form?.getAttribute('data-has-validation-errors') === 'true') {
            revealServerValidationErrors();
          }
        });
      } else {
        restoreFieldGroupStates();
        const form = document.getElementById('content-form');
        if (form?.getAttribute('data-has-validation-errors') === 'true') {
          revealServerValidationErrors();
        }
      }

      document.addEventListener('htmx:afterSwap', function() {
        setTimeout(() => {
          restoreFieldGroupStates();
          const form = document.getElementById('content-form');
          if (form?.getAttribute('data-has-validation-errors') === 'true') {
            revealServerValidationErrors();
          }
        }, 50);
      });

      const contentFormEl = document.getElementById('content-form');
      if (contentFormEl instanceof HTMLFormElement) {
        contentFormEl.addEventListener('submit', () => {
          persistAllFieldGroupStates();
        }, true);
      }

      window.addEventListener('beforeunload', () => {
        persistAllFieldGroupStates();
      });

      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
          persistAllFieldGroupStates();
        }
      });

      let pendingNativeValidationReveal = false;
      document.addEventListener('invalid', function(event) {
        const target = event.target;
        if (!(target instanceof Element)) return;
        const form = target.closest('form');
        if (!(form instanceof HTMLFormElement)) return;

        if (pendingNativeValidationReveal) return;
        pendingNativeValidationReveal = true;

        // Expand only first invalid path synchronously so the browser can focus it
        // and avoid "invalid form control is not focusable" errors.
        walkErrorContainers(target, true);

        setTimeout(() => {
          pendingNativeValidationReveal = false;
          revealNativeValidationErrors(form);
        }, 0);
      }, true);

      // Media field functions
      function notifyFieldChange(input) {
        if (!input) return;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }

      function getActiveMediaModal() {
        const modal = document.getElementById('media-selector-modal');
        return modal instanceof HTMLElement ? modal : null;
      }

      function getMediaFieldElements(fieldId) {
        if (!fieldId) {
          return {
            fieldId: '',
            hiddenInput: null,
            preview: null,
            mediaField: null,
            actionsDiv: null,
          };
        }

        const hiddenInput = document.getElementById(fieldId);
        const preview = document.getElementById(fieldId + '-preview');
        const mediaField = hiddenInput?.closest('.media-field-container') || null;
        const actionsDiv = mediaField?.querySelector('.media-actions') || null;

        return {
          fieldId,
          hiddenInput,
          preview,
          mediaField,
          actionsDiv,
        };
      }

      function getActiveMediaTarget() {
        const modal = getActiveMediaModal();
        const fieldId = modal?.dataset.targetFieldId || '';
        return {
          modal,
          originalValue: modal?.dataset.originalValue || '',
          ...getMediaFieldElements(fieldId),
        };
      }

      function ensureSingleMediaRemoveButton(fieldId, actionsDiv) {
        if (!(actionsDiv instanceof HTMLElement)) return;
        const existingRemoveButton = actionsDiv.querySelector('[data-media-remove="true"]');
        if (existingRemoveButton) return;

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.setAttribute('data-media-remove', 'true');
        removeBtn.onclick = () => clearMediaField(fieldId);
        removeBtn.className = 'inline-flex items-center px-4 py-2 bg-red-600 text-white rounded-xl hover:bg-red-700 transition-all';
        removeBtn.textContent = 'Remove';
        actionsDiv.appendChild(removeBtn);
      }

      function openMediaSelector(fieldId) {
        const existingModal = getActiveMediaModal();
        if (existingModal) {
          existingModal.remove();
        }

        // Store the original value in case user cancels
        const originalValue = getMediaFieldElements(fieldId).hiddenInput?.value || '';

        // Open media library modal
        const modal = document.createElement('div');
        modal.className = 'fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50';
        modal.id = 'media-selector-modal';
        modal.dataset.targetFieldId = fieldId;
        modal.dataset.originalValue = originalValue;
        modal.innerHTML = \`
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-xl ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <h3 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Select Media</h3>
            <div id="media-grid-container" hx-get="/admin/media/selector" hx-trigger="load"></div>
            <div class="mt-4 flex justify-end space-x-2">
              <button
                onclick="cancelMediaSelection()"
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
        const modal = getActiveMediaModal();
        if (modal) {
          modal.remove();
        }
      }

      function cancelMediaSelection() {
        const { hiddenInput, preview, originalValue } = getActiveMediaTarget();

        // Restore original value
        if (hiddenInput) {
          hiddenInput.value = originalValue;
          notifyFieldChange(hiddenInput);
        }

        // If original value was empty, hide the preview and show select button
        if (!originalValue) {
          if (preview) {
            preview.classList.add('hidden');
          }
        }

        // Close modal
        closeMediaSelector();
      }

      function clearMediaField(fieldId) {
        const { hiddenInput, preview, actionsDiv } = getMediaFieldElements(fieldId);

        if (hiddenInput) {
          hiddenInput.value = '';
          notifyFieldChange(hiddenInput);
        }

        if (preview) {
          // Clear all children if it's a grid, or hide it
          if (preview.classList.contains('media-preview-grid')) {
            preview.innerHTML = '';
          }
          preview.classList.add('hidden');
        }

        const removeButton = actionsDiv?.querySelector('[data-media-remove="true"]');
        if (removeButton) {
          removeButton.remove();
        }
      }

      // Global function to remove a single media from multiple selection
      window.removeMediaFromMultiple = function(fieldId, urlToRemove) {
        const { hiddenInput, preview } = getMediaFieldElements(fieldId);
        if (!hiddenInput) return;

        const values = hiddenInput.value.split(',').filter(url => url !== urlToRemove);
        hiddenInput.value = values.join(',');
        notifyFieldChange(hiddenInput);

        // Remove preview item
        const previewItem =
          preview &&
          Array.from(preview.querySelectorAll('[data-url]')).find(
            (item) => item.getAttribute('data-url') === urlToRemove,
          );
        if (previewItem) {
          previewItem.remove();
        }

        // Hide preview grid if empty
        if (values.length === 0) {
          if (preview) {
            preview.classList.add('hidden');
          }
        }
      };

      // Global function called by media selector buttons
      window.selectMediaFile = function(mediaId, mediaUrl, filename) {
        const { fieldId, hiddenInput, preview, actionsDiv } = getActiveMediaTarget();
        if (!fieldId || !hiddenInput) {
          console.error('No field ID set for media selection');
          return;
        }

        // Set the hidden input value to the media URL (not ID)
        hiddenInput.value = mediaUrl;
        notifyFieldChange(hiddenInput);

        // Update the preview
        if (preview) {
          preview.innerHTML = \`<img src="\${mediaUrl}" alt="\${filename}" class="w-32 h-32 object-cover rounded-lg border border-white/20">\`;
          preview.classList.remove('hidden');
        }

        // Show the remove button by finding the media actions container and updating it
        ensureSingleMediaRemoveButton(fieldId, actionsDiv);

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
        const hiddenInput = document.getElementById(fieldId);
        hiddenInput.value = mediaUrl;
        notifyFieldChange(hiddenInput);
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

      // Repeater/blocks delete confirmation
      let pendingRepeaterDelete = null;
      function requestRepeaterDelete(callback, type = 'item') {
        pendingRepeaterDelete = callback;
        if (typeof showConfirmDialog === 'function') {
          showConfirmDialog(type === 'block' ? 'delete-block-confirm' : 'delete-repeater-item-confirm');
          return;
        }
        if (confirm('Remove this item? This action cannot be undone.')) {
          if (typeof pendingRepeaterDelete === 'function') {
            pendingRepeaterDelete();
          }
        }
        pendingRepeaterDelete = null;
      }

      function performRepeaterDelete() {
        if (typeof pendingRepeaterDelete === 'function') {
          pendingRepeaterDelete();
        }
        pendingRepeaterDelete = null;
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
