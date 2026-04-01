import { html } from 'hono/html'
import type { HtmlEscapedString } from 'hono/utils/html'
import type { Redirect } from '../types'
import { renderAdminLayoutCatalyst } from '@sonicjs-cms/core/templates'

export interface RedirectFormPageData {
  /** Whether this is an edit form (true) or create form (false) */
  isEdit: boolean
  /** The redirect being edited (only populated for edit forms) */
  redirect?: Redirect | undefined
  /** Validation error message to display */
  error?: string | undefined
  /** Warning message to display */
  warning?: string | undefined
  /** Preserved filter params from list page for back navigation */
  referrerParams?: string | undefined
  /** Current user */
  user: any
}

/**
 * Render the redirect create/edit form page
 */
export function renderRedirectFormPage(data: RedirectFormPageData): HtmlEscapedString | Promise<HtmlEscapedString> {
  const { isEdit, redirect, error, warning, referrerParams } = data
  const pageTitle = isEdit ? 'Edit Redirect' : 'New Redirect'
  const submitText = isEdit ? 'Update Redirect' : 'Create Redirect'
  const formAction = isEdit ? `/admin/redirects/${redirect?.id}` : '/admin/redirects'

  const backUrl = referrerParams
    ? `/admin/redirects?${referrerParams}`
    : '/admin/redirects'

  const content = html`
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">
            ${pageTitle}
          </h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            ${isEdit ? 'Modify an existing redirect rule' : 'Create a new redirect rule'}
          </p>
        </div>
      </div>

      <!-- Error/Warning Messages -->
      ${error ? renderAlert('error', error) : ''}
      ${warning ? renderAlert('warning', warning) : ''}

      <!-- Form Container -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
        <form
          hx-${isEdit ? 'put' : 'post'}="${formAction}"
          hx-target="#form-messages"
          hx-swap="innerHTML"
          class="p-6 space-y-8"
        >
          <div id="form-messages"></div>

          <!-- Section 1: URLs -->
          <div class="border-b border-zinc-200 dark:border-zinc-800 pb-8">
            <h2 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">
              URLs
            </h2>

            <!-- Source URL -->
            <div class="mb-6">
              <label for="source" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
                Source URL
                <span class="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="source"
                name="source"
                value="${redirect?.source || ''}"
                placeholder="/old-page"
                required
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
              />
              <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                The URL path to redirect from (e.g., /old-page)
              </p>
            </div>

            <!-- Destination URL -->
            <div>
              <label for="destination" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
                Destination URL
                <span class="text-red-500">*</span>
              </label>
              <input
                type="text"
                id="destination"
                name="destination"
                value="${redirect?.destination || ''}"
                placeholder="/new-page or https://example.com/page"
                required
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
              />
              <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                The URL to redirect to (path or full URL)
              </p>
            </div>
          </div>

          <!-- Section 2: Behavior -->
          <div class="border-b border-zinc-200 dark:border-zinc-800 pb-8">
            <h2 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">
              Behavior
            </h2>

            <!-- Status Code -->
            <div class="mb-6">
              <label for="status_code" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
                Status Code
                <span class="text-red-500">*</span>
              </label>
              <select
                id="status_code"
                name="status_code"
                required
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
              >
                <option value="301" ${(!redirect || redirect.statusCode === 301) ? 'selected' : ''}>301 Permanent</option>
                <option value="302" ${redirect?.statusCode === 302 ? 'selected' : ''}>302 Temporary</option>
                <option value="307" ${redirect?.statusCode === 307 ? 'selected' : ''}>307 Temporary (Preserve Method)</option>
                <option value="308" ${redirect?.statusCode === 308 ? 'selected' : ''}>308 Permanent (Preserve Method)</option>
                <option value="410" ${redirect?.statusCode === 410 ? 'selected' : ''}>410 Gone</option>
              </select>
              <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                301/308 for permanent moves (SEO), 302/307 for temporary, 410 for deleted pages
              </p>
            </div>

            <!-- Match Type -->
            <div>
              <label for="match_type" class="block text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-2">
                Match Type
                <span class="text-red-500">*</span>
              </label>
              <select
                id="match_type"
                name="match_type"
                required
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500"
              >
                <option value="0" ${(!redirect || redirect.matchType === 0) ? 'selected' : ''}>Exact</option>
                <option value="1" ${redirect?.matchType === 1 ? 'selected' : ''}>Wildcard</option>
                <option value="2" ${redirect?.matchType === 2 ? 'selected' : ''}>Regex (not synced to Cloudflare)</option>
              </select>
              <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                Exact: URL must match exactly. Wildcard: Matches URLs with prefix/contains. Regex: Pattern matching (local only).
              </p>
            </div>
          </div>

          <!-- Section 3: Options (Cloudflare-aligned) -->
          <div class="border-b border-zinc-200 dark:border-zinc-800 pb-8">
            <h2 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">
              Options
              <span class="ml-2 text-xs font-normal text-zinc-500 dark:text-zinc-400">(Cloudflare Bulk Redirects compatible)</span>
            </h2>

            <!-- Preserve Query String -->
            <div class="mb-4">
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="preserve_query_string"
                  value="1"
                  ${redirect?.preserveQueryString ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Preserve Query String</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Append original query string to destination URL
                  </span>
                </span>
              </label>
            </div>

            <!-- Include Subdomains -->
            <div class="mb-4">
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="include_subdomains"
                  value="1"
                  ${redirect?.includeSubdomains ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Include Subdomains</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Match requests from all subdomains (e.g., www.example.com, blog.example.com)
                  </span>
                </span>
              </label>
            </div>

            <!-- Subpath Matching -->
            <div class="mb-4">
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="subpath_matching"
                  value="1"
                  ${redirect?.subpathMatching ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Subpath Matching</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Match all paths that start with the source URL pattern
                  </span>
                </span>
              </label>
            </div>

            <!-- Preserve Path Suffix -->
            <div class="mb-4">
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="preserve_path_suffix"
                  value="1"
                  ${(!redirect || redirect.preservePathSuffix) ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Preserve Path Suffix</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Append the remaining path to destination (requires Subpath Matching)
                  </span>
                </span>
              </label>
            </div>

            <!-- Active -->
            <div>
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="active"
                  value="1"
                  ${(!redirect || redirect.isActive) ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Active</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Inactive redirects are saved but not applied
                  </span>
                </span>
              </label>
            </div>
          </div>

          ${isEdit && redirect ? html`
            <!-- Section 4: Audit Trail (Edit mode only) -->
            <div class="pb-8">
              <h2 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">
                Audit Trail
              </h2>
              <dl class="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Created By</dt>
                  <dd class="mt-1 text-sm text-zinc-900 dark:text-zinc-100">
                    ${(redirect as any).createdByName || 'Unknown'}
                    <span class="text-zinc-500 dark:text-zinc-400 ml-1">
                      (${formatRelativeTime(redirect.createdAt)})
                    </span>
                  </dd>
                </div>
                ${(redirect as any).updatedByName ? html`
                  <div>
                    <dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Last Updated By</dt>
                    <dd class="mt-1 text-sm text-zinc-900 dark:text-zinc-100">
                      ${(redirect as any).updatedByName}
                      <span class="text-zinc-500 dark:text-zinc-400 ml-1">
                        (${formatRelativeTime(redirect.updatedAt)})
                      </span>
                    </dd>
                  </div>
                ` : ''}
                ${(redirect as any).hitCount !== undefined ? html`
                  <div>
                    <dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Total Hits</dt>
                    <dd class="mt-1 text-sm text-zinc-900 dark:text-zinc-100">
                      ${((redirect as any).hitCount || 0).toLocaleString()}
                      ${(redirect as any).lastHitAt ? html`
                        <span class="text-zinc-500 dark:text-zinc-400 ml-1">
                          (last: ${formatRelativeTime((redirect as any).lastHitAt)})
                        </span>
                      ` : ''}
                    </dd>
                  </div>
                ` : ''}
              </dl>
            </div>
          ` : ''}

          <!-- Form Actions -->
          <div class="flex items-center justify-end gap-x-4 pt-4 border-t border-zinc-200 dark:border-zinc-800">
            <a
              href="${backUrl}"
              class="px-4 py-2 text-sm font-semibold text-zinc-900 dark:text-zinc-100 bg-white dark:bg-zinc-800 rounded-lg ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700"
            >
              Cancel
            </a>
            <button
              type="submit"
              class="px-4 py-2 text-sm font-semibold text-white bg-indigo-600 rounded-lg hover:bg-indigo-500 shadow-sm"
            >
              ${submitText}
            </button>
          </div>
        </form>
      </div>
    </div>

    ${getFormScripts()}
  `

  return renderLayout(pageTitle, content)
}

/**
 * Format relative time using native Intl.RelativeTimeFormat
 */
function formatRelativeTime(timestamp: number): string {
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' })
  const seconds = Math.floor((timestamp - Date.now()) / 1000)

  if (Math.abs(seconds) < 60) return rtf.format(seconds, 'second')
  const minutes = Math.floor(seconds / 60)
  if (Math.abs(minutes) < 60) return rtf.format(minutes, 'minute')
  const hours = Math.floor(minutes / 60)
  if (Math.abs(hours) < 24) return rtf.format(hours, 'hour')
  const days = Math.floor(hours / 24)
  if (Math.abs(days) < 30) return rtf.format(days, 'day')
  const months = Math.floor(days / 30)
  if (Math.abs(months) < 12) return rtf.format(months, 'month')
  const years = Math.floor(months / 12)
  return rtf.format(years, 'year')
}

/**
 * Render alert message box
 */
function renderAlert(type: 'error' | 'warning', message: string): HtmlEscapedString | Promise<HtmlEscapedString> {
  const colors = {
    error: 'bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-400 border-red-200 dark:border-red-800',
    warning: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-400 border-yellow-200 dark:border-yellow-800'
  }

  return html`
    <div class="mb-6 rounded-lg border ${colors[type]} p-4">
      <p class="text-sm">${message}</p>
    </div>
  `
}

/**
 * Get form interaction scripts
 */
function getFormScripts(): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script>
      // Handle HTMX form submission
      document.body.addEventListener('htmx:afterRequest', function(event) {
        // Only redirect on successful responses (2xx status codes)
        // The server returns 302 redirect for success, 400/500 for errors
        if (event.detail.successful && event.detail.xhr.status >= 200 && event.detail.xhr.status < 300) {
          // If server returns redirect, let HTMX handle it normally
          // Otherwise redirect to list page
          if (event.detail.xhr.status !== 302) {
            window.location.href = '/admin/redirects';
          }
        }
      });

      // Handle form validation errors (4xx, 5xx responses)
      // HTMX will automatically swap the error HTML into #form-messages
      // No additional handling needed - the error stays visible
      document.body.addEventListener('htmx:responseError', function(event) {
        // Only show generic error if no error HTML was returned
        const messagesDiv = document.getElementById('form-messages');
        if (messagesDiv && !messagesDiv.innerHTML.trim()) {
          messagesDiv.innerHTML = '<div class="rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-400 p-4 mb-4"><p class="text-sm">Failed to save redirect. Please check your input and try again.</p></div>';
        }
      });
    </script>
  `
}

/**
 * Render page layout using shared admin layout template
 */
function renderLayout(title: string, content: any): HtmlEscapedString | Promise<HtmlEscapedString> {
  return renderAdminLayoutCatalyst({
    title,
    currentPath: '/admin/redirects',
    content: content.toString()
  }) as HtmlEscapedString
}
