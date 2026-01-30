import { html } from 'hono/html'
import type { HtmlEscapedString } from 'hono/utils/html'
import type { Redirect, MatchType, StatusCode } from '../types'

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
  const formMethod = isEdit ? 'put' : 'post'

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
                <option value="1" ${redirect?.matchType === 1 ? 'selected' : ''}>Partial</option>
                <option value="2" ${redirect?.matchType === 2 ? 'selected' : ''}>Regex</option>
              </select>
              <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
                Exact: URL must match exactly. Partial: Matches URLs starting with source. Regex: Pattern matching.
              </p>
            </div>
          </div>

          <!-- Section 3: Options -->
          <div class="pb-8">
            <h2 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">
              Options
            </h2>

            <!-- Include Query Params -->
            <div class="mb-4">
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="include_query_params"
                  value="1"
                  ${redirect?.includeQueryParams ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Include Query Params</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Match query parameters in source URL
                  </span>
                </span>
              </label>
            </div>

            <!-- Preserve Query Params -->
            <div class="mb-4">
              <label class="flex items-start">
                <input
                  type="checkbox"
                  name="preserve_query_params"
                  value="1"
                  ${redirect?.preserveQueryParams ? 'checked' : ''}
                  class="mt-0.5 h-4 w-4 rounded border-zinc-300 dark:border-zinc-700 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="ml-2 block">
                  <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">Preserve Query Params</span>
                  <span class="mt-1 block text-xs text-zinc-500 dark:text-zinc-400">
                    Append original query parameters to destination
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
 * Render page layout
 */
function renderLayout(title: string, content: any): HtmlEscapedString | Promise<HtmlEscapedString> {
  return html`
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>${title} - SonicJS</title>
      <script src="https://cdn.tailwindcss.com"></script>
      <script>tailwind.config = { darkMode: 'class', theme: { extend: { colors: { zinc: { 50: '#fafafa', 100: '#f4f4f5', 200: '#e4e4e7', 300: '#d4d4d8', 400: '#a1a1aa', 500: '#71717a', 600: '#52525b', 700: '#3f3f46', 800: '#27272a', 900: '#18181b', 950: '#09090b' } } } } }</script>
      <style>@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap'); body { font-family: 'Inter', sans-serif; }</style>
    </head>
    <body class="min-h-screen bg-white dark:bg-zinc-900">
      <div class="relative isolate flex min-h-svh w-full max-lg:flex-col lg:bg-zinc-100 dark:lg:bg-zinc-950">
        <div class="fixed inset-y-0 left-0 w-64 max-lg:hidden">
          <nav class="flex h-full min-h-0 flex-col bg-white shadow-sm ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:ring-white/10">
            <div class="flex flex-col border-b border-zinc-950/5 p-4 dark:border-white/5">
              <a href="/admin" class="flex items-center gap-2 font-bold text-xl dark:text-white">SonicJS</a>
            </div>
            <div class="flex flex-1 flex-col overflow-y-auto p-4 gap-0.5">
               <a href="/admin" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Dashboard</a>
               <a href="/admin/collections" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Collections</a>
               <a href="/admin/content" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Content</a>
               <a href="/admin/media" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Media</a>
               <a href="/admin/users" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Users</a>
               <a href="/admin/redirects" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 bg-zinc-100 dark:bg-zinc-800 dark:text-white">
                 <span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500"></span>
                 Redirects
               </a>
               <a href="/admin/plugins" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Plugins</a>
            </div>
             <div class="border-t border-zinc-950/5 p-4 dark:border-white/5">
               <a href="/admin/settings" class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-sm font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">Settings</a>
             </div>
          </nav>
        </div>
        <main class="flex flex-1 flex-col pb-2 lg:min-w-0 lg:pl-64 lg:pr-2">
          <div class="grow p-6 lg:rounded-lg lg:bg-white lg:p-10 lg:shadow-sm lg:ring-1 lg:ring-zinc-950/5 dark:lg:bg-zinc-900 dark:lg:ring-white/10">
            ${content}
          </div>
        </main>
      </div>
    </body>
    </html>
  `
}
