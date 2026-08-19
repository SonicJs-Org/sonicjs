import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderTable } from '../components/table.template'
import { escapeHtml } from '../../utils/sanitize'

export interface Form {
  id: string
  name: string
  display_name: string
  description?: string
  category: string
  submission_count: number
  is_active: boolean
  is_public: boolean
  created_at: number
  formattedDate: string
}

export interface FormsListPageData {
  forms: Form[]
  search?: string
  category?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderFormsListPage(data: FormsListPageData): string {
  const tableData: any = {
    tableId: 'forms-table',
    rowClickable: true,
    rowClickUrl: (form: Form) => `/admin/forms/${form.id}/builder`,
    columns: [
      {
        key: 'name',
        label: 'Name',
        sortable: true,
        sortType: 'string',
        render: (_value: any, form: any) => `
            <div class="flex items-center gap-2 ml-2">
                <span class="inline-flex items-center rounded-md bg-cyan-50 dark:bg-cyan-500/10 px-2.5 py-1 text-sm font-medium text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-400/20">
                  ${escapeHtml(form.name)}
                </span>
            </div>
          `
      },
      {
        key: 'display_name',
        label: 'Display Name',
        sortable: true,
        sortType: 'string',
        render: (_value: any, form: any) => escapeHtml(form.display_name)
      },
      {
        key: 'category',
        label: 'Category',
        sortable: true,
        sortType: 'string',
        render: (_value: any, form: any) => {
          const categoryColors: Record<string, string> = {
            'contact': 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 ring-blue-700/10 dark:ring-blue-400/20',
            'survey': 'bg-purple-50 dark:bg-purple-500/10 text-purple-700 dark:text-purple-300 ring-purple-700/10 dark:ring-purple-400/20',
            'registration': 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-300 ring-green-700/10 dark:ring-green-400/20',
            'feedback': 'bg-orange-50 dark:bg-orange-500/10 text-orange-700 dark:text-orange-300 ring-orange-700/10 dark:ring-orange-400/20',
            'general': 'bg-gray-50 dark:bg-gray-500/10 text-gray-700 dark:text-gray-300 ring-gray-700/10 dark:ring-gray-400/20'
          }
          const colorClass = categoryColors[form.category] || categoryColors['general']
          return `
            <span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset ${colorClass}">
              ${escapeHtml(form.category || 'general')}
            </span>
          `
        }
      },
      {
        key: 'submission_count',
        label: 'Submissions',
        sortable: true,
        sortType: 'number',
        render: (_value: any, form: any) => {
          const count = form.submission_count || 0
          return `
            <div class="flex items-center">
              <span class="inline-flex items-center rounded-md bg-pink-50 dark:bg-pink-500/10 px-2.5 py-1 text-sm font-medium text-pink-700 dark:text-pink-300 ring-1 ring-inset ring-pink-700/10 dark:ring-pink-400/20">
                ${count}
              </span>
            </div>
          `
        }
      },
      {
        key: 'is_active',
        label: 'Status',
        sortable: true,
        sortType: 'string',
        render: (_value: any, form: any) => {
          if (form.is_active) {
            return `
              <span class="inline-flex items-center rounded-md bg-green-50 dark:bg-green-500/10 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-300 ring-1 ring-inset ring-green-700/10 dark:ring-green-400/20">
                Active
              </span>
            `
          } else {
            return `
              <span class="inline-flex items-center rounded-md bg-gray-50 dark:bg-gray-500/10 px-2 py-1 text-xs font-medium text-gray-700 dark:text-gray-300 ring-1 ring-inset ring-gray-700/10 dark:ring-gray-400/20">
                Inactive
              </span>
            `
          }
        }
      },
      {
        key: 'formattedDate',
        label: 'Created',
        sortable: true,
        sortType: 'date'
      },
      {
        key: 'actions',
        label: 'Actions',
        sortable: false,
        render: (_value: any, form: any) => {
          if (!form || !form.id) return '<span class="text-zinc-500 dark:text-zinc-400">-</span>'
          return `
            <div class="flex items-center space-x-2">
              <a href="/admin/forms/${form.id}/builder" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-lg bg-zinc-950 dark:bg-white text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors" title="Edit Form">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>
                </svg>
              </a>
              <a href="/forms/${form.name}" target="_blank" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-lg bg-green-600 text-white hover:bg-green-700 transition-colors" title="View Public Form">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
                </svg>
              </a>
              <a href="/admin/forms/${form.id}/submissions" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors" title="View Submissions">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
                </svg>
              </a>
            </div>
          `
        }
      }
    ],
    rows: data.forms,
    emptyMessage: 'No forms found. Create your first form to get started!'
  }

  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Forms</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Create and manage forms with the visual form builder</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 flex flex-wrap items-center gap-3">
          <!-- Documentation Links -->
          <a href="/admin/forms/examples" class="inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors" title="View interactive examples">
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>
            </svg>
            Examples
          </a>
          <a href="/admin/forms/docs" class="inline-flex items-center px-4 py-2 text-sm font-medium rounded-lg bg-purple-600 text-white hover:bg-purple-700 transition-colors" title="Quick reference guide">
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
            </svg>
            Quick Reference
          </a>
          <a href="/admin/forms/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-4 py-2 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="w-4 h-4 mr-2" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            Create Form
          </a>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-3 mb-6">
        <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-950/5 dark:border-white/10 p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0">
              <svg class="h-8 w-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400 truncate">Total Forms</dt>
                <dd class="text-2xl font-semibold text-zinc-900 dark:text-white">${data.forms.length}</dd>
              </dl>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-950/5 dark:border-white/10 p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0">
              <svg class="h-8 w-8 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400 truncate">Active Forms</dt>
                <dd class="text-2xl font-semibold text-zinc-900 dark:text-white">${data.forms.filter(f => f.is_active).length}</dd>
              </dl>
            </div>
          </div>
        </div>

        <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-950/5 dark:border-white/10 p-6">
          <div class="flex items-center">
            <div class="flex-shrink-0">
              <svg class="h-8 w-8 text-pink-600 dark:text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
              </svg>
            </div>
            <div class="ml-5 w-0 flex-1">
              <dl>
                <dt class="text-sm font-medium text-zinc-500 dark:text-zinc-400 truncate">Total Submissions</dt>
                <dd class="text-2xl font-semibold text-zinc-900 dark:text-white">${data.forms.reduce((sum, f) => sum + (f.submission_count || 0), 0)}</dd>
              </dl>
            </div>
          </div>
        </div>
      </div>

      <!-- Filters -->
      <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-950/5 dark:border-white/10 p-4 mb-6">
        <form class="flex flex-col sm:flex-row gap-4" method="get" action="/admin/forms">
          <div class="flex-1">
            <input
              type="text"
              name="search"
              placeholder="Search forms..."
              value="${escapeHtml(data.search || '')}"
              class="block w-full rounded-lg border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-white placeholder-zinc-500 dark:placeholder-zinc-400 focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            />
          </div>
          <div class="w-full sm:w-48">
            <select
              name="category"
              class="block w-full rounded-lg border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-white focus:border-blue-500 focus:ring-blue-500 sm:text-sm"
            >
              <option value="">All Categories</option>
              <option value="contact" ${data.category === 'contact' ? 'selected' : ''}>Contact</option>
              <option value="survey" ${data.category === 'survey' ? 'selected' : ''}>Survey</option>
              <option value="registration" ${data.category === 'registration' ? 'selected' : ''}>Registration</option>
              <option value="feedback" ${data.category === 'feedback' ? 'selected' : ''}>Feedback</option>
              <option value="general" ${data.category === 'general' ? 'selected' : ''}>General</option>
            </select>
          </div>
          <button
            type="submit"
            class="inline-flex items-center justify-center rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition-colors"
          >
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
            </svg>
            Filter
          </button>
          ${data.search || data.category ? `
            <a
              href="/admin/forms"
              class="inline-flex items-center justify-center rounded-lg bg-zinc-200 dark:bg-zinc-700 px-4 py-2 text-sm font-semibold text-zinc-900 dark:text-white hover:bg-zinc-300 dark:hover:bg-zinc-600 transition-colors"
            >
              Clear
            </a>
          ` : ''}
        </form>
      </div>

      <!-- Forms Table -->
      <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-950/5 dark:border-white/10 overflow-hidden">
        ${renderTable(tableData)}
      </div>
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Forms',
    content: pageContent,
    user: data.user,
    version: data.version
  }

  return renderAdminLayoutCatalyst(layoutData)
}
