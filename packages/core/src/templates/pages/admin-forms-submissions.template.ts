import {
  renderAdminLayoutCatalyst,
  AdminLayoutCatalystData,
} from '../layouts/admin-layout-catalyst.template'
import { renderTable } from '../components/table.template'
import { escapeHtml } from '../../utils/sanitize'

export interface FormSubmissionRow {
  id: string
  submission_number?: number | null
  submission_data: string
  status?: string | null
  submitted_at: number
}

export interface FormSubmissionsPageData {
  form: {
    id: string
    display_name: string
  }
  submissions: FormSubmissionRow[]
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

/**
 * Render a submission's `submission_data` JSON as an escaped key/value list.
 * `submission_data` holds public, user-supplied form input, so every key and
 * value is passed through escapeHtml — rendering it raw is a stored XSS in the
 * admin UI.
 */
function renderSubmissionData(raw: string): string {
  let data: unknown
  try {
    data = JSON.parse(raw)
  } catch {
    return `<pre class="text-xs whitespace-pre-wrap">${escapeHtml(raw)}</pre>`
  }
  if (typeof data !== 'object' || data === null) {
    return `<pre class="text-xs whitespace-pre-wrap">${escapeHtml(String(data))}</pre>`
  }
  const rows = Object.entries(data as Record<string, unknown>)
    .map(
      ([key, value]) => `
        <div class="flex gap-2 py-0.5">
          <dt class="w-32 shrink-0 font-medium text-zinc-500 dark:text-zinc-400">${escapeHtml(key)}</dt>
          <dd class="text-zinc-900 dark:text-zinc-100 break-words">${escapeHtml(
            typeof value === 'string' ? value : JSON.stringify(value)
          )}</dd>
        </div>`
    )
    .join('')
  return `<dl class="text-sm max-w-xl">${rows}</dl>`
}

export function renderFormSubmissionsPage(data: FormSubmissionsPageData): string {
  const { form, submissions } = data
  const safeName = escapeHtml(form.display_name)

  const tableData: any = {
    tableId: 'form-submissions',
    emptyMessage: 'No submissions yet.',
    columns: [
      {
        key: 'submission_number',
        label: '#',
        sortable: true,
        sortType: 'number',
        render: (value: any) => escapeHtml(String(value ?? '—')),
      },
      {
        key: 'submitted_at',
        label: 'Submitted',
        sortable: true,
        sortType: 'date',
        render: (value: any) =>
          escapeHtml(new Date(Number(value)).toLocaleString()),
      },
      {
        key: 'status',
        label: 'Status',
        sortable: true,
        render: (value: any) => escapeHtml(String(value ?? 'pending')),
      },
      {
        key: 'submission_data',
        label: 'Data',
        render: (value: any) => renderSubmissionData(String(value ?? '')),
      },
    ],
    rows: submissions,
  }

  const content = `
    <div class="mb-6">
      <a href="/admin/forms" class="text-sm text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 transition-colors">&larr; Back to Forms</a>
      <h1 class="mt-2 text-2xl font-semibold text-zinc-950 dark:text-white">Submissions: ${safeName}</h1>
      <p class="mt-1 text-sm text-zinc-500 dark:text-zinc-400">Total submissions: ${submissions.length}</p>
    </div>
    <div class="bg-white dark:bg-zinc-900 rounded-lg border border-zinc-950/5 dark:border-white/10 overflow-hidden">
      ${renderTable(tableData)}
    </div>`

  const layoutData: AdminLayoutCatalystData = {
    title: `Submissions - ${safeName}`,
    pageTitle: `Submissions: ${safeName}`,
    currentPath: '/admin/forms',
    content,
    user: data.user,
    version: data.version,
  }

  return renderAdminLayoutCatalyst(layoutData)
}
