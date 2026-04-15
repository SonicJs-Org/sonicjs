import type { StripeEventRecord, StripeEventStats } from '../types'
import { renderAdminLayoutCatalyst, type AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { renderStripeTabBar } from './tab-bar'

export interface EventsPageData {
  events: StripeEventRecord[]
  stats: StripeEventStats
  types: string[]
  filters: { type?: string; status?: string; page: number; totalPages: number }
  user?: { name: string; email: string; role: string }
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
}

export function renderEventsPage(data: EventsPageData): string {
  const { events, stats, types, filters, user, version, dynamicMenuItems } = data

  const content = `
    <div>
      <div class="sm:flex sm:items-center sm:justify-between mb-6">
        <div class="sm:flex-auto">
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Stripe</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Webhook event log showing all processed, failed, and ignored Stripe events.
          </p>
        </div>
      </div>

      ${renderStripeTabBar('/admin/plugins/stripe/events')}

      <!-- Stats Cards -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-6">
        ${eventStatsCard('Total Events', stats.total, 'text-zinc-950 dark:text-white')}
        ${eventStatsCard('Processed', stats.processed, 'text-emerald-600 dark:text-emerald-400')}
        ${eventStatsCard('Failed', stats.failed, 'text-red-600 dark:text-red-400')}
        ${eventStatsCard('Ignored', stats.ignored, 'text-zinc-500 dark:text-zinc-400')}
      </div>

      <!-- Filters -->
      <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl p-4 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm mb-6">
        <form method="GET" class="flex items-center gap-4 flex-wrap">
          <label class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Type:</label>
          <select name="type" class="rounded-lg border-0 bg-white dark:bg-zinc-800 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10" onchange="this.form.submit()">
            <option value="">All</option>
            ${types.map(t => `<option value="${t}" ${t === filters.type ? 'selected' : ''}>${t}</option>`).join('')}
          </select>

          <label class="text-sm font-medium text-zinc-500 dark:text-zinc-400">Status:</label>
          <select name="status" class="rounded-lg border-0 bg-white dark:bg-zinc-800 px-3 py-1.5 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10" onchange="this.form.submit()">
            <option value="">All</option>
            ${eventStatusOption('processed', filters.status)}
            ${eventStatusOption('failed', filters.status)}
            ${eventStatusOption('ignored', filters.status)}
          </select>
        </form>
      </div>

      <!-- Events Table -->
      <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm overflow-hidden">
        <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/5">
          <thead>
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Time</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Type</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Object / User</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Status</th>
              <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Event ID</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
            ${events.length === 0
              ? '<tr><td colspan="5" class="px-6 py-8 text-center text-zinc-500 dark:text-zinc-400">No events recorded yet</td></tr>'
              : events.map(renderEventRow).join('')
            }
          </tbody>
        </table>

        ${renderEventPagination(filters.page, filters.totalPages, filters.type, filters.status)}
      </div>
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Stripe Events',
    pageTitle: 'Stripe Events',
    currentPath: '/admin/plugins/stripe',
    user,
    content,
    version,
    dynamicMenuItems
  }

  return renderAdminLayoutCatalyst(layoutData)
}

function eventStatsCard(label: string, value: number, colorClass: string): string {
  return `
    <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl p-5 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm">
      <p class="text-sm font-medium text-zinc-500 dark:text-zinc-400">${label}</p>
      <p class="mt-2 text-3xl font-bold ${colorClass}">${value}</p>
    </div>
  `
}

function eventStatusOption(value: string, current?: string): string {
  const selected = value === current ? 'selected' : ''
  const label = value.charAt(0).toUpperCase() + value.slice(1)
  return `<option value="${value}" ${selected}>${label}</option>`
}

function eventStatusBadge(status: string): string {
  const colors: Record<string, string> = {
    processed: 'bg-emerald-400/10 text-emerald-500 dark:text-emerald-400 ring-emerald-400/20',
    failed: 'bg-red-400/10 text-red-500 dark:text-red-400 ring-red-400/20',
    ignored: 'bg-zinc-400/10 text-zinc-500 dark:text-zinc-400 ring-zinc-400/20'
  }
  const color = colors[status] || 'bg-zinc-400/10 text-zinc-500 ring-zinc-400/20'
  return `<span class="inline-flex items-center rounded-full px-2 py-1 text-xs font-medium ring-1 ring-inset ${color}">${status}</span>`
}

function formatTimestamp(timestamp: number): string {
  if (!timestamp) return '-'
  const d = new Date(timestamp * 1000)
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit'
  })
}

function extractUserInfo(event: StripeEventRecord): { userId?: string; email?: string } {
  try {
    const data = typeof event.data === 'string' ? JSON.parse(event.data) : event.data
    const userId = data?.metadata?.sonicjs_user_id || data?.sonicjs_user_id
    const email = data?.customer_email || data?.customerEmail || data?.receipt_email
    return { userId: userId || undefined, email: email || undefined }
  } catch {
    return {}
  }
}

function renderEventRow(event: StripeEventRecord): string {
  const errorTooltip = event.error ? ` title="${event.error.replace(/"/g, '&quot;')}"` : ''
  const userInfo = extractUserInfo(event)
  const userLink = userInfo.userId
    ? `<a href="/admin/users/${userInfo.userId}" class="text-sm text-blue-600 dark:text-blue-400 hover:underline">${userInfo.email || userInfo.userId}</a>`
    : userInfo.email
      ? `<span class="text-sm text-zinc-500 dark:text-zinc-400">${userInfo.email}</span>`
      : ''

  return `
    <tr class="hover:bg-zinc-950/[0.025] dark:hover:bg-white/[0.025]"${errorTooltip}>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-500 dark:text-zinc-400">
        ${formatTimestamp(event.processedAt)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        <span class="text-sm font-mono text-zinc-950 dark:text-white">${event.type}</span>
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        <div class="text-sm font-mono text-zinc-500 dark:text-zinc-400">${event.objectId || '-'}</div>
        <div class="text-xs text-zinc-400 dark:text-zinc-500">${event.objectType}</div>
        ${userLink ? `<div class="mt-1">${userLink}</div>` : ''}
      </td>
      <td class="px-6 py-4 whitespace-nowrap">${eventStatusBadge(event.status)}</td>
      <td class="px-6 py-4 whitespace-nowrap text-xs font-mono text-zinc-400 dark:text-zinc-500">${event.stripeEventId}</td>
    </tr>
  `
}

function renderEventPagination(page: number, totalPages: number, type?: string, status?: string): string {
  if (totalPages <= 1) return ''

  const params: string[] = []
  if (type) params.push(`type=${type}`)
  if (status) params.push(`status=${status}`)
  const extra = params.length > 0 ? `&${params.join('&')}` : ''

  return `
    <div class="px-6 py-3 flex items-center justify-between border-t border-zinc-950/5 dark:border-white/5">
      <div class="text-sm text-zinc-500 dark:text-zinc-400">
        Page ${page} of ${totalPages}
      </div>
      <div class="flex gap-2">
        ${page > 1
          ? `<a href="?page=${page - 1}${extra}" class="px-3 py-1 rounded-lg text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-800">Previous</a>`
          : ''
        }
        ${page < totalPages
          ? `<a href="?page=${page + 1}${extra}" class="px-3 py-1 rounded-lg text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-800">Next</a>`
          : ''
        }
      </div>
    </div>
  `
}
