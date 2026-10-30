import { renderAdminLayoutCatalyst } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import type { TenantData } from '../services/tenant-service'

export interface TenantsListPageData {
  tenants: Array<TenantData & { documentCount: number; memberCount: number }>
  currentTenantId: string
  user?: { name: string; email: string; role: string }
  version?: string
  message?: string
  messageType?: 'success' | 'error'
}

function statusBadge(status: string): string {
  return status === 'active'
    ? '<span class="inline-flex items-center rounded-md bg-emerald-500/10 px-2 py-1 text-xs font-medium text-emerald-600 dark:text-emerald-400">Active</span>'
    : '<span class="inline-flex items-center rounded-md bg-zinc-500/10 px-2 py-1 text-xs font-medium text-zinc-600 dark:text-zinc-400">Inactive</span>'
}

function renderRow(tenant: TenantData & { documentCount: number; memberCount: number }, currentTenantId: string): string {
  const slug = escapeHtml(tenant.slug)
  const isCurrent = tenant.slug === currentTenantId
  const isDefault = tenant.slug === 'default'
  return `
    <tr data-tenant-row="${slug}" class="border-b border-zinc-950/5 dark:border-white/5">
      <td class="px-4 py-3">
        <div class="flex items-center gap-2">
          <span class="font-medium text-zinc-950 dark:text-white">${escapeHtml(tenant.name)}</span>
          ${isCurrent ? '<span data-current-tenant-badge class="inline-flex items-center rounded-md bg-cyan-500/10 px-2 py-0.5 text-xs font-medium text-cyan-600 dark:text-cyan-400">Current</span>' : ''}
        </div>
      </td>
      <td class="px-4 py-3 font-mono text-sm text-zinc-600 dark:text-zinc-400">${slug}</td>
      <td class="px-4 py-3 text-sm text-zinc-600 dark:text-zinc-400">${tenant.domain ? escapeHtml(tenant.domain) : '—'}</td>
      <td class="px-4 py-3">${statusBadge(tenant.status)}</td>
      <td class="px-4 py-3 text-sm text-zinc-600 dark:text-zinc-400" data-tenant-doc-count>${tenant.documentCount}</td>
      <td class="px-4 py-3 text-sm text-zinc-600 dark:text-zinc-400" data-tenant-member-count>${tenant.memberCount}</td>
      <td class="px-4 py-3">
        <div class="flex items-center justify-end gap-2">
          ${
            !isCurrent && tenant.status === 'active'
              ? `<form method="POST" action="/admin/tenants/switch" class="inline">
                   <input type="hidden" name="tenant" value="${slug}">
                   <input type="hidden" name="redirect" value="/admin/tenants">
                   <button type="submit" data-switch-tenant="${slug}" class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-cyan-600 hover:bg-cyan-500/10 dark:text-cyan-400">Switch</button>
                 </form>`
              : ''
          }
          <a href="/admin/tenants/${slug}/members" data-members-tenant="${slug}" class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-zinc-600 hover:bg-zinc-950/5 dark:text-zinc-400 dark:hover:bg-white/5">Members</a>
          <a href="/admin/tenants/${slug}/edit" data-edit-tenant="${slug}" class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-zinc-600 hover:bg-zinc-950/5 dark:text-zinc-400 dark:hover:bg-white/5">Edit</a>
          ${
            !isDefault
              ? `<form method="POST" action="/admin/tenants/${slug}/delete" class="inline" onsubmit="return confirm('Delete tenant ${slug}? This only works while the tenant owns no documents.')">
                   <button type="submit" data-delete-tenant="${slug}" class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-red-600 hover:bg-red-500/10 dark:text-red-400">Delete</button>
                 </form>`
              : ''
          }
        </div>
      </td>
    </tr>`
}

export function renderTenantsList(data: TenantsListPageData): string {
  const alert = data.message
    ? `<div data-tenants-alert class="mb-6 rounded-lg border px-4 py-3 text-sm ${
        data.messageType === 'error'
          ? 'border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-400'
          : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
      }">${escapeHtml(data.message)}</div>`
    : ''

  const content = `
    <div class="p-6 lg:p-8">
      <div class="mb-8 flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Tenants</h1>
          <p class="mt-1 text-sm text-zinc-600 dark:text-zinc-400">Isolated content spaces served from this SonicJS instance. The sidebar switcher and this page control which tenant the admin operates on.</p>
        </div>
        <a href="/admin/tenants/new" data-new-tenant class="inline-flex items-center gap-2 rounded-lg bg-zinc-950 px-3.5 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-950 dark:hover:bg-zinc-200">
          <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.5v15m7.5-7.5h-15"/></svg>
          New Tenant
        </a>
      </div>

      ${alert}

      <div class="overflow-hidden rounded-xl border border-zinc-950/5 bg-white shadow-sm dark:border-white/10 dark:bg-zinc-900">
        <table class="w-full text-left">
          <thead>
            <tr class="border-b border-zinc-950/5 text-xs font-medium uppercase tracking-wide text-zinc-500 dark:border-white/5 dark:text-zinc-400">
              <th class="px-4 py-3">Name</th>
              <th class="px-4 py-3">Slug</th>
              <th class="px-4 py-3">Domain</th>
              <th class="px-4 py-3">Status</th>
              <th class="px-4 py-3">Documents</th>
              <th class="px-4 py-3">Members</th>
              <th class="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            ${data.tenants.map(t => renderRow(t, data.currentTenantId)).join('')}
          </tbody>
        </table>
      </div>
    </div>`

  return renderAdminLayoutCatalyst({
    title: 'Tenants - SonicJS',
    pageTitle: 'Tenants',
    currentPath: '/admin/tenants',
    user: data.user,
    version: data.version,
    content,
  })
}

/** Rendered when the multi-tenant plugin is installed but not active (routes self-gate). */
export function renderTenantsInactive(data: { user?: { name: string; email: string; role: string }; version?: string }): string {
  const content = `
    <div class="p-6 lg:p-8">
      <div class="mx-auto max-w-xl rounded-xl border border-zinc-950/5 bg-white p-8 text-center shadow-sm dark:border-white/10 dark:bg-zinc-900" data-tenants-inactive>
        <span class="text-4xl">🏢</span>
        <h1 class="mt-4 text-xl font-semibold text-zinc-950 dark:text-white">Multi-Tenant plugin is not active</h1>
        <p class="mt-2 text-sm text-zinc-600 dark:text-zinc-400">Tenant management is available once the Multi-Tenant plugin is installed and activated.</p>
        <a href="/admin/plugins" class="mt-6 inline-flex items-center rounded-lg bg-zinc-950 px-3.5 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-950 dark:hover:bg-zinc-200">Go to Plugins</a>
      </div>
    </div>`

  return renderAdminLayoutCatalyst({
    title: 'Tenants - SonicJS',
    pageTitle: 'Tenants',
    currentPath: '/admin/tenants',
    user: data.user,
    version: data.version,
    content,
  })
}
