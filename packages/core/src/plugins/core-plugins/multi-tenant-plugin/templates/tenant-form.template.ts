import { renderAdminLayoutCatalyst } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import type { TenantData } from '../services/tenant-service'

export interface TenantFormPageData {
  tenant?: Partial<TenantData>
  isEdit: boolean
  user?: { name: string; email: string; role: string }
  version?: string
  errors?: Record<string, string[]>
  message?: string
  messageType?: 'success' | 'error'
}

function fieldErrors(errors: Record<string, string[]> | undefined, field: string): string {
  const list = errors?.[field]
  if (!list || list.length === 0) return ''
  return `<div class="mt-1" data-field-error="${escapeHtml(field)}">${list.map(e => `<p class="text-sm text-red-500">${escapeHtml(e)}</p>`).join('')}</div>`
}

export function renderTenantForm(data: TenantFormPageData): string {
  const t = data.tenant ?? {}
  const isDefault = data.isEdit && t.slug === 'default'
  const action = data.isEdit ? `/admin/tenants/${escapeHtml(t.slug ?? '')}` : '/admin/tenants'
  const inputClass = 'w-full rounded-lg border border-zinc-950/10 bg-white px-3 py-2 text-sm text-zinc-950 placeholder-zinc-400 dark:border-white/10 dark:bg-zinc-800 dark:text-white'
  const labelClass = 'mb-1 block text-sm font-medium text-zinc-950 dark:text-white'

  const alert = data.message
    ? `<div data-tenant-form-alert class="mb-6 rounded-lg border px-4 py-3 text-sm ${
        data.messageType === 'error'
          ? 'border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-400'
          : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
      }">${escapeHtml(data.message)}</div>`
    : ''

  const content = `
    <div class="p-6 lg:p-8">
      <div class="mx-auto max-w-2xl">
        <div class="mb-8">
          <a href="/admin/tenants" class="text-sm text-zinc-600 hover:text-zinc-950 dark:text-zinc-400 dark:hover:text-white">&larr; Back to Tenants</a>
          <h1 class="mt-2 text-2xl font-semibold text-zinc-950 dark:text-white">${data.isEdit ? `Edit Tenant: ${escapeHtml(t.name ?? t.slug ?? '')}` : 'New Tenant'}</h1>
        </div>

        ${alert}

        <form method="POST" action="${action}" data-tenant-form class="space-y-6 rounded-xl border border-zinc-950/5 bg-white p-6 shadow-sm dark:border-white/10 dark:bg-zinc-900">
          <div>
            <label for="tenant-name" class="${labelClass}">Name</label>
            <input id="tenant-name" name="name" type="text" required value="${escapeHtml(t.name ?? '')}" placeholder="Acme Inc" class="${inputClass}">
            ${fieldErrors(data.errors, 'name')}
          </div>

          <div>
            <label for="tenant-slug" class="${labelClass}">Slug</label>
            <input id="tenant-slug" name="slug" type="text" ${data.isEdit ? 'readonly disabled' : 'required'} value="${escapeHtml(t.slug ?? '')}" placeholder="acme"
              pattern="[a-z0-9][a-z0-9-]*" class="${inputClass} ${data.isEdit ? 'opacity-60' : ''}">
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Lowercase letters, numbers and hyphens. Identifies the tenant in the API header and subdomains. Cannot be changed later.</p>
            ${fieldErrors(data.errors, 'slug')}
          </div>

          <div>
            <label for="tenant-domain" class="${labelClass}">Domain <span class="font-normal text-zinc-500">(optional)</span></label>
            <input id="tenant-domain" name="domain" type="text" value="${escapeHtml(t.domain ?? '')}" placeholder="acme.example.com" class="${inputClass}">
            <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Requests with this exact Host resolve to this tenant.</p>
            ${fieldErrors(data.errors, 'domain')}
          </div>

          ${
            data.isEdit && !isDefault
              ? `<div>
                  <label for="tenant-status" class="${labelClass}">Status</label>
                  <select id="tenant-status" name="status" class="${inputClass}">
                    <option value="active" ${t.status !== 'inactive' ? 'selected' : ''}>Active</option>
                    <option value="inactive" ${t.status === 'inactive' ? 'selected' : ''}>Inactive</option>
                  </select>
                  <p class="mt-1 text-xs text-zinc-500 dark:text-zinc-400">Inactive tenants stop resolving for requests; their data is kept.</p>
                </div>`
              : ''
          }

          <div>
            <label for="tenant-notes" class="${labelClass}">Notes <span class="font-normal text-zinc-500">(optional)</span></label>
            <textarea id="tenant-notes" name="notes" rows="3" class="${inputClass}">${escapeHtml(t.notes ?? '')}</textarea>
          </div>

          <div class="flex items-center justify-end gap-3 border-t border-zinc-950/5 pt-4 dark:border-white/5">
            <a href="/admin/tenants" class="rounded-lg px-3.5 py-2 text-sm font-medium text-zinc-600 hover:bg-zinc-950/5 dark:text-zinc-400 dark:hover:bg-white/5">Cancel</a>
            <button type="submit" data-save-tenant class="rounded-lg bg-zinc-950 px-3.5 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-950 dark:hover:bg-zinc-200">
              ${data.isEdit ? 'Save Changes' : 'Create Tenant'}
            </button>
          </div>
        </form>
      </div>
    </div>`

  return renderAdminLayoutCatalyst({
    title: `${data.isEdit ? 'Edit Tenant' : 'New Tenant'} - SonicJS`,
    pageTitle: data.isEdit ? 'Edit Tenant' : 'New Tenant',
    currentPath: '/admin/tenants',
    user: data.user,
    version: data.version,
    content,
  })
}
