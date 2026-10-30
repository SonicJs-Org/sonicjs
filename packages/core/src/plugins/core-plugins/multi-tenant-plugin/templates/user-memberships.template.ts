import { renderAdminLayoutCatalyst } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import { VALID_MEMBER_ROLES } from '../services/tenant-service'

export interface UserMembershipsPageData {
  userId: string
  userEmail: string
  memberships: Array<{ slug: string; name: string; role: string }>
  /** Tenants the user is NOT yet a member of (for the add picker). */
  availableTenants: Array<{ slug: string; name: string }>
  user?: { name: string; email: string; role: string }
  version?: string
  message?: string
  messageType?: 'success' | 'error'
}

function roleOptions(selected: string): string {
  return VALID_MEMBER_ROLES.map(
    (r) => `<option value="${r}" ${r === selected ? 'selected' : ''}>${r}</option>`,
  ).join('')
}

export function renderUserMemberships(data: UserMembershipsPageData): string {
  const uid = escapeHtml(data.userId)
  const alert = data.message
    ? `<div data-memberships-alert class="mb-6 rounded-lg border px-4 py-3 text-sm ${
        data.messageType === 'error'
          ? 'border-red-500/20 bg-red-500/10 text-red-700 dark:text-red-400'
          : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
      }">${escapeHtml(data.message)}</div>`
    : ''

  const rows = data.memberships.length
    ? data.memberships.map((m) => {
        const slug = escapeHtml(m.slug)
        return `
        <tr data-membership-row="${slug}" class="border-b border-zinc-950/5 dark:border-white/5">
          <td class="px-4 py-3">
            <div class="font-medium text-zinc-950 dark:text-white">${escapeHtml(m.name)}</div>
            <div class="font-mono text-xs text-zinc-500 dark:text-zinc-400">${slug}</div>
          </td>
          <td class="px-4 py-3">
            <form method="POST" action="/admin/tenants/users/${uid}/memberships/${slug}/role" class="flex items-center gap-2">
              <select name="role" data-membership-role onchange="this.form.requestSubmit ? this.form.requestSubmit() : this.form.submit()"
                class="rounded-lg border border-zinc-950/10 bg-white px-2 py-1.5 text-sm text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white">
                ${roleOptions(m.role)}
              </select>
            </form>
          </td>
          <td class="px-4 py-3 text-right">
            <form method="POST" action="/admin/tenants/users/${uid}/memberships/${slug}/delete" class="inline"
              onsubmit="return confirm('Remove this user from ${slug}?')">
              <button type="submit" data-remove-membership="${slug}" class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-red-600 hover:bg-red-500/10 dark:text-red-400">Remove</button>
            </form>
          </td>
        </tr>`
      }).join('')
    : `<tr><td colspan="3" class="px-4 py-3 text-sm text-zinc-500 dark:text-zinc-400">Not a member of any tenant.</td></tr>`

  const addForm = data.availableTenants.length
    ? `<form method="POST" action="/admin/tenants/users/${uid}/memberships" class="flex flex-wrap items-end gap-3" data-add-membership-form>
        <div class="flex-1 min-w-[14rem]">
          <label for="membership-tenant" class="mb-1 block text-xs font-medium text-zinc-500 dark:text-zinc-400">Tenant</label>
          <select id="membership-tenant" name="slug" class="w-full rounded-lg border border-zinc-950/10 bg-white px-2 py-2 text-sm text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white">
            ${data.availableTenants.map((t) => `<option value="${escapeHtml(t.slug)}">${escapeHtml(t.name)}</option>`).join('')}
          </select>
        </div>
        <div>
          <label for="membership-role" class="mb-1 block text-xs font-medium text-zinc-500 dark:text-zinc-400">Role</label>
          <select id="membership-role" name="role" class="rounded-lg border border-zinc-950/10 bg-white px-2 py-2 text-sm text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white">
            ${roleOptions('viewer')}
          </select>
        </div>
        <button type="submit" data-add-membership class="rounded-lg bg-zinc-950 px-3.5 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-950 dark:hover:bg-zinc-200">Add to tenant</button>
      </form>`
    : `<p class="text-sm text-zinc-500 dark:text-zinc-400">This user is already a member of every tenant.</p>`

  const content = `
    <div class="p-6 lg:p-8">
      <div class="mb-2"><a href="/admin/users/${uid}/edit" class="text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400">← Back to user</a></div>
      <div class="mb-8">
        <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Tenant memberships</h1>
        <p class="mt-1 text-sm text-zinc-600 dark:text-zinc-400">Tenants <span class="font-medium">${escapeHtml(data.userEmail)}</span> belongs to, and their role within each. Role is per-tenant — a user can be admin in one tenant and viewer in another.</p>
      </div>

      ${alert}

      <div class="mb-6 rounded-xl border border-zinc-950/5 bg-white p-4 shadow-sm dark:border-white/10 dark:bg-zinc-900">
        ${addForm}
      </div>

      <div class="overflow-hidden rounded-xl border border-zinc-950/5 bg-white shadow-sm dark:border-white/10 dark:bg-zinc-900">
        <table class="w-full text-left">
          <thead>
            <tr class="border-b border-zinc-950/5 text-xs font-medium uppercase tracking-wide text-zinc-500 dark:border-white/5 dark:text-zinc-400">
              <th class="px-4 py-3">Tenant</th>
              <th class="px-4 py-3">Role</th>
              <th class="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`

  return renderAdminLayoutCatalyst({
    title: `Tenant memberships - ${data.userEmail} - SonicJS`,
    pageTitle: 'Tenant memberships',
    currentPath: '/admin/users',
    user: data.user,
    version: data.version,
    content,
  })
}
