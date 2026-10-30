import { renderAdminLayoutCatalyst } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'

export interface RoleUsagePageData {
  roleName: string
  assignments: Array<{ slug: string; tenantName: string; userId: string; email: string }>
  user?: { name: string; email: string; role: string }
  version?: string
}

export function renderRoleUsage(data: RoleUsagePageData): string {
  const role = escapeHtml(data.roleName)
  const rows = data.assignments.length
    ? data.assignments.map((a) => `
        <tr class="border-b border-zinc-950/5 dark:border-white/5" data-role-assignment="${escapeHtml(a.email)}@${escapeHtml(a.slug)}">
          <td class="px-4 py-3">
            <div class="font-medium text-zinc-950 dark:text-white">${escapeHtml(a.tenantName)}</div>
            <div class="font-mono text-xs text-zinc-500 dark:text-zinc-400">${escapeHtml(a.slug)}</div>
          </td>
          <td class="px-4 py-3 text-sm text-zinc-700 dark:text-zinc-300">${escapeHtml(a.email)}</td>
          <td class="px-4 py-3 text-right">
            <a href="/admin/tenants/users/${escapeHtml(a.userId)}" class="text-sm text-cyan-600 hover:underline dark:text-cyan-400">manage</a>
          </td>
        </tr>`).join('')
    : `<tr><td colspan="3" class="px-4 py-3 text-sm text-zinc-500 dark:text-zinc-400">This role is not assigned in any tenant.</td></tr>`

  const content = `
    <div class="p-6 lg:p-8">
      <div class="mb-2"><a href="/admin/tenants" class="text-sm text-zinc-500 hover:text-zinc-700 dark:text-zinc-400">← Tenants</a></div>
      <div class="mb-8">
        <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Role usage — <span class="font-mono">${role}</span></h1>
        <p class="mt-1 text-sm text-zinc-600 dark:text-zinc-400">Per-tenant assignments of the <span class="font-mono">${role}</span> role. Roles are one shared catalog; this shows who holds it, and in which tenant. Assign or change roles on a user's memberships page or a tenant's members page.</p>
      </div>

      <div class="overflow-hidden rounded-xl border border-zinc-950/5 bg-white shadow-sm dark:border-white/10 dark:bg-zinc-900">
        <table class="w-full text-left">
          <thead>
            <tr class="border-b border-zinc-950/5 text-xs font-medium uppercase tracking-wide text-zinc-500 dark:border-white/5 dark:text-zinc-400">
              <th class="px-4 py-3">Tenant</th>
              <th class="px-4 py-3">User</th>
              <th class="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>`

  return renderAdminLayoutCatalyst({
    title: `Role usage - ${data.roleName} - SonicJS`,
    pageTitle: 'Role usage',
    currentPath: '/admin/tenants',
    user: data.user,
    version: data.version,
    content,
  })
}
