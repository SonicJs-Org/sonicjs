import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderAlert } from '../alert.template'
import { renderConfirmationDialog, getConfirmationDialogScript } from '../components/confirmation-dialog.template'
import { escapeHtml } from '../../utils/sanitize'

export interface UserProfileData {
  displayName?: string
}

export interface UserEditData {
  id: string
  email: string
  firstName: string
  lastName: string
  phone?: string
  avatarUrl?: string
  role: string
  isActive: boolean
  emailVerified: boolean
  twoFactorEnabled: boolean
  createdAt: number
  lastLoginAt?: number
  profile?: UserProfileData
}

export interface UserEditPageData {
  userToEdit: UserEditData
  roles: Array<{ value: string; label: string }>
  error?: string
  success?: string
  /** True only when developer has called defineUserProfile() in the app entry point. */
  hasProfilePlugin?: boolean
  customProfileFieldsHtml?: string
  /** When the multi-tenant plugin is active: inline membership matrix data. */
  tenantMemberships?: {
    memberships: Array<{ slug: string; name: string; role: string }>
    availableTenants: Array<{ slug: string; name: string }>
    memberRoles: string[]
  }
  user?: {
    name: string
    email: string
    role: string
  }
}

function renderTenantMembershipsSection(
  userId: string,
  tm?: UserEditPageData['tenantMemberships'],
): string {
  if (!tm) return ''
  const uid = escapeHtml(userId)
  const redirectField = `<input type="hidden" name="_redirect" value="/admin/users/${uid}/edit">`
  const count = tm.memberships.length

  const rows = count
    ? tm.memberships.map((m) => {
        const slug = escapeHtml(m.slug)
        const roleOpts = tm.memberRoles
          .map((r) => `<option value="${r}" ${r === m.role ? 'selected' : ''}>${r}</option>`)
          .join('')
        return `
        <tr data-membership-row="${slug}" class="border-b border-zinc-950/5 last:border-0 dark:border-white/5">
          <td class="px-4 py-3">
            <div class="font-medium text-zinc-950 dark:text-white">${escapeHtml(m.name)}</div>
            <div class="font-mono text-xs text-zinc-500 dark:text-zinc-400">${slug}</div>
          </td>
          <td class="px-4 py-3">
            <form method="POST" action="/admin/tenants/users/${uid}/memberships/${slug}/role" class="flex items-center gap-2">
              ${redirectField}
              <select name="role" onchange="this.form.requestSubmit ? this.form.requestSubmit() : this.form.submit()"
                class="rounded-lg border border-zinc-950/10 bg-white px-2 py-1.5 text-sm text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white">
                ${roleOpts}
              </select>
            </form>
          </td>
          <td class="px-4 py-3 text-right">
            <form method="POST" action="/admin/tenants/users/${uid}/memberships/${slug}/delete" class="inline"
              onsubmit="return confirm('Remove this user from ${slug}?')">
              ${redirectField}
              <button type="submit" data-remove-membership="${slug}" class="rounded-lg px-2.5 py-1.5 text-sm font-medium text-red-600 hover:bg-red-500/10 dark:text-red-400">Remove</button>
            </form>
          </td>
        </tr>`
      }).join('')
    : `<tr><td colspan="3" class="px-4 py-6 text-sm text-zinc-500 text-center dark:text-zinc-400">Not a member of any tenant.</td></tr>`

  const addForm = tm.availableTenants.length
    ? `<div class="mt-4 border-t border-zinc-950/5 pt-4 dark:border-white/5">
        <form method="POST" action="/admin/tenants/users/${uid}/memberships" class="flex flex-wrap items-end gap-3">
          ${redirectField}
          <div class="flex-1 min-w-[12rem]">
            <label class="mb-1 block text-xs font-medium text-zinc-500 dark:text-zinc-400">Add to tenant</label>
            <select name="slug" class="w-full rounded-lg border border-zinc-950/10 bg-white px-2 py-2 text-sm text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white">
              ${tm.availableTenants.map((t) => `<option value="${escapeHtml(t.slug)}">${escapeHtml(t.name)}</option>`).join('')}
            </select>
          </div>
          <div>
            <label class="mb-1 block text-xs font-medium text-zinc-500 dark:text-zinc-400">Role</label>
            <select name="role" class="rounded-lg border border-zinc-950/10 bg-white px-2 py-2 text-sm text-zinc-950 dark:border-white/10 dark:bg-zinc-800 dark:text-white">
              ${tm.memberRoles.map((r) => `<option value="${r}" ${r === 'viewer' ? 'selected' : ''}>${r}</option>`).join('')}
            </select>
          </div>
          <button type="submit" class="rounded-lg bg-zinc-950 px-3.5 py-2 text-sm font-semibold text-white hover:bg-zinc-800 dark:bg-white dark:text-zinc-950 dark:hover:bg-zinc-200">Add</button>
        </form>
      </div>`
    : `<p class="mt-4 text-sm text-zinc-500 dark:text-zinc-400">Member of all tenants.</p>`

  const defaultOpen = count <= 5
  return `
    <details class="group mt-6" ${defaultOpen ? 'open' : ''} data-tenant-memberships>
      <summary class="flex cursor-pointer list-none items-center justify-between rounded-xl bg-white px-6 py-4 shadow-sm ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:ring-white/10 select-none">
        <div class="flex items-center gap-3">
          <svg class="h-4 w-4 text-zinc-400 transition-transform group-open:rotate-90 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/></svg>
          <h3 class="text-base font-semibold text-zinc-950 dark:text-white">Tenant memberships</h3>
        </div>
        <span class="text-sm font-normal text-zinc-500 dark:text-zinc-400">${count} tenant${count !== 1 ? 's' : ''}</span>
      </summary>
      <div class="mt-1 rounded-xl bg-white shadow-sm ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:ring-white/10">
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
        <div class="px-4 pb-4">${addForm}</div>
      </div>
    </details>`
}

export function renderUserEditPage(data: UserEditPageData): string {
  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <div class="flex items-center gap-3 mb-2">
            <a href="/admin/users" class="text-zinc-500 dark:text-zinc-400 hover:text-zinc-950 dark:hover:text-white transition-colors">
              <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
              </svg>
            </a>
            <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Edit User</h1>
          </div>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Update user account and permissions</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none flex space-x-3">
          <button
            type="submit"
            form="user-edit-form"
            class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm"
          >
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
            </svg>
            Save Changes
          </button>
          <a
            href="/admin/users"
            class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm"
          >
            Cancel
          </a>
        </div>
      </div>

      <!-- Alert Messages -->
      <div id="form-messages" class="mb-6 empty:mb-0">
        ${data.error ? renderAlert({ type: 'error', message: data.error, dismissible: true }) : ''}
        ${data.success ? renderAlert({ type: 'success', message: data.success, dismissible: true }) : ''}
      </div>

      <!-- User Edit Form -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Main Form -->
        <div class="lg:col-span-2">
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-8">
            <form id="user-edit-form" hx-put="/admin/users/${data.userToEdit.id}" hx-target="#form-messages">

              <!-- Basic Information -->
              <div class="mb-8">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Basic Information</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">First Name</label>
                    <input
                      type="text"
                      name="first_name"
                      value="${escapeHtml(data.userToEdit.firstName || '')}"
                      class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    />
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Last Name</label>
                    <input
                      type="text"
                      name="last_name"
                      value="${escapeHtml(data.userToEdit.lastName || '')}"
                      class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    />
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Email</label>
                    <input
                      type="email"
                      name="email"
                      value="${escapeHtml(data.userToEdit.email || '')}"
                      required
                      class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    />
                  </div>

                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Phone</label>
                    <input
                      type="tel"
                      name="phone"
                      value="${escapeHtml(data.userToEdit.phone || '')}"
                      class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    />
                  </div>

                  <div>
                    <label for="role" class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Role</label>
                    <div class="mt-2 grid grid-cols-1">
                      <select
                        id="role"
                        name="role"
                        class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-500/30 dark:outline-zinc-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-zinc-500 dark:focus-visible:outline-zinc-400 sm:text-sm/6"
                      >
                        ${data.roles.map(role => `
                          <option value="${escapeHtml(role.value)}" ${data.userToEdit.role === role.value ? 'selected' : ''}>${escapeHtml(role.label)}</option>
                        `).join('')}
                      </select>
                      <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-zinc-600 dark:text-zinc-400 sm:size-4">
                        <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>

              ${data.hasProfilePlugin ? `
              <!-- Profile Information (shown when defineUserProfile() is configured) -->
              <div class="mb-8">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Profile Information</h3>
                <div class="mb-4">
                  <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Display Name</label>
                  <input
                    type="text"
                    name="profile_display_name"
                    value="${escapeHtml(data.userToEdit.profile?.displayName || '')}"
                    placeholder="Public display name"
                    class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                  />
                </div>
                ${data.customProfileFieldsHtml || ''}
              </div>
              ` : ''}


              <!-- Set Password -->
              <div class="mb-8">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Set Password</h3>
                <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Leave blank to keep the current password</p>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">New Password</label>
                    <input
                      type="password"
                      name="new_password"
                      minlength="8"
                      placeholder="Minimum 8 characters"
                      autocomplete="new-password"
                      class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    />
                  </div>
                  <div>
                    <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Confirm Password</label>
                    <input
                      type="password"
                      name="confirm_password"
                      minlength="8"
                      placeholder="Repeat new password"
                      autocomplete="new-password"
                      class="w-full rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white shadow-sm ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-zinc-950 dark:focus:ring-white transition-shadow"
                    />
                  </div>
                </div>
              </div>

              <!-- Account Status -->
              <div class="mb-8">
                <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">Account Status</h3>
                <div class="space-y-4">
                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input
                          type="checkbox"
                          id="is_active"
                          name="is_active"
                          value="1"
                          ${data.userToEdit.isActive ? 'checked' : ''}
                          class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto"
                        />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                          <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6">
                      <label for="is_active" class="font-medium text-zinc-950 dark:text-white">Account Active</label>
                      <p class="text-zinc-500 dark:text-zinc-400">User can sign in and access the system</p>
                    </div>
                  </div>

                  <div class="flex gap-3">
                    <div class="flex h-6 shrink-0 items-center">
                      <div class="group grid size-4 grid-cols-1">
                        <input
                          type="checkbox"
                          id="email_verified"
                          name="email_verified"
                          value="1"
                          ${data.userToEdit.emailVerified ? 'checked' : ''}
                          class="col-start-1 row-start-1 appearance-none rounded border border-zinc-950/10 dark:border-white/10 bg-white dark:bg-white/5 checked:border-indigo-500 checked:bg-indigo-500 indeterminate:border-indigo-500 indeterminate:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500 disabled:border-zinc-950/5 dark:disabled:border-white/5 disabled:bg-zinc-950/10 dark:disabled:bg-white/10 disabled:checked:bg-zinc-950/10 dark:disabled:checked:bg-white/10 forced-colors:appearance-auto"
                        />
                        <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-zinc-950/25 dark:group-has-[:disabled]:stroke-white/25">
                          <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                          <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                        </svg>
                      </div>
                    </div>
                    <div class="text-sm/6">
                      <label for="email_verified" class="font-medium text-zinc-950 dark:text-white">Email Verified</label>
                      <p class="text-zinc-500 dark:text-zinc-400">User has verified their email address</p>
                    </div>
                  </div>
                </div>
              </div>

            </form>
          </div>
        </div>

        <!-- Sidebar -->
        <div class="lg:col-span-1">
          <!-- User Stats -->
          <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
            <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-4">User Details</h3>
            <dl class="space-y-4 text-sm">
              <div>
                <dt class="text-zinc-500 dark:text-zinc-400">User ID</dt>
                <dd class="mt-1 text-zinc-950 dark:text-white font-mono text-xs">${data.userToEdit.id}</dd>
              </div>
              <div>
                <dt class="text-zinc-500 dark:text-zinc-400">Created</dt>
                <dd class="mt-1 text-zinc-950 dark:text-white">${new Date(data.userToEdit.createdAt).toLocaleDateString()}</dd>
              </div>
              ${data.userToEdit.lastLoginAt ? `
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Last Login</dt>
                  <dd class="mt-1 text-zinc-950 dark:text-white">${new Date(data.userToEdit.lastLoginAt).toLocaleDateString()}</dd>
                </div>
              ` : ''}
              <div>
                <dt class="text-zinc-500 dark:text-zinc-400">Status</dt>
                <dd class="mt-1">
                  ${data.userToEdit.isActive
                    ? '<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-300 ring-1 ring-inset ring-lime-700/10 dark:ring-lime-400/20">Active</span>'
                    : '<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-700/10 dark:ring-red-500/20">Inactive</span>'
                  }
                </dd>
              </div>
              ${data.userToEdit.twoFactorEnabled ? `
                <div>
                  <dt class="text-zinc-500 dark:text-zinc-400">Security</dt>
                  <dd class="mt-1">
                    <span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-1 ring-inset ring-blue-700/10 dark:ring-blue-500/20">2FA Enabled</span>
                  </dd>
                </div>
              ` : ''}
            </dl>
          </div>

          <!-- Danger Zone -->
          <div class="rounded-xl bg-red-50 dark:bg-red-500/10 shadow-sm ring-1 ring-red-600/20 dark:ring-red-500/20 p-6">
            <h3 class="text-base font-semibold text-red-900 dark:text-red-300 mb-2">Danger Zone</h3>
            <p class="text-sm text-red-700 dark:text-red-400 mb-4">Irreversible and destructive actions</p>

            <div class="flex gap-3 mb-4">
              <div class="flex h-6 shrink-0 items-center">
                <div class="group grid size-4 grid-cols-1">
                  <input
                    type="checkbox"
                    id="hard-delete-checkbox"
                    class="col-start-1 row-start-1 appearance-none rounded border border-red-300 dark:border-red-700 bg-white dark:bg-red-950/50 checked:border-red-600 checked:bg-red-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-600 disabled:border-red-200 dark:disabled:border-red-900 disabled:bg-red-50 dark:disabled:bg-red-950/30 disabled:checked:bg-red-300 dark:disabled:checked:bg-red-900 forced-colors:appearance-auto"
                  />
                  <svg viewBox="0 0 14 14" fill="none" class="pointer-events-none col-start-1 row-start-1 size-3.5 self-center justify-self-center stroke-white group-has-[:disabled]:stroke-red-950/25 dark:group-has-[:disabled]:stroke-white/25">
                    <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:checked]:opacity-100" />
                    <path d="M3 7H11" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="opacity-0 group-has-[:indeterminate]:opacity-100" />
                  </svg>
                </div>
              </div>
              <div class="text-sm/6">
                <label for="hard-delete-checkbox" class="font-medium text-red-900 dark:text-red-300 cursor-pointer">Hard Delete (Permanent)</label>
                <p class="text-red-700 dark:text-red-400">Permanently remove from database. Unchecked performs soft delete (deactivate only).</p>
              </div>
            </div>

            <button
              onclick="deleteUser('${data.userToEdit.id}')"
              class="w-full inline-flex items-center justify-center rounded-lg bg-red-600 px-3 py-2 text-sm font-semibold text-white hover:bg-red-700 transition-colors"
            >
              <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
              </svg>
              Delete User
            </button>
          </div>
        </div>
      </div>
    </div>

    ${renderTenantMembershipsSection(data.userToEdit.id, data.tenantMemberships)}

    <script>
      let userIdToDelete = null;

      function deleteUser(userId) {
        userIdToDelete = userId;
        showConfirmDialog('delete-user-confirm');
      }

      function performDeleteUser() {
        if (!userIdToDelete) return;

        const checkbox = document.getElementById('hard-delete-checkbox');
        const hardDelete = checkbox ? checkbox.checked : false;

        fetch(\`/admin/users/\${userIdToDelete}\`, {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ hardDelete })
        })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            // Add a small delay to ensure database transaction completes
            // and add cache busting to force refresh
            setTimeout(() => {
              window.location.href = '/admin/users?_t=' + Date.now()
            }, 300)
          } else {
            alert('Error deleting user: ' + (data.error || 'Unknown error'))
          }
        })
        .catch(error => {
          console.error('Error:', error)
          alert('Error deleting user')
        })
        .finally(() => {
          userIdToDelete = null;
        });
      }
    </script>

    <!-- Confirmation Dialogs -->
    ${renderConfirmationDialog({
      id: 'delete-user-confirm',
      title: 'Delete User',
      message: 'Are you sure you want to delete this user? Check the "Hard Delete" option to permanently remove all data from the database. This action cannot be undone!',
      confirmText: 'Delete',
      cancelText: 'Cancel',
      iconColor: 'red',
      confirmClass: 'bg-red-500 hover:bg-red-400',
      onConfirm: 'performDeleteUser()'
    })}

    ${getConfirmationDialogScript()}
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Edit User',
    pageTitle: `Edit User - ${data.userToEdit.firstName} ${data.userToEdit.lastName}`,
    currentPath: '/admin/users',
    user: data.user,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
