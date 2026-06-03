import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../layouts/admin-layout-catalyst.template'
import { renderPagination, PaginationData } from '../pagination.template'
import { renderAlert } from '../alert.template'
import { renderTable, TableColumn, TableData } from '../table.template'
import { renderConfirmationDialog, getConfirmationDialogScript } from '../components/confirmation-dialog.template'

export interface User {
  id: string
  email: string
  username: string
  firstName: string
  lastName: string
  role: string
  avatar?: string
  isActive: boolean
  lastLoginAt?: number
  createdAt: number
  updatedAt: number
  formattedLastLogin?: string
  formattedCreatedAt?: string
}

export interface UsersListPageData {
  users: User[]
  pagination?: PaginationData
  currentPage: number
  totalPages: number
  totalUsers: number
  statusFilter?: string
  roleFilter?: string
  searchFilter?: string
  error?: string
  success?: string
  user?: {
    name: string
    email: string
    role: string
  }
  version?: string
}

export function renderUsersListPage(data: UsersListPageData): string {
  const columns: TableColumn[] = [
    {
      key: 'avatar',
      label: '',
      className: 'w-12',
      sortable: false,
      render: (value: string | null, row: User) => {
        const initials = `${row.firstName.charAt(0)}${row.lastName.charAt(0)}`.toUpperCase()
        if (value) {
          return `<img src="${value}" alt="${row.firstName} ${row.lastName}" class="w-8 h-8 rounded-full">`
        }
        return `
          <div class="w-8 h-8 bg-gradient-to-br from-cyan-400 to-blue-500 dark:from-cyan-300 dark:to-blue-400 rounded-full flex items-center justify-center">
            <span class="text-xs font-medium text-white">${initials}</span>
          </div>
        `
      }
    },
    {
      key: 'name',
      label: 'Name',
      sortable: true,
      sortType: 'string',
      render: (_value: any, row: User) => {
        const escapeHtml = (text: string) => text.replace(/[&<>"']/g, (char) => ({
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;'
        }[char] || char))
        
        const truncatedFirstName = row.firstName.length > 25 ? row.firstName.substring(0, 25) + '...' : row.firstName
        const truncatedLastName = row.lastName.length > 25 ? row.lastName.substring(0, 25) + '...' : row.lastName
        const fullName = escapeHtml(`${truncatedFirstName} ${truncatedLastName}`)
        const truncatedUsername = row.username.length > 100 ? row.username.substring(0, 100) + '...' : row.username
        const username = escapeHtml(truncatedUsername)
        const statusBadge = row.isActive ?
          '<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-lime-50 dark:bg-lime-500/10 text-lime-700 dark:text-lime-300 ring-1 ring-inset ring-lime-700/10 dark:ring-lime-400/20 ml-2">Active</span>' :
          '<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-700/10 dark:ring-red-500/20 ml-2">Inactive</span>'
        return `
          <div>
            <div class="text-sm font-medium text-zinc-950 dark:text-white">${fullName}${statusBadge}</div>
            <div class="text-sm text-zinc-500 dark:text-zinc-400">@${username}</div>
          </div>
        `
      }
    },
    {
      key: 'email',
      label: 'Email',
      sortable: true,
      sortType: 'string',
      render: (value: string) => {
        const escapeHtml = (text: string) => text.replace(/[&<>"']/g, (char) => ({
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#39;'
        }[char] || char))
        const escapedEmail = escapeHtml(value)
        return `<a href="mailto:${escapedEmail}" class="text-cyan-600 dark:text-cyan-400 hover:text-cyan-700 dark:hover:text-cyan-300 transition-colors">${escapedEmail}</a>`
      }
    },
    {
      key: 'role',
      label: 'Role',
      sortable: true,
      sortType: 'string',
      render: (value: string) => {
        const roleColors = {
          admin: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-700/10 dark:ring-red-500/20',
          editor: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-1 ring-inset ring-blue-700/10 dark:ring-blue-500/20',
          author: 'bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 ring-1 ring-inset ring-cyan-700/10 dark:ring-cyan-500/20',
          viewer: 'bg-zinc-50 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/10 dark:ring-zinc-400/20'
        }
        const colorClass = roleColors[value as keyof typeof roleColors] || 'bg-zinc-50 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 ring-1 ring-inset ring-zinc-500/10 dark:ring-zinc-400/20'
        return `<span class="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ${colorClass}">${value.charAt(0).toUpperCase() + value.slice(1)}</span>`
      }
    },
    {
      key: 'lastLoginAt',
      label: 'Last Login',
      sortable: true,
      sortType: 'date',
      render: (value: number | null) => {
        if (!value) return '<span class="text-zinc-500 dark:text-zinc-400">Never</span>'
        return `<span class="text-sm text-zinc-500 dark:text-zinc-400">${new Date(value).toLocaleDateString()}</span>`
      }
    },
    {
      key: 'createdAt',
      label: 'Created',
      sortable: true,
      sortType: 'date',
      render: (value: number) => `<span class="text-sm text-zinc-500 dark:text-zinc-400">${new Date(value).toLocaleDateString()}</span>`
    },
    {
      key: 'actions',
      label: 'Actions',
      className: 'text-right',
      sortable: false,
      render: (_value: any, row: User) => `
        <div class="flex justify-end space-x-2">
          ${row.isActive ?
            `<button onclick="toggleUserStatus('${row.id}', false)" title="Deactivate user" class="inline-flex items-center justify-center p-2 text-sm font-medium rounded-lg bg-gradient-to-r from-red-500 to-pink-500 dark:from-red-400 dark:to-pink-400 text-white hover:from-red-600 hover:to-pink-600 dark:hover:from-red-500 dark:hover:to-pink-500 shadow-sm transition-all duration-200">
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/>
              </svg>
            </button>` :
            `<button onclick="toggleUserStatus('${row.id}', true)" title="Activate user" class="inline-flex items-center justify-center p-2 text-sm font-medium rounded-lg bg-gradient-to-r from-lime-500 to-green-500 dark:from-lime-400 dark:to-green-400 text-white hover:from-lime-600 hover:to-green-600 dark:hover:from-lime-500 dark:hover:to-green-500 shadow-sm transition-all duration-200">
              <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
              </svg>
            </button>`
          }
        </div>
      `
    }
  ]

  const tableData: TableData<User> = {
    tableId: 'users-table',
    columns,
    rows: data.users,
    selectable: false,
    rowClickable: true,
    rowClickUrl: (row: User) => `/admin/users/${row.id}/edit`,
    emptyMessage: 'No users found'
  }

  const pageContent = `
    <div>
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">User Management</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage user accounts and permissions</p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16 sm:flex-none flex space-x-3">
          <a href="/admin/users/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z" />
            </svg>
            Add User
          </a>
          <button class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm" onclick="exportUsers()">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
            </svg>
            Export
          </button>
        </div>
      </div>

      <!-- Tabs -->
      <div class="border-b border-zinc-950/10 dark:border-white/10 mb-6">
        <nav class="-mb-px flex space-x-6" aria-label="Tabs">
          <a href="/admin/users" aria-current="page" class="whitespace-nowrap border-b-2 border-cyan-500 px-1 py-3 text-sm font-medium text-cyan-600 dark:text-cyan-400">Users</a>
          <a href="/admin/rbac" class="whitespace-nowrap border-b-2 border-transparent px-1 py-3 text-sm font-medium text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-200">Roles &amp; Permissions</a>
        </nav>
      </div>

      <!-- Alert Messages -->
      ${data.error ? renderAlert({ type: 'error', message: data.error, dismissible: true }) : ''}
      ${data.success ? renderAlert({ type: 'success', message: data.success, dismissible: true }) : ''}

      <!-- Stats -->
      <div class="mb-6">
        <h3 class="text-base font-semibold text-zinc-950 dark:text-white">User Statistics</h3>
        <dl class="mt-5 grid grid-cols-1 divide-zinc-950/5 dark:divide-white/10 overflow-hidden rounded-lg bg-zinc-800/75 dark:bg-zinc-800/75 ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 md:grid-cols-4 md:divide-x md:divide-y-0">
          <div class="px-4 py-5 sm:p-6">
            <dt class="text-base font-normal text-zinc-700 dark:text-zinc-100">Total Users</dt>
            <dd class="mt-1 flex items-baseline justify-between md:block lg:flex">
              <div class="flex items-baseline text-2xl font-semibold text-cyan-400">
                ${data.totalUsers}
              </div>
              <div class="inline-flex items-baseline rounded-full bg-lime-400/10 text-lime-600 dark:text-lime-400 px-2.5 py-0.5 text-sm font-medium md:mt-2 lg:mt-0">
                <svg viewBox="0 0 20 20" fill="currentColor" class="-ml-1 mr-0.5 size-5 shrink-0 self-center">
                  <path d="M10 17a.75.75 0 0 1-.75-.75V5.612L5.29 9.77a.75.75 0 0 1-1.08-1.04l5.25-5.5a.75.75 0 0 1 1.08 0l5.25 5.5a.75.75 0 1 1-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0 1 10 17Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
                <span class="sr-only">Increased by</span>
                5.2%
              </div>
            </dd>
          </div>
          <div class="px-4 py-5 sm:p-6">
            <dt class="text-base font-normal text-zinc-700 dark:text-zinc-100">Active Users</dt>
            <dd class="mt-1 flex items-baseline justify-between md:block lg:flex">
              <div class="flex items-baseline text-2xl font-semibold text-lime-400">
                ${data.users.filter(u => u.isActive).length}
              </div>
              <div class="inline-flex items-baseline rounded-full bg-lime-400/10 text-lime-600 dark:text-lime-400 px-2.5 py-0.5 text-sm font-medium md:mt-2 lg:mt-0">
                <svg viewBox="0 0 20 20" fill="currentColor" class="-ml-1 mr-0.5 size-5 shrink-0 self-center">
                  <path d="M10 17a.75.75 0 0 1-.75-.75V5.612L5.29 9.77a.75.75 0 0 1-1.08-1.04l5.25-5.5a.75.75 0 0 1 1.08 0l5.25 5.5a.75.75 0 1 1-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0 1 10 17Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
                <span class="sr-only">Increased by</span>
                3.1%
              </div>
            </dd>
          </div>
          <div class="px-4 py-5 sm:p-6">
            <dt class="text-base font-normal text-zinc-700 dark:text-zinc-100">Administrators</dt>
            <dd class="mt-1 flex items-baseline justify-between md:block lg:flex">
              <div class="flex items-baseline text-2xl font-semibold text-pink-400">
                ${data.users.filter(u => u.role === 'admin').length}
              </div>
              <div class="inline-flex items-baseline rounded-full bg-lime-400/10 text-lime-600 dark:text-lime-400 px-2.5 py-0.5 text-sm font-medium md:mt-2 lg:mt-0">
                <svg viewBox="0 0 20 20" fill="currentColor" class="-ml-1 mr-0.5 size-5 shrink-0 self-center">
                  <path d="M10 17a.75.75 0 0 1-.75-.75V5.612L5.29 9.77a.75.75 0 0 1-1.08-1.04l5.25-5.5a.75.75 0 0 1 1.08 0l5.25 5.5a.75.75 0 1 1-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0 1 10 17Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
                <span class="sr-only">Increased by</span>
                1.8%
              </div>
            </dd>
          </div>
          <div class="px-4 py-5 sm:p-6">
            <dt class="text-base font-normal text-zinc-700 dark:text-zinc-100">Active This Week</dt>
            <dd class="mt-1 flex items-baseline justify-between md:block lg:flex">
              <div class="flex items-baseline text-2xl font-semibold text-purple-400">
                ${data.users.filter(u => u.lastLoginAt && u.lastLoginAt > Date.now() - 7 * 24 * 60 * 60 * 1000).length}
              </div>
              <div class="inline-flex items-baseline rounded-full bg-pink-400/10 text-pink-600 dark:text-pink-400 px-2.5 py-0.5 text-sm font-medium md:mt-2 lg:mt-0">
                <svg viewBox="0 0 20 20" fill="currentColor" class="-ml-1 mr-0.5 size-5 shrink-0 self-center">
                  <path d="M10 3a.75.75 0 0 1 .75.75v10.638l3.96-4.158a.75.75 0 1 1 1.08 1.04l-5.25 5.5a.75.75 0 0 1-1.08 0l-5.25-5.5a.75.75 0 1 1 1.08-1.04l3.96 4.158V3.75A.75.75 0 0 1 10 3Z" clip-rule="evenodd" fill-rule="evenodd" />
                </svg>
                <span class="sr-only">Decreased by</span>
                2.3%
              </div>
            </dd>
          </div>
        </dl>
      </div>

      <!-- Filters with Gradient Background -->
      <div class="relative rounded-xl overflow-hidden mb-6">
        <!-- Gradient Background Layer -->
        <div class="absolute inset-0 bg-gradient-to-r from-purple-500/10 via-pink-500/10 to-blue-500/10 dark:from-purple-400/20 dark:via-pink-400/20 dark:to-blue-400/20"></div>

        <!-- Content Layer with backdrop blur -->
        <div class="relative bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
          <div class="px-6 py-5">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
              <!-- Modern Search Input -->
              <div>
                <label class="block text-sm font-medium text-zinc-950 dark:text-white mb-2">Search</label>
                <div class="relative group">
                  <input
                    type="text"
                    name="search"
                    id="user-search-input"
                    value="${data.searchFilter || ''}"
                    placeholder="Search users..."
                    class="rounded-full bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm px-4 py-2.5 pl-11 text-sm w-full text-zinc-950 dark:text-white border-2 border-purple-200/50 dark:border-purple-700/50 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:border-purple-500 dark:focus:border-purple-400 focus:bg-white dark:focus:bg-zinc-800 focus:shadow-lg focus:shadow-purple-500/20 dark:focus:shadow-purple-400/20 transition-all duration-300"
                    hx-get="/admin/users"
                    hx-trigger="keyup changed delay:300ms"
                    hx-target="body"
                    hx-include="[name='role'], [name='status']"
                    hx-on::after-request="
                      const input = document.getElementById('user-search-input');
                      if (input && document.activeElement === input) {
                        const len = input.value.length;
                        setTimeout(() => {
                          input.focus();
                          input.setSelectionRange(len, len);
                        }, 10);
                      }
                    "
                  >
                  <!-- Gradient search icon -->
                  <div class="absolute left-3.5 top-2.5 flex items-center justify-center w-5 h-5 rounded-full bg-gradient-to-br from-purple-400 to-pink-500 dark:from-purple-300 dark:to-pink-400 opacity-90 group-focus-within:opacity-100 transition-opacity">
                    <svg class="h-3 w-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2.5">
                      <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>
                    </svg>
                  </div>
                </div>
              </div>

              <div>
                <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Role</label>
                <div class="mt-2 grid grid-cols-1">
                  <select
                    name="role"
                    hx-get="/admin/users"
                    hx-trigger="change"
                    hx-target="body"
                    hx-include="[name='search'], [name='status']"
                    class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-purple-500/30 dark:outline-purple-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-purple-500 dark:focus-visible:outline-purple-400 sm:text-sm/6"
                  >
                    <option value="" ${!data.roleFilter ? 'selected' : ''}>All Roles</option>
                    <option value="admin" ${data.roleFilter === 'admin' ? 'selected' : ''}>Admin</option>
                    <option value="editor" ${data.roleFilter === 'editor' ? 'selected' : ''}>Editor</option>
                    <option value="author" ${data.roleFilter === 'author' ? 'selected' : ''}>Author</option>
                    <option value="viewer" ${data.roleFilter === 'viewer' ? 'selected' : ''}>Viewer</option>
                  </select>
                  <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-purple-600 dark:text-purple-400 sm:size-4">
                    <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                  </svg>
                </div>
              </div>

              <div>
                <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white">Status</label>
                <div class="mt-2 grid grid-cols-1">
                  <select
                    name="status"
                    hx-get="/admin/users"
                    hx-trigger="change"
                    hx-target="body"
                    hx-include="[name='search'], [name='role']"
                    class="col-start-1 row-start-1 w-full appearance-none rounded-md bg-white/5 dark:bg-white/5 py-1.5 pl-3 pr-8 text-base text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-purple-500/30 dark:outline-purple-400/30 *:bg-white dark:*:bg-zinc-800 focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-purple-500 dark:focus-visible:outline-purple-400 sm:text-sm/6"
                  >
                    <option value="active" ${!data.statusFilter || data.statusFilter === 'active' ? 'selected' : ''}>Active</option>
                    <option value="inactive" ${data.statusFilter === 'inactive' ? 'selected' : ''}>Inactive</option>
                    <option value="all" ${data.statusFilter === 'all' ? 'selected' : ''}>All Users</option>
                  </select>
                  <svg viewBox="0 0 16 16" fill="currentColor" data-slot="icon" aria-hidden="true" class="pointer-events-none col-start-1 row-start-1 mr-2 size-5 self-center justify-self-end text-purple-600 dark:text-purple-400 sm:size-4">
                    <path d="M4.22 6.22a.75.75 0 0 1 1.06 0L8 8.94l2.72-2.72a.75.75 0 1 1 1.06 1.06l-3.25 3.25a.75.75 0 0 1-1.06 0L4.22 7.28a.75.75 0 0 1 0-1.06Z" clip-rule="evenodd" fill-rule="evenodd" />
                  </svg>
                </div>
              </div>

              <div>
                <label class="block text-sm/6 font-medium text-zinc-950 dark:text-white">&nbsp;</label>
                <div class="mt-2">
                  <button
                    class="inline-flex items-center gap-x-1.5 justify-center px-4 py-2 bg-white/90 dark:bg-zinc-800/90 backdrop-blur-sm text-zinc-950 dark:text-white text-sm font-medium rounded-full ring-1 ring-inset ring-purple-200/50 dark:ring-purple-700/50 hover:bg-gradient-to-r hover:from-purple-50 hover:to-pink-50 dark:hover:from-purple-900/30 dark:hover:to-pink-900/30 hover:ring-purple-300 dark:hover:ring-purple-600 transition-all duration-200 w-full"
                    onclick="clearFilters()"
                  >
                    <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
                    </svg>
                    Clear Filters
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Users Table -->
      ${renderTable(tableData)}

      <!-- Pagination -->
      ${data.pagination ? renderPagination(data.pagination) : ''}
    </div>

    <script>
      let userStatusData = null;

      function toggleUserStatus(userId, activate) {
        userStatusData = { userId, activate };
        showConfirmDialog('toggle-user-status-confirm');
      }

      function performToggleUserStatus() {
        if (!userStatusData) return;

        const { userId, activate } = userStatusData;

        fetch(\`/admin/users/\${userId}/toggle\`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ active: activate })
        })
        .then(response => response.json())
        .then(data => {
          if (data.success) {
            location.reload()
          } else {
            alert('Error updating user status')
          }
        })
        .catch(error => {
          console.error('Error:', error)
          alert('Error updating user status')
        })
        .finally(() => {
          userStatusData = null;
        });
      }

      function clearFilters() {
        window.location.href = '/admin/users'
      }

      function exportUsers() {
        window.open('/admin/users/export', '_blank')
      }
    </script>

    <!-- Confirmation Dialogs -->
    ${renderConfirmationDialog({
      id: 'toggle-user-status-confirm',
      title: 'Toggle User Status',
      message: 'Are you sure you want to activate/deactivate this user?',
      confirmText: 'Confirm',
      cancelText: 'Cancel',
      iconColor: 'yellow',
      confirmClass: 'bg-yellow-500 hover:bg-yellow-400',
      onConfirm: 'performToggleUserStatus()'
    })}

    ${getConfirmationDialogScript()}
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Users',
    pageTitle: 'User Management',
    currentPath: '/admin/users',
    user: data.user,
    version: data.version,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
} 