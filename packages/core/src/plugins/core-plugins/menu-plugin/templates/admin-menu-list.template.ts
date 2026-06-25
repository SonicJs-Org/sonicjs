import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import type { MenuItem, SidebarItem } from '../services/menu-repository'

interface MenuListPageData {
  items: MenuItem[]
  tree: SidebarItem[]
  pluginStatuses?: Record<string, 'active' | 'inactive'>
  user?: { name?: string; email?: string; role?: string }
  currentPath?: string
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
  message?: string
}

function pluginStatusBadge(status: 'active' | 'inactive'): string {
  if (status === 'inactive') {
    return `<span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20 ml-1">disabled</span>`
  }
  return `<span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-1 ring-inset ring-green-600/20 dark:ring-green-500/20 ml-1">enabled</span>`
}

function sourceBadge(source: string): string {
  switch (source) {
    case 'system':
      return `<span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-zinc-100 dark:bg-zinc-700/50 text-zinc-600 dark:text-zinc-300 ring-1 ring-inset ring-zinc-300/50 dark:ring-zinc-600/50">system</span>`
    case 'plugin':
      return `<span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 ring-1 ring-inset ring-blue-700/10 dark:ring-blue-400/20">plugin</span>`
    default:
      return `<span class="inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-300 ring-1 ring-inset ring-green-700/10 dark:ring-green-400/20">user</span>`
  }
}

function iconPreview(icon: string): string {
  if (!icon) return '<span class="text-zinc-400 dark:text-zinc-500">—</span>'
  if (icon.trim().startsWith('<')) {
    return `<span class="w-5 h-5 inline-flex items-center justify-center">${icon}</span>`
  }
  return `<span class="text-xs font-mono text-zinc-500 dark:text-zinc-400 truncate max-w-[80px]">${escapeHtml(icon)}</span>`
}

export function renderMenuListPage(data: MenuListPageData): string {
  const messageBanner = data.message
    ? `<div class="mb-6 rounded-lg bg-cyan-50 dark:bg-cyan-900/20 border border-cyan-200 dark:border-cyan-700 px-4 py-3 text-sm text-cyan-800 dark:text-cyan-200">
        ${escapeHtml(data.message)}
      </div>`
    : ''

  const pluginStatuses = data.pluginStatuses ?? {}
  const rows = data.items.map((item, index) => {
    const isFirst = index === 0
    const isLast = index === data.items.length - 1

    const moveUpForm = !isFirst
      ? `<form method="POST" action="/admin/menu/${escapeHtml(item.id)}/move-up" class="inline">
          <button type="submit" class="p-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors" title="Move up">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/>
            </svg>
          </button>
        </form>`
      : `<span class="w-6 inline-block"></span>`

    const moveDownForm = !isLast
      ? `<form method="POST" action="/admin/menu/${escapeHtml(item.id)}/move-down" class="inline">
          <button type="submit" class="p-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors" title="Move down">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
            </svg>
          </button>
        </form>`
      : `<span class="w-6 inline-block"></span>`

    const deleteButton = item.source === 'user'
      ? `<form method="POST" action="/admin/menu/${escapeHtml(item.id)}/delete" onsubmit="return confirm('Delete this item?')" class="inline">
          <button type="submit" class="inline-flex items-center px-2.5 py-1.5 text-xs font-medium rounded-md text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-500/10 hover:bg-red-100 dark:hover:bg-red-500/20 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20 transition-colors">
            Delete
          </button>
        </form>`
      : ''

    return `
      <tr class="border-b border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50/50 dark:hover:bg-zinc-800/30 transition-colors">
        <td class="px-4 py-3 w-16">
          <div class="flex items-center gap-0.5">
            ${moveUpForm}
            ${moveDownForm}
          </div>
        </td>
        <td class="px-4 py-3 w-16">
          ${iconPreview(item.icon)}
        </td>
        <td class="px-4 py-3">
          <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">${escapeHtml(item.label)}</span>
          ${item.parent ? `<span class="ml-2 text-xs text-zinc-400 dark:text-zinc-500">child</span>` : ''}
        </td>
        <td class="px-4 py-3 max-w-[200px]">
          <span class="text-sm text-zinc-500 dark:text-zinc-400 truncate block">${escapeHtml(item.url)}</span>
        </td>
        <td class="px-4 py-3">
          ${sourceBadge(item.source)}
          ${item.source === 'plugin' && item.pluginId ? pluginStatusBadge(pluginStatuses[item.pluginId] ?? 'active') : ''}
        </td>
        <td class="px-4 py-3">
          <form method="POST" action="/admin/menu/${escapeHtml(item.id)}/visibility" class="inline">
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                type="checkbox"
                name="visible"
                value="true"
                ${item.visible ? 'checked' : ''}
                onchange="this.form.requestSubmit()"
                class="sr-only peer"
              >
              <div class="w-9 h-5 bg-zinc-200 dark:bg-zinc-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-zinc-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
            </label>
          </form>
        </td>
        <td class="px-4 py-3">
          <div class="flex items-center gap-2">
            <a href="/admin/menu/${escapeHtml(item.id)}" class="inline-flex items-center px-2.5 py-1.5 text-xs font-medium rounded-md text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-700 hover:bg-zinc-200 dark:hover:bg-zinc-600 ring-1 ring-inset ring-zinc-300/50 dark:ring-zinc-600/50 transition-colors">
              Edit
            </a>
            ${deleteButton}
          </div>
        </td>
      </tr>`
  }).join('\n')

  const emptyState = data.items.length === 0
    ? `<tr>
        <td colspan="7" class="px-4 py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">
          No menu items yet. <a href="/admin/menu/new" class="text-cyan-600 dark:text-cyan-400 underline hover:no-underline">Add a link</a> to get started.
        </td>
      </tr>`
    : ''

  const pageContent = `
    <div>
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Menu Manager</h1>
          <p class="mt-1 text-sm/6 text-zinc-500 dark:text-zinc-400">Manage navigation links and their order</p>
        </div>
        <div class="mt-4 sm:mt-0">
          <a href="/admin/menu/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2.5 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
              <path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z"/>
            </svg>
            Add Link
          </a>
        </div>
      </div>

      ${messageBanner}

      <div class="rounded-xl overflow-hidden bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
        <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-800/50">
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider w-16">Order</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider w-16">Icon</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Label</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">URL</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Source</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Visible</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
            ${rows}
            ${emptyState}
          </tbody>
        </table>
      </div>
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: 'Menu Manager',
    pageTitle: 'Menu Manager',
    currentPath: data.currentPath ?? '/admin/menu',
    user: data.user as AdminLayoutCatalystData['user'],
    version: data.version,
    dynamicMenuItems: data.dynamicMenuItems,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}

/**
 * Renders just the menu items table for embedding in the plugin settings tab.
 * No layout wrapper — called from the plugin's settingsTabContent.render().
 */
export function renderMenuSettingsContent(items: MenuItem[], pluginStatuses: Record<string, 'active' | 'inactive'> = {}, message?: string): string {
  const messageBanner = message
    ? `<div class="mb-4 rounded-lg bg-cyan-50 dark:bg-cyan-900/20 border border-cyan-200 dark:border-cyan-700 px-4 py-3 text-sm text-cyan-800 dark:text-cyan-200">${escapeHtml(message)}</div>`
    : ''

  const rows = items.map((item, index) => {
    const isFirst = index === 0
    const isLast = index === items.length - 1

    const moveUpForm = !isFirst
      ? `<form method="POST" action="/admin/menu/${escapeHtml(item.id)}/move-up" class="inline">
          <button type="submit" class="p-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors" title="Move up">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/></svg>
          </button>
        </form>`
      : `<span class="w-6 inline-block"></span>`

    const moveDownForm = !isLast
      ? `<form method="POST" action="/admin/menu/${escapeHtml(item.id)}/move-down" class="inline">
          <button type="submit" class="p-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-700 text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors" title="Move down">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>
          </button>
        </form>`
      : `<span class="w-6 inline-block"></span>`

    const deleteButton = item.source === 'user'
      ? `<form method="POST" action="/admin/menu/${escapeHtml(item.id)}/delete" onsubmit="return confirm('Delete this item?')" class="inline">
          <button type="submit" class="inline-flex items-center px-2.5 py-1.5 text-xs font-medium rounded-md text-red-700 dark:text-red-400 bg-red-50 dark:bg-red-500/10 hover:bg-red-100 dark:hover:bg-red-500/20 ring-1 ring-inset ring-red-600/20 dark:ring-red-500/20 transition-colors">Delete</button>
        </form>`
      : ''

    return `
      <tr class="border-b border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50/50 dark:hover:bg-zinc-800/30 transition-colors">
        <td class="px-4 py-3 w-16">
          <div class="flex items-center gap-0.5">${moveUpForm}${moveDownForm}</div>
        </td>
        <td class="px-4 py-3 w-16">${iconPreview(item.icon)}</td>
        <td class="px-4 py-3">
          <span class="text-sm font-medium text-zinc-900 dark:text-zinc-100">${escapeHtml(item.label)}</span>
          ${item.parent ? `<span class="ml-2 text-xs text-zinc-400 dark:text-zinc-500">child</span>` : ''}
        </td>
        <td class="px-4 py-3 max-w-[200px]">
          <span class="text-sm text-zinc-500 dark:text-zinc-400 truncate block">${escapeHtml(item.url)}</span>
        </td>
        <td class="px-4 py-3">${sourceBadge(item.source)}${item.source === 'plugin' && item.pluginId ? pluginStatusBadge(pluginStatuses[item.pluginId] ?? 'active') : ''}</td>
        <td class="px-4 py-3">
          <form method="POST" action="/admin/menu/${escapeHtml(item.id)}/visibility" class="inline">
            <label class="relative inline-flex items-center cursor-pointer">
              <input type="checkbox" name="visible" value="true" ${item.visible ? 'checked' : ''} onchange="this.form.requestSubmit()" class="sr-only peer">
              <div class="w-9 h-5 bg-zinc-200 dark:bg-zinc-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-zinc-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
            </label>
          </form>
        </td>
        <td class="px-4 py-3">
          <div class="flex items-center gap-2">
            <a href="/admin/menu/${escapeHtml(item.id)}" class="inline-flex items-center px-2.5 py-1.5 text-xs font-medium rounded-md text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-700 hover:bg-zinc-200 dark:hover:bg-zinc-600 ring-1 ring-inset ring-zinc-300/50 dark:ring-zinc-600/50 transition-colors">Edit</a>
            ${deleteButton}
          </div>
        </td>
      </tr>`
  }).join('\n')

  const emptyState = items.length === 0
    ? `<tr><td colspan="7" class="px-4 py-12 text-center text-sm text-zinc-400 dark:text-zinc-500">No menu items yet. <a href="/admin/menu/new" class="text-cyan-600 dark:text-cyan-400 underline hover:no-underline">Add a link</a> to get started.</td></tr>`
    : ''

  return `
    <script>
      (function() {
        function getCsrfToken() {
          var c = document.cookie.split('; ').find(function(r) { return r.startsWith('csrf_token='); });
          return c ? c.substring(c.indexOf('=') + 1) : '';
        }
        document.addEventListener('submit', function(e) {
          var form = e.target;
          if (!form || form.tagName !== 'FORM') return;
          if ((form.method || 'GET').toUpperCase() === 'GET') return;
          if (!form.querySelector('input[name="_csrf"]')) {
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = '_csrf';
            input.value = getCsrfToken();
            form.appendChild(input);
          }
        });
      })();
    </script>
    <div>
      <div class="flex items-center justify-between mb-4">
        <p class="text-sm text-zinc-500 dark:text-zinc-400">Manage navigation links and their order in the sidebar.</p>
        <a href="/admin/menu/new" class="inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3 py-2 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm">
          <svg class="-ml-0.5 mr-1.5 h-4 w-4" viewBox="0 0 20 20" fill="currentColor"><path d="M10.75 4.75a.75.75 0 00-1.5 0v4.5h-4.5a.75.75 0 000 1.5h4.5v4.5a.75.75 0 001.5 0v-4.5h4.5a.75.75 0 000-1.5h-4.5v-4.5z"/></svg>
          Add Link
        </a>
      </div>
      ${messageBanner}
      <div class="rounded-xl overflow-hidden bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
        <table class="min-w-full divide-y divide-zinc-200 dark:divide-zinc-800">
          <thead>
            <tr class="bg-zinc-50 dark:bg-zinc-800/50">
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider w-16">Order</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider w-16">Icon</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Label</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">URL</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Source</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Visible</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-zinc-100 dark:divide-zinc-800">
            ${rows}
            ${emptyState}
          </tbody>
        </table>
      </div>
    </div>
  `
}
