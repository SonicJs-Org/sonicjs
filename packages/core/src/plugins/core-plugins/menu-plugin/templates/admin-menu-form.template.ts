import { renderAdminLayoutCatalyst, AdminLayoutCatalystData } from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import type { MenuItem } from '../services/menu-repository'
import { renderIconPicker } from './icon-picker.template'

interface MenuFormPageData {
  item: MenuItem | null
  topLevelItems: MenuItem[]
  user?: { name?: string; email?: string; role?: string }
  currentPath?: string
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
  error?: string
}

export function renderMenuFormPage(data: MenuFormPageData): string {
  const { item, topLevelItems } = data
  const isEdit = item !== null

  const errorBanner = data.error
    ? `<div class="mb-6 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 px-4 py-3 text-sm text-red-800 dark:text-red-300">
        ${escapeHtml(data.error)}
      </div>`
    : ''

  const parentOptions = topLevelItems
    .filter((t) => !isEdit || t.id !== item?.id)
    .map((t) => {
      const selected = item?.parent === t.id ? 'selected' : ''
      return `<option value="${escapeHtml(t.id)}" ${selected}>${escapeHtml(t.label)}</option>`
    })
    .join('\n')

  const targetSelfSelected = !item || item.target === '_self' ? 'selected' : ''
  const targetBlankSelected = item?.target === '_blank' ? 'selected' : ''
  const visibleChecked = item ? (item.visible ? 'checked' : '') : 'checked'

  const formAttrs = isEdit
    ? `hx-put="/admin/menu/${escapeHtml(item!.id)}" hx-target="body" hx-push-url="true"`
    : `method="POST" action="/admin/menu"`

  const submitLabel = isEdit ? 'Save Changes' : 'Add Item'
  const pageTitle = isEdit ? `Edit: ${escapeHtml(item!.label)}` : 'Add Menu Item'

  const pageContent = `
    <div class="max-w-2xl">
      <div class="mb-6">
        <a href="/admin/menu" class="inline-flex items-center gap-1.5 text-sm text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors">
          <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
          </svg>
          Back to Menu Manager
        </a>
        <h1 class="mt-3 text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">${pageTitle}</h1>
      </div>

      ${errorBanner}

      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
        <form ${formAttrs} class="space-y-6">

          <div>
            <label for="menu-label" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">
              Label <span class="text-red-500">*</span>
            </label>
            <input
              id="menu-label"
              type="text"
              name="label"
              required
              value="${isEdit ? escapeHtml(item!.label) : ''}"
              placeholder="e.g. Documentation"
              class="w-full rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-shadow"
            >
          </div>

          <div>
            <label for="menu-url" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">URL</label>
            <input
              id="menu-url"
              type="text"
              name="url"
              value="${isEdit ? escapeHtml(item!.url) : ''}"
              placeholder="/path/to/page or https://example.com"
              class="w-full rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-shadow"
            >
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label for="menu-target" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Open in</label>
              <select
                id="menu-target"
                name="target"
                class="w-full rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-shadow"
              >
                <option value="_self" ${targetSelfSelected}>Same tab</option>
                <option value="_blank" ${targetBlankSelected}>New tab</option>
              </select>
            </div>

            <div>
              <label for="menu-parent" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Parent</label>
              <select
                id="menu-parent"
                name="parent"
                class="w-full rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-shadow"
              >
                <option value="">Top level (none)</option>
                ${parentOptions}
              </select>
            </div>
          </div>

          <div class="flex items-center gap-3">
            <label class="relative inline-flex items-center cursor-pointer">
              <input
                id="menu-visible"
                type="checkbox"
                name="visible"
                value="1"
                ${visibleChecked}
                class="sr-only peer"
              >
              <div class="w-9 h-5 bg-zinc-200 dark:bg-zinc-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-cyan-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-zinc-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
            </label>
            <label for="menu-visible" class="text-sm font-medium text-zinc-700 dark:text-zinc-300 cursor-pointer">Visible in navigation</label>
          </div>

          <div>
            <p class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2">Icon</p>
            ${renderIconPicker(item?.icon ?? 'link')}
          </div>

          <div class="flex items-center justify-end gap-3 pt-2 border-t border-zinc-100 dark:border-zinc-800">
            <a href="/admin/menu" class="inline-flex items-center px-3.5 py-2 text-sm font-medium rounded-lg text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-zinc-700 hover:bg-zinc-200 dark:hover:bg-zinc-600 transition-colors">
              Cancel
            </a>
            <button
              type="submit"
              class="inline-flex items-center px-3.5 py-2 text-sm font-semibold rounded-lg bg-zinc-950 dark:bg-white text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors shadow-sm"
            >
              ${submitLabel}
            </button>
          </div>

        </form>
      </div>
    </div>
  `

  const layoutData: AdminLayoutCatalystData = {
    title: isEdit ? 'Edit Menu Item' : 'Add Menu Item',
    pageTitle: isEdit ? 'Edit Menu Item' : 'Add Menu Item',
    currentPath: data.currentPath ?? '/admin/menu',
    user: data.user as AdminLayoutCatalystData['user'],
    version: data.version,
    dynamicMenuItems: data.dynamicMenuItems,
    content: pageContent
  }

  return renderAdminLayoutCatalyst(layoutData)
}
