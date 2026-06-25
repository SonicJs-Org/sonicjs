import type { Context, Next } from 'hono'
import type { Bindings, Variables } from '../app'
import { listMenuItems, buildSidebarTree } from '../plugins/core-plugins/menu-plugin/services/menu-repository'
import type { SidebarItem } from '../plugins/core-plugins/menu-plugin/services/menu-repository'
import { resolveIcon } from '../services/menu-icons'
import { escapeHtml } from '../utils/sanitize'

const MARKER_START = '<!-- ADMIN_SIDEBAR_NAV_ITEMS -->'
const MARKER_END = '<!-- /ADMIN_SIDEBAR_NAV_ITEMS -->'

const EXTERNAL_ICON = `<svg class="h-3 w-3 ml-1 shrink-0 opacity-60" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>`

const CHEVRON = `<svg data-menu-chevron class="h-4 w-4 rotate-180 transition-transform duration-200" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/></svg>`

function renderTopLevelItem(item: SidebarItem, currentPath: string): string {
  const isActive =
    currentPath === item.url ||
    (item.url !== '/admin' && currentPath.startsWith(item.url))
  const icon = resolveIcon(item.icon)
  const label = escapeHtml(item.label)
  const targetAttr = item.target === '_blank' ? ' target="_blank" rel="noopener noreferrer"' : ''
  const externalAffordance = item.isExternal ? EXTERNAL_ICON : ''

  if (item.children.length > 0) {
    const accordionId = `acc-${item.id.replace(/[^a-z0-9]/gi, '-')}`
    const isChildActive = item.children.some(
      (c) => currentPath === c.url || currentPath.startsWith(c.url),
    )
    const accordionActive = isActive || isChildActive
    return `
      <div data-menu-accordion class="relative">
        ${accordionActive ? '<span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>' : ''}
        <div class="flex w-full items-center">
          <a href="${item.url}"${targetAttr}
            class="flex flex-1 items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium ${accordionActive ? 'text-zinc-950 dark:text-white' : 'text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5'}"
            ${accordionActive ? 'data-current="true"' : ''}
          >
            <span class="shrink-0 ${accordionActive ? 'fill-zinc-950 dark:fill-white' : 'fill-zinc-500 dark:fill-zinc-400'}">${icon}</span>
            <span class="truncate">${label}</span>${externalAffordance}
          </a>
          <button
            onclick="toggleMenuAccordion('${accordionId}')"
            class="flex items-center justify-center rounded-lg p-2 text-zinc-500 hover:bg-zinc-950/5 dark:text-zinc-400 dark:hover:bg-white/5 flex-shrink-0"
            aria-label="Toggle ${label} submenu"
          >
            ${CHEVRON}
          </button>
        </div>
        <div id="${accordionId}" class="pl-6 mt-0.5 flex flex-col gap-0.5">
          ${item.children.map((child) => renderChildItem(child, currentPath)).join('')}
        </div>
      </div>`
  }

  return `
    <span class="relative">
      ${isActive ? '<span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>' : ''}
      <a href="${item.url}"${targetAttr}
        class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium ${isActive ? 'text-zinc-950 dark:text-white' : 'text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5'}"
        ${isActive ? 'data-current="true"' : ''}
      >
        <span class="shrink-0 ${isActive ? 'fill-zinc-950 dark:fill-white' : 'fill-zinc-500 dark:fill-zinc-400'}">${icon}</span>
        <span class="truncate">${label}</span>${externalAffordance}
      </a>
    </span>`
}

function renderChildItem(item: SidebarItem, currentPath: string): string {
  const isActive =
    currentPath === item.url ||
    (item.url !== '/admin' && currentPath.startsWith(item.url))
  const icon = resolveIcon(item.icon)
  const label = escapeHtml(item.label)
  const targetAttr = item.target === '_blank' ? ' target="_blank" rel="noopener noreferrer"' : ''
  const externalAffordance = item.isExternal ? EXTERNAL_ICON : ''

  return `
    <span class="relative">
      ${isActive ? '<span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>' : ''}
      <a href="${item.url}"${targetAttr}
        class="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm/5 font-medium ${isActive ? 'text-zinc-950 dark:text-white' : 'text-zinc-600 hover:bg-zinc-950/5 dark:text-zinc-400 dark:hover:bg-white/5'}"
        ${isActive ? 'data-current="true"' : ''}
      >
        <span class="shrink-0 ${isActive ? 'fill-zinc-950 dark:fill-white' : 'fill-zinc-500 dark:fill-zinc-400'}">${icon}</span>
        <span class="truncate">${label}</span>${externalAffordance}
      </a>
    </span>`
}

const ACCORDION_SCRIPT = `
<script>
  function toggleMenuAccordion(id) {
    var el = document.getElementById(id)
    if (!el) return
    var chevrons = el.parentElement ? el.parentElement.querySelectorAll('[data-menu-chevron]') : []
    if (el.style.display === 'none' || el.style.display === '') {
      el.style.display = 'flex'
      el.style.flexDirection = 'column'
      chevrons.forEach(function(c) { c.style.transform = 'rotate(180deg)' })
    } else {
      el.style.display = 'none'
      chevrons.forEach(function(c) { c.style.transform = 'rotate(0deg)' })
    }
  }
  // Open active accordions on load
  document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('[data-menu-accordion]').forEach(function(acc) {
      if (acc.querySelector('[data-current]')) {
        var sub = acc.querySelector('[id^="acc-"]')
        if (sub) { sub.style.display = 'flex'; sub.style.flexDirection = 'column' }
      }
    })
  })
</script>`

async function isMenuPluginActive(db: any): Promise<boolean> {
  try {
    // Plugins live in documents (type_id='plugin', slug=pluginId) — not the legacy plugins table
    const row = await db
      .prepare(
        `SELECT json_extract(data, '$.status') AS status
         FROM documents
         WHERE slug = 'menu' AND type_id = 'plugin' AND tenant_id = 'default'
           AND is_current_draft = 1 AND deleted_at IS NULL
         LIMIT 1`,
      )
      .first() as { status: string } | null
    // Not yet in DB (never installed/activated) → off by default
    if (!row) return false
    return row.status === 'active'
  } catch {
    return true
  }
}

export function menuMiddleware() {
  return async (c: Context<{ Bindings: Bindings; Variables: Variables }>, next: Next) => {
    const path = new URL(c.req.url).pathname
    if (!path.startsWith('/admin')) {
      return next()
    }

    await next()

    if (!c.res.headers.get('content-type')?.includes('text/html')) return

    // Revert to hardcoded sidebar when plugin is explicitly disabled
    if (!(await isMenuPluginActive(c.env.DB))) return

    let items: Awaited<ReturnType<typeof listMenuItems>> = []
    try {
      items = await listMenuItems(c.env.DB)
    } catch {
      return
    }

    if (items.length === 0) return

    const tree = buildSidebarTree(items)
    const renderedItems = tree.map((item) => renderTopLevelItem(item, path)).join('')
    const navItemsHtml = renderedItems + ACCORDION_SCRIPT

    const status = c.res.status
    const headers = new Headers(c.res.headers)
    const html = await c.res.text()

    // Replace ALL occurrences of the marker pair (desktop + mobile sidebars both use it)
    const markerRegex = /<!-- ADMIN_SIDEBAR_NAV_ITEMS -->[\s\S]*?<!-- \/ADMIN_SIDEBAR_NAV_ITEMS -->/g
    if (markerRegex.test(html)) {
      const newHtml = html.replace(
        /<!-- ADMIN_SIDEBAR_NAV_ITEMS -->[\s\S]*?<!-- \/ADMIN_SIDEBAR_NAV_ITEMS -->/g,
        navItemsHtml,
      )
      c.res = new Response(newHtml, { status, headers })
    } else {
      c.res = new Response(html, { status, headers })
    }
  }
}
