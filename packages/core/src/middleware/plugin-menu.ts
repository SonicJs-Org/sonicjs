import type { Context, Next } from 'hono'
import type { Bindings, Variables } from '../app'
import { PLUGIN_REGISTRY } from '../plugins/manifest-registry'

// Build menu plugin data from the auto-generated registry.
// Any plugin with an adminMenu entry in its manifest.json will
// automatically appear in the sidebar when active.
// `id` matches the `slug` column in the documents table (how plugins are stored).
const REGISTRY_MENU_PLUGINS = Object.values(PLUGIN_REGISTRY)
  .filter(p => p.adminMenu !== null)
  .map(p => ({
    id: p.id,
    label: p.adminMenu!.label,
    path: p.adminMenu!.path,
    icon: p.adminMenu!.icon,
    order: p.adminMenu!.order,
  }))

// Map icon names from manifest.json to Heroicons SVG (outline, 24x24)
const ICON_SVG: Record<string, string> = {
  'magnifying-glass': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z"/></svg>',
  'chart-bar': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 0 1 3 19.875v-6.75ZM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V8.625ZM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 0 1-1.125-1.125V4.125Z"/></svg>',
  'image': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m2.25 15.75 5.159-5.159a2.25 2.25 0 0 1 3.182 0l5.159 5.159m-1.5-1.5 1.409-1.409a2.25 2.25 0 0 1 3.182 0l2.909 2.909m-18 3.75h16.5a1.5 1.5 0 0 0 1.5-1.5V6a1.5 1.5 0 0 0-1.5-1.5H3.75A1.5 1.5 0 0 0 2.25 6v12a1.5 1.5 0 0 0 1.5 1.5Zm10.5-11.25h.008v.008h-.008V8.25Zm.375 0a.375.375 0 1 1-.75 0 .375.375 0 0 1 .75 0Z"/></svg>',
  'palette': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4.098 19.902a3.75 3.75 0 0 0 5.304 0l6.401-6.402M6.75 21A3.75 3.75 0 0 1 3 17.25V4.125C3 3.504 3.504 3 4.125 3h5.25c.621 0 1.125.504 1.125 1.125v4.072M6.75 21a3.75 3.75 0 0 0 3.75-3.75V8.197M6.75 21h13.125c.621 0 1.125-.504 1.125-1.125v-5.25c0-.621-.504-1.125-1.125-1.125h-4.072M10.5 8.197l2.88-2.88c.438-.439 1.15-.439 1.59 0l3.712 3.713c.44.44.44 1.152 0 1.59l-2.879 2.88M6.75 17.25h.008v.008H6.75v-.008Z"/></svg>',
  'envelope': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75"/></svg>',
  'hand-raised': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.05 4.575a1.575 1.575 0 1 0-3.15 0v3m3.15-3v-1.5a1.575 1.575 0 0 1 3.15 0v1.5m-3.15 0 .075 5.925m3.075-5.925v2.925m0-2.925a1.575 1.575 0 0 1 3.15 0V9.9m-3.15-2.4v5.325M16.5 9.9a1.575 1.575 0 0 1 3.15 0V15a6.15 6.15 0 0 1-6.15 6.15H12A6.15 6.15 0 0 1 5.85 15V9.525"/></svg>',
  'key': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"/></svg>',
  'arrow-right': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.5 4.5 21 12m0 0-7.5 7.5M21 12H3"/></svg>',
  'shield-check': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>',
  'credit-card': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h3m-3.75 3h15a2.25 2.25 0 0 0 2.25-2.25V6.75A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25v10.5A2.25 2.25 0 0 0 4.5 19.5Z"/></svg>',
  'document-text': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5.586a1 1 0 0 1 .707.293l5.414 5.414a1 1 0 0 1 .293.707V19a2 2 0 0 1-2 2z"/></svg>',
  'pencil-square': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10"/></svg>',
  'server': '<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm14 1a1 1 0 11-2 0 1 1 0 012 0zM2 13a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2v-2zm14 1a1 1 0 11-2 0 1 1 0 012 0z" clip-rule="evenodd"/></svg>',
  'building-office': '<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"/></svg>',
}

function resolveIcon(iconName?: string): string {
  if (!iconName) return ''
  // If it's already SVG markup, return as-is
  if (iconName.startsWith('<svg') || iconName.startsWith('<')) return iconName
  // Look up by name
  return ICON_SVG[iconName] || ''
}

const MARKER = '<!-- DYNAMIC_PLUGIN_MENU -->'

function renderMenuItem(item: { label: string; path: string; icon?: string }, currentPath: string): string {
  const isActive = currentPath === item.path || currentPath.startsWith(item.path)
  const fallbackIcon = `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>`
  const resolvedIcon = resolveIcon(item.icon) || fallbackIcon
  return `
    <span class="relative">
      ${isActive ? '<span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>' : ''}
      <a
        href="${item.path}"
        class="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left text-sm/5 font-medium ${
          isActive
            ? 'text-zinc-950 dark:text-white'
            : 'text-zinc-600 hover:bg-zinc-950/5 dark:text-zinc-400 dark:hover:bg-white/5'
        }"
        ${isActive ? 'data-current="true"' : ''}
      >
        <span class="shrink-0 ${isActive ? 'fill-zinc-950 dark:fill-white' : 'fill-zinc-500 dark:fill-zinc-400'}">
          ${resolvedIcon}
        </span>
        <span class="truncate">${item.label}</span>
      </a>
    </span>`
}

export function pluginMenuMiddleware() {
  return async (c: Context<{ Bindings: Bindings; Variables: Variables }>, next: Next) => {
    const path = new URL(c.req.url).pathname
    if (!path.startsWith('/admin')) {
      return next()
    }

    // Collect menu items from active plugins using the registry
    let activeMenuItems: Array<{ label: string; path: string; icon?: string; order: number }> = []
    try {
      const db = c.env.DB
      const pluginIds = REGISTRY_MENU_PLUGINS.map(p => p.id)
      if (pluginIds.length > 0) {
        const placeholders = pluginIds.map(() => '?').join(',')
        const result = await db.prepare(
          `SELECT slug FROM documents WHERE type_id = 'plugin' AND tenant_id = 'default' AND slug IN (${placeholders}) AND q_plugin_status = 'active' AND is_current_draft = 1 AND deleted_at IS NULL`
        ).bind(...pluginIds).all()

        const activeIds = new Set((result.results || []).map((r: any) => r.slug))

        for (const plugin of REGISTRY_MENU_PLUGINS) {
          if (activeIds.has(plugin.id)) {
            activeMenuItems.push({
              label: plugin.label,
              path: plugin.path,
              icon: plugin.icon,
              order: plugin.order,
            })
          }
        }

        // Sort by order
        activeMenuItems.sort((a, b) => a.order - b.order)
      }
    } catch {
      // DB not ready or plugin table doesn't exist yet
    }

    c.set('pluginMenuItems', activeMenuItems.map(m => ({ label: m.label, path: m.path, icon: resolveIcon(m.icon) || '' })))

    await next()

    // Inject menu items into HTML response by replacing the marker
    if (activeMenuItems.length > 0 && c.res.headers.get('content-type')?.includes('text/html')) {
      const status = c.res.status
      const headers = new Headers(c.res.headers)
      const html = await c.res.text()

      if (html.includes(MARKER)) {
        const renderedItems = activeMenuItems.map(item => renderMenuItem(item, path)).join('')
        const newHtml = html.split(MARKER).join(renderedItems)
        c.res = new Response(newHtml, { status, headers })
      } else {
        // Body was consumed by .text(), must create new Response either way
        c.res = new Response(html, { status, headers })
      }
    }
  }
}
