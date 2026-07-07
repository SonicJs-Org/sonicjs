/**
 * Plugin admin-sidebar menu registry.
 *
 * Plugins declare `menu: PluginMenuEntry[]` on definePlugin. registerPlugins
 * collects every entry into this module singleton; the admin layout reads via
 * `resolvePluginMenuItems(user)` to render the sidebar.
 *
 * Phase 1 — strings + paths only. No custom React/HTMX components in menu
 * entries (icons are name strings looked up by the sidebar's icon map).
 */

export interface PluginMenuEntry {
  /** Display label. */
  label: string
  /** Admin URL the entry navigates to (e.g. `/admin/email`). */
  path: string
  /** Icon name from the admin icon map. Default: `puzzle-piece`. */
  icon?: string
  /** Sort key (ASC). Default 100. */
  order?: number
  /** Required permission slugs; if any matches the user's permissions, the entry is shown. */
  permissions?: readonly string[]
  /** Plugin ID — set automatically by registerPlugins. Used to DB-check active status. */
  pluginId?: string
}

/**
 * Resolved entry — guaranteed `icon` + `order`, ready to render. Same shape
 * the catalyst sidebar consumes via `dynamicMenuItems`. `icon` is the rendered
 * SVG HTML string (resolved via {@link MENU_ICON_MAP} when the entry supplied
 * a name; passed through verbatim when the entry supplied raw SVG/HTML).
 */
export interface ResolvedPluginMenuEntry {
  label: string
  path: string
  icon: string
  order: number
  pluginId?: string
}

// ── Icon name → SVG map ──────────────────────────────────────────────────────
//
// Plugins declare icons by name (`icon: 'envelope'`); the layout never has to
// import a per-plugin SVG. Names match heroicons-mini style. Unknown names
// fall through to the generic puzzle-piece. Names containing `<svg` are
// treated as raw SVG and passed through unchanged (escape hatch for one-off
// custom icons).

const PUZZLE_PIECE = `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path d="M14.5 2A1.5 1.5 0 0013 3.5V4H8.5A1.5 1.5 0 007 5.5V10h-.5a1.5 1.5 0 100 3H7v4.5A1.5 1.5 0 008.5 19H13v-.5a1.5 1.5 0 113 0V19h.5a1.5 1.5 0 001.5-1.5V13h-.5a1.5 1.5 0 110-3h.5V5.5A1.5 1.5 0 0017 4h-.5v-.5A1.5 1.5 0 0014.5 2z"/></svg>`

const MENU_ICON_MAP: Readonly<Record<string, string>> = {
  'puzzle-piece': PUZZLE_PIECE,
  envelope: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z"/><path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z"/></svg>`,
  cog: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/></svg>`,
  chart: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"/></svg>`,
  sparkles: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path d="M9 4.804A7.968 7.968 0 005.5 4c-1.255 0-2.443.29-3.5.804v10A7.969 7.969 0 015.5 14c1.669 0 3.218.51 4.5 1.385A7.962 7.962 0 0114.5 14c1.255 0 2.443.29 3.5.804v-10A7.968 7.968 0 0014.5 4c-1.255 0-2.443.29-3.5.804V12a1 1 0 11-2 0V4.804z"/></svg>`,
  bolt: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clip-rule="evenodd"/></svg>`,
  document: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm3 1h6v2H7V5zm0 4h6v2H7V9zm0 4h4v2H7v-2z" clip-rule="evenodd"/></svg>`,
  lock: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/></svg>`,
  photo: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clip-rule="evenodd"/></svg>`,
  'globe-alt': `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"/></svg>`,
}

function resolveIcon(name: string | undefined): string {
  if (!name) return PUZZLE_PIECE
  if (name.startsWith('<svg')) return name // raw SVG escape hatch
  return MENU_ICON_MAP[name] ?? PUZZLE_PIECE
}

let menuItems: readonly PluginMenuEntry[] = []

export function setPluginMenu(items: readonly PluginMenuEntry[]): void {
  menuItems = [...items]
}

export function getPluginMenu(): readonly PluginMenuEntry[] {
  return menuItems
}

export function resetPluginMenu(): void {
  menuItems = []
}

/**
 * Filter entries by user permissions, sort by `order` ASC, project to render-ready
 * shape with default icon. Pure function — same inputs, same output.
 *
 * Permission semantics: an entry with no `permissions` is always visible. An entry
 * with `permissions: ['x','y']` is visible if the user has ANY of `x` or `y`.
 * Users with `role: 'admin'` bypass all permission checks (admins see everything).
 */
export function resolvePluginMenuItems(
  user?: { permissions?: readonly string[]; role?: string }
): ResolvedPluginMenuEntry[] {
  const isAdmin = user?.role === 'admin'
  const userPerms = new Set(user?.permissions ?? [])
  return menuItems
    .filter((m) => {
      if (!m.permissions || m.permissions.length === 0) return true
      if (isAdmin) return true
      return m.permissions.some((p) => userPerms.has(p))
    })
    .slice()
    .sort((a, b) => (a.order ?? 100) - (b.order ?? 100))
    .map((m) => ({
      label: m.label,
      path: m.path,
      icon: resolveIcon(m.icon),
      order: m.order ?? 100,
      pluginId: m.pluginId,
    }))
}
