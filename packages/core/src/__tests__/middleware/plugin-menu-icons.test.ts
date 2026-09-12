/**
 * Sidebar icon resolution for plugin menu entries.
 *
 * The bug this pins was visible on every page of the admin panel: the sidebar showed the literal
 * text `lock-closed` where the Two-Factor Auth icon belongs, and `book-open` for API Reference.
 * Both plugins declare an icon NAME in their manifest, `middleware/plugin-menu.ts` could not
 * resolve either name, and the fallback was `resolveIcon(m.icon) || m.icon` — so the unresolved
 * name was handed to the catalyst layout, which interpolates it as markup.
 *
 * Nothing caught it because both the resolved SVG and the raw name are `string`: the types agree,
 * the page renders, and only a human looking at the sidebar can see the difference. So these
 * assert the one property that distinguishes them — the value must be SVG markup, never a name.
 */
import { describe, it, expect } from 'vitest'
import { PLUGIN_REGISTRY } from '../../plugins/manifest-registry'

// The module keeps ICON_SVG/resolveIcon private, so drive them the way the app does: through the
// exported middleware, with a context stub that captures what it sets on `pluginMenuItems`.
const { pluginMenuMiddleware } = await import('../../middleware/plugin-menu')

type MenuItem = { label: string; path: string; icon: string }

/**
 * Run the middleware and return what it set for rendering.
 *
 * `activeSlugs` drives the MANIFEST path (plugins listed in PLUGIN_REGISTRY whose document row is
 * active). That is the path that carried the bug: those entries reach the final projection with
 * their raw manifest icon NAME. The singleton path is deliberately not used here — its entries are
 * pre-resolved by `resolvePluginMenuItems`, so a test driving it passes either way. An earlier
 * version of this file made exactly that mistake and stayed green against the broken code.
 */
async function renderMenu(activeSlugs: string[]) {
  const captured: Record<string, unknown> = {}
  const c = {
    env: {
      DB: {
        prepare: () => ({
          bind: () => ({ all: async () => ({ results: activeSlugs.map((slug) => ({ slug })) }) }),
          all: async () => ({ results: [] }),
          first: async () => null,
        }),
      },
    },
    req: { path: '/admin', url: 'http://localhost/admin' },
    res: new Response('<html></html>', { headers: { 'content-type': 'text/html' } }),
    get: (k: string) => captured[k],
    set: (k: string, v: unknown) => {
      captured[k] = v
    },
  }

  await pluginMenuMiddleware()(c as never, async () => {})
  return (captured['pluginMenuItems'] as MenuItem[]) ?? []
}

/** SVG markup, as opposed to a bare icon name that would render as text. */
function isSvgMarkup(icon: string) {
  return icon.trim().startsWith('<svg') && icon.includes('</svg>')
}

/** Every plugin whose manifest puts an entry in the sidebar. */
const MENU_PLUGINS = Object.entries(PLUGIN_REGISTRY)
  .map(([, p]) => p as { id: string; adminMenu?: { icon?: string; label?: string } | null })
  .filter((p) => !!p.adminMenu)

describe('plugin sidebar icons', () => {
  it('renders SVG for every icon the shipped manifests declare', async () => {
    // Driven off the registry rather than a hardcoded list, so adding a plugin whose icon name has
    // no mapping fails here instead of showing the name as text in the sidebar.
    expect(MENU_PLUGINS.length, 'no plugin manifests declare an adminMenu').toBeGreaterThan(0)

    const items = await renderMenu(MENU_PLUGINS.map((p) => p.id))
    expect(items.length).toBe(MENU_PLUGINS.length)

    for (const item of items) {
      expect(isSvgMarkup(item.icon), `"${item.label}" rendered a non-SVG icon: ${item.icon}`).toBe(true)
    }
  })

  it.each(['two-factor-auth', 'api-docs-plugin'])(
    'renders a real icon for %s — both showed their name as text',
    async (slug) => {
      // Only assert on plugins that are actually in the registry, so this does not become a
      // tripwire for unrelated plugin removals.
      if (!MENU_PLUGINS.some((p) => p.id === slug)) return
      const items = await renderMenu([slug])
      expect(items).toHaveLength(1)
      expect(isSvgMarkup(items[0]!.icon)).toBe(true)
    },
  )

  it('never passes an unresolved icon name through as markup', async () => {
    // The regression itself. A plugin id that is in the registry but whose icon name is unknown
    // must render the fallback, never the raw string.
    const target = MENU_PLUGINS[0]!
    const original = target.adminMenu!.icon
    target.adminMenu!.icon = 'no-such-icon-name'
    try {
      const items = await renderMenu([target.id])
      expect(items).toHaveLength(1)
      expect(items[0]!.icon).not.toContain('no-such-icon-name')
      expect(isSvgMarkup(items[0]!.icon)).toBe(true)
    } finally {
      target.adminMenu!.icon = original
    }
  })

  it('renders nothing extra when no plugin is active', async () => {
    expect(await renderMenu([])).toHaveLength(0)
  })
})
