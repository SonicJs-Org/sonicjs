/**
 * How many D1 round trips the sidebar costs per admin request.
 *
 * `pluginMenuMiddleware` runs on EVERY `/admin/*` request — the page itself plus each of the four
 * dashboard htmx fragments, so a single visit to /admin pays for it five times. It used to issue
 * two serial queries: one for the plugins in the compiled manifest, one for the plugins
 * `config.plugins.register` feeds in. Same table, same tenant, same WHERE clause — only the slug
 * list differed, so they now go out as one statement.
 *
 * Counting statements is the one thing a mock DB is good for (R10): it cannot verify SQL, but the
 * number of `prepare` calls is exactly the property that regressed and exactly what a future edit
 * splitting the lookup back apart would change.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { setPluginMenu, resetPluginMenu } from '../../services/plugin-menu-singleton'

const { pluginMenuMiddleware } = await import('../../middleware/plugin-menu')

type MenuItem = { label: string; path: string; icon: string }

async function runMiddleware(activeSlugs: string[]) {
  const statements: string[] = []
  const binds: unknown[][] = []
  const captured: Record<string, unknown> = {}

  const c = {
    env: {
      DB: {
        prepare: (sql: string) => {
          statements.push(sql)
          return {
            bind: (...args: unknown[]) => {
              binds.push(args)
              return {
                all: async () => ({
                  results: activeSlugs.filter((s) => args.includes(s)).map((slug) => ({ slug })),
                }),
              }
            },
            all: async () => ({ results: [] }),
            first: async () => null,
          }
        },
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
  return {
    statements,
    binds,
    items: (captured['pluginMenuItems'] as MenuItem[]) ?? [],
  }
}

describe('pluginMenuMiddleware D1 usage', () => {
  afterEach(() => {
    resetPluginMenu()
  })

  it('resolves manifest and registered plugins in a single statement', async () => {
    setPluginMenu([
      { label: 'Billing', path: '/admin/billing', pluginId: 'billing-plugin', order: 10 },
      { label: 'Reports', path: '/admin/reports', pluginId: 'reports-plugin', order: 20 },
    ])

    const { statements, binds } = await runMiddleware([])

    expect(
      statements,
      `sidebar issued ${statements.length} D1 statements; it runs on every /admin request ` +
        '(page + 4 dashboard fragments) so each extra one is paid 5x per dashboard visit'
    ).toHaveLength(1)

    // Both sources' ids have to reach that one statement, or one of them silently stops being
    // active-checked and its entries disappear from (or wrongly persist in) the sidebar.
    expect(binds[0]).toContain('billing-plugin')
    expect(binds[0]).toContain('reports-plugin')
  })

  it('still hides a registered plugin whose document row is inactive', async () => {
    setPluginMenu([
      { label: 'Billing', path: '/admin/billing', pluginId: 'billing-plugin', order: 10 },
      { label: 'Reports', path: '/admin/reports', pluginId: 'reports-plugin', order: 20 },
    ])

    // Only billing comes back as active — issue #971: a plugin disabled in the admin UI stays in
    // config but its document row flips inactive.
    const { items } = await runMiddleware(['billing-plugin'])
    const paths = items.map((i) => i.path)

    expect(paths).toContain('/admin/billing')
    expect(paths).not.toContain('/admin/reports')
  })

  it('shows a registered entry that declares no pluginId even when nothing is active', async () => {
    setPluginMenu([{ label: 'Docs', path: '/admin/docs', order: 10 }])

    const { items } = await runMiddleware([])

    expect(items.map((i) => i.path)).toContain('/admin/docs')
  })

  it('renders the sidebar rather than throwing when the plugin rows are missing', async () => {
    setPluginMenu([{ label: 'Docs', path: '/admin/docs', order: 10 }])

    const captured: Record<string, unknown> = {}
    const c = {
      env: {
        DB: {
          prepare: () => ({
            bind: () => ({
              all: async () => {
                throw new Error('no such table: documents')
              },
            }),
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

    await expect(pluginMenuMiddleware()(c as never, async () => {})).resolves.toBeUndefined()

    // Fail open: entries without a pluginId survive a DB that cannot answer.
    expect((captured['pluginMenuItems'] as MenuItem[]).map((i) => i.path)).toContain('/admin/docs')
  })

  it('publishes the resolved slugs for the rest of the admin chain', async () => {
    setPluginMenu([{ label: 'Billing', path: '/admin/billing', pluginId: 'billing-plugin', order: 10 }])

    const captured: Record<string, unknown> = {}
    const c = {
      env: {
        DB: {
          prepare: () => ({
            bind: (...args: unknown[]) => ({
              all: async () => ({
                results: ['billing-plugin', 'menu']
                  .filter((s) => args.includes(s))
                  .map((slug) => ({ slug })),
              }),
            }),
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

    const slugs = captured['activePluginSlugs'] as Set<string>
    expect(slugs, 'downstream middleware falls back to its own query without this').toBeInstanceOf(Set)
    expect(slugs.has('billing-plugin')).toBe(true)

    // `menu` contributes no sidebar entry (adminMenu: null) but menuMiddleware needs its status,
    // so it has to ride along in the same statement rather than costing a second one.
    expect(slugs.has('menu'), 'menu plugin status must come from the shared lookup').toBe(true)
  })

  it('skips the lookup entirely off the admin surface', async () => {
    setPluginMenu([{ label: 'Docs', path: '/admin/docs', order: 10 }])

    const statements: string[] = []
    const c = {
      env: {
        DB: {
          prepare: (sql: string) => {
            statements.push(sql)
            return { bind: () => ({ all: async () => ({ results: [] }) }) }
          },
        },
      },
      req: { path: '/api/content', url: 'http://localhost/api/content' },
      res: new Response('{}', { headers: { 'content-type': 'application/json' } }),
      get: () => undefined,
      set: () => {},
    }

    await pluginMenuMiddleware()(c as never, async () => {})
    expect(statements, 'public API requests must not pay for the admin sidebar').toHaveLength(0)
  })
})
