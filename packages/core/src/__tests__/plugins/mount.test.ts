import { describe, it, expect, vi, afterEach } from 'vitest'
import { Hono } from 'hono'
import {
  mountPlugin,
  registerPluginRoutes,
  PluginRegisterMustBeSyncError,
  type MountablePlugin,
} from '../../plugins/mount'

// A small plugin factory: one Hono sub-app that returns its label for GET /.
function makeRoute(label: string): Hono {
  const r = new Hono()
  r.get('/', (c) => c.text(label))
  return r
}

async function get(app: Hono, path: string): Promise<{ status: number; body: string }> {
  const res = await app.request(path)
  return { status: res.status, body: await res.text() }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('mountPlugin', () => {
  it('mounts a single declarative route', async () => {
    const app = new Hono()
    const plugin: MountablePlugin = {
      name: 'solo',
      routes: [{ path: '/solo', handler: makeRoute('solo-ok') }],
    }

    mountPlugin(app, plugin)

    expect(await get(app, '/solo')).toEqual({ status: 200, body: 'solo-ok' })
  })

  it('mounts multiple routes from one plugin', async () => {
    const app = new Hono()
    const plugin: MountablePlugin = {
      name: 'multi',
      routes: [
        { path: '/a', handler: makeRoute('a') },
        { path: '/b', handler: makeRoute('b') },
      ],
    }

    mountPlugin(app, plugin)

    expect((await get(app, '/a')).body).toBe('a')
    expect((await get(app, '/b')).body).toBe('b')
  })

  it('is a no-op for a plugin with no routes and no register()', async () => {
    const app = new Hono()
    const result = { mounted: [], skipped: [] }
    mountPlugin(app, { name: 'empty' }, result)
    expect(result.mounted).toHaveLength(0)
    expect(result.skipped).toHaveLength(0)
  })

  it('skips an invalid plugin object instead of throwing', () => {
    const app = new Hono()
    const result = { mounted: [], skipped: [] }
    // @ts-expect-error intentionally invalid
    mountPlugin(app, null, result)
    // @ts-expect-error intentionally invalid (no name)
    mountPlugin(app, { routes: [] }, result)
    expect(result.skipped.length).toBeGreaterThan(0)
  })

  it('skips a route entry missing a path or handler', () => {
    const app = new Hono()
    const result = { mounted: [], skipped: [] }
    const plugin: MountablePlugin = {
      name: 'bad-route',
      // @ts-expect-error intentionally malformed route
      routes: [{ path: '/ok', handler: makeRoute('ok') }, { path: '', handler: undefined }],
    }
    mountPlugin(app, plugin, result)
    expect(result.mounted).toHaveLength(1)
    expect(result.skipped).toHaveLength(1)
  })

  it('calls a synchronous register(app) hook', async () => {
    const app = new Hono()
    const plugin: MountablePlugin = {
      name: 'imperative',
      register(a) {
        a.route('/imp', makeRoute('imp-ok'))
      },
    }

    mountPlugin(app, plugin)

    expect((await get(app, '/imp')).body).toBe('imp-ok')
  })

  it('throws PluginRegisterMustBeSyncError when register() returns a Promise', () => {
    const app = new Hono()
    const plugin: MountablePlugin = {
      name: 'async-bad',
      // eslint-disable-next-line @typescript-eslint/require-await
      register: async () => {
        /* returns a Promise — illegal */
      },
    }

    expect(() => mountPlugin(app, plugin)).toThrow(PluginRegisterMustBeSyncError)
    expect(() => mountPlugin(app, plugin)).toThrow(/must be synchronous/)
  })
})

describe('registerPluginRoutes', () => {
  it('mounts a list of plugins in array order', async () => {
    const app = new Hono()
    const result = registerPluginRoutes(app, [
      { name: 'p1', routes: [{ path: '/p1', handler: makeRoute('p1') }] },
      { name: 'p2', routes: [{ path: '/p2', handler: makeRoute('p2') }] },
    ])

    expect((await get(app, '/p1')).body).toBe('p1')
    expect((await get(app, '/p2')).body).toBe('p2')
    expect(result.mounted.map((m) => m.path)).toEqual(['/p1', '/p2'])
  })

  it('ignores null/undefined entries', () => {
    const app = new Hono()
    const result = registerPluginRoutes(app, [
      null,
      undefined,
      { name: 'p', routes: [{ path: '/p', handler: makeRoute('p') }] },
    ])
    expect(result.mounted).toHaveLength(1)
  })

  it('mounts routes ordered by descending priority within a plugin', () => {
    const app = new Hono()
    const plugin: MountablePlugin = {
      name: 'prio',
      routes: [
        { path: '/low', handler: makeRoute('low'), priority: 1 },
        { path: '/high', handler: makeRoute('high'), priority: 100 },
        { path: '/mid', handler: makeRoute('mid'), priority: 50 },
      ],
    }
    const result = registerPluginRoutes(app, [plugin])
    expect(result.mounted.map((m) => m.path)).toEqual(['/high', '/mid', '/low'])
  })

  it('preserves declaration order for equal/absent priorities (stable)', () => {
    const app = new Hono()
    const plugin: MountablePlugin = {
      name: 'stable',
      routes: [
        { path: '/first', handler: makeRoute('first') },
        { path: '/second', handler: makeRoute('second') },
        { path: '/third', handler: makeRoute('third') },
      ],
    }
    const result = registerPluginRoutes(app, [plugin])
    expect(result.mounted.map((m) => m.path)).toEqual(['/first', '/second', '/third'])
  })

  it('warns when two plugins claim the same route path', () => {
    const app = new Hono()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    registerPluginRoutes(
      app,
      [
        { name: 'first', routes: [{ path: '/dup', handler: makeRoute('first') }] },
        { name: 'second', routes: [{ path: '/dup', handler: makeRoute('second') }] },
      ],
      { warnOnDuplicatePath: true }
    )
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('Duplicate route path "/dup"'))
  })

  it('does not warn on duplicates when disabled', () => {
    const app = new Hono()
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    registerPluginRoutes(
      app,
      [
        { name: 'first', routes: [{ path: '/dup', handler: makeRoute('first') }] },
        { name: 'second', routes: [{ path: '/dup', handler: makeRoute('second') }] },
      ],
      { warnOnDuplicatePath: false }
    )
    expect(warn).not.toHaveBeenCalled()
  })

  it('first registration wins for a duplicate path (Hono first-match)', async () => {
    const app = new Hono()
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    registerPluginRoutes(app, [
      { name: 'first', routes: [{ path: '/dup', handler: makeRoute('first-wins') }] },
      { name: 'second', routes: [{ path: '/dup', handler: makeRoute('second-loses') }] },
    ])
    expect((await get(app, '/dup')).body).toBe('first-wins')
  })

  it('plugin /admin routes are not shadowed by a later /admin catch-all', async () => {
    // Reproduces the app.ts ordering in miniature: plugin routes mount BEFORE
    // the bare `/admin` catch-all (adminUsersRoutes), so a plugin-owned
    // /admin/<x> page wins. This is the precedence guarantee behind mounting
    // plugins before the catch-all.
    const app = new Hono()

    registerPluginRoutes(app, [
      { name: 'feature', routes: [{ path: '/admin/my-feature', handler: makeRoute('feature') }] },
    ])

    // Bare /admin catch-all registered AFTER the plugin (mirrors app.ts).
    const adminCatchAll = new Hono()
    adminCatchAll.all('/*', (c) => c.text('catch-all'))
    app.route('/admin', adminCatchAll)

    expect((await get(app, '/admin/my-feature')).body).toBe('feature')
    // The catch-all still handles unclaimed /admin paths.
    expect((await get(app, '/admin/something-else')).body).toBe('catch-all')
  })

  it('propagates a sync-contract violation from any plugin in the list', () => {
    const app = new Hono()
    expect(() =>
      registerPluginRoutes(app, [
        { name: 'ok', routes: [{ path: '/ok', handler: makeRoute('ok') }] },
        { name: 'bad', register: async () => {} },
      ])
    ).toThrow(PluginRegisterMustBeSyncError)
  })
})
