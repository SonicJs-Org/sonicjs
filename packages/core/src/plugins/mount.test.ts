/**
 * Tests for the plugin mount helper used by createSonicJSApp to wire
 * user-registered plugins into the Hono app.
 */

import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import { mountPlugin } from './mount'
import type { Plugin } from './types'

function makePlugin(overrides: Partial<Plugin> = {}): Plugin {
  return {
    name: 'test-plugin',
    version: '1.0.0',
    ...overrides,
  }
}

describe('mountPlugin', () => {
  it('mounts plugin routes onto the app', async () => {
    const app = new Hono()
    const handler = new Hono().get('/ping', (c) => c.json({ ok: true }))

    mountPlugin(
      app,
      makePlugin({
        routes: [{ path: '/api/test', handler }],
      })
    )

    const res = await app.request('/api/test/ping')
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: true })
  })

  it('mounts multiple routes from one plugin', async () => {
    const app = new Hono()
    const a = new Hono().get('/', (c) => c.text('a'))
    const b = new Hono().get('/', (c) => c.text('b'))

    mountPlugin(
      app,
      makePlugin({
        routes: [
          { path: '/a', handler: a },
          { path: '/b', handler: b },
        ],
      })
    )

    expect(await (await app.request('/a')).text()).toBe('a')
    expect(await (await app.request('/b')).text()).toBe('b')
  })

  it('applies global middleware to all routes', async () => {
    const app = new Hono()
    const handler = new Hono().get('/', (c) => c.text(c.get('marker') ?? 'no'))

    mountPlugin(
      app,
      makePlugin({
        middleware: [
          {
            name: 'marker',
            global: true,
            handler: async (c, next) => {
              c.set('marker', 'yes')
              await next()
            },
          },
        ],
        routes: [{ path: '/x', handler }],
      })
    )

    expect(await (await app.request('/x')).text()).toBe('yes')
  })

  it('scopes middleware to routes when not global', async () => {
    const app = new Hono()
    const scoped = new Hono().get('/', (c) => c.text(c.get('hit') ?? 'no'))
    const other = new Hono().get('/', (c) => c.text(c.get('hit') ?? 'no'))

    mountPlugin(
      app,
      makePlugin({
        middleware: [
          {
            name: 'scoped',
            routes: ['/scoped/*'],
            handler: async (c, next) => {
              c.set('hit', 'yes')
              await next()
            },
          },
        ],
        routes: [
          { path: '/scoped', handler: scoped },
          { path: '/other', handler: other },
        ],
      })
    )

    expect(await (await app.request('/scoped')).text()).toBe('yes')
    expect(await (await app.request('/other')).text()).toBe('no')
  })

  it('runs middleware in priority order (lower first)', async () => {
    const app = new Hono()
    const order: string[] = []
    const handler = new Hono().get('/', (c) => c.json(order))

    mountPlugin(
      app,
      makePlugin({
        middleware: [
          {
            name: 'late',
            global: true,
            priority: 100,
            handler: async (_c, next) => {
              order.push('late')
              await next()
            },
          },
          {
            name: 'early',
            global: true,
            priority: 1,
            handler: async (_c, next) => {
              order.push('early')
              await next()
            },
          },
        ],
        routes: [{ path: '/p', handler }],
      })
    )

    await app.request('/p')
    expect(order).toEqual(['early', 'late'])
  })

  it('is a no-op for plugins with no routes or middleware', () => {
    const app = new Hono()
    expect(() => mountPlugin(app, makePlugin())).not.toThrow()
  })
})
