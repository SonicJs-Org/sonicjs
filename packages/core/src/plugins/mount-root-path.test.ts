/**
 * Regression test: a plugin route with path === '/' (mounted at root)
 * must still resolve when other prefixed routes are registered around it.
 *
 * The contact-form plugin uses this pattern: addRoute('/', publicRoutes)
 * where publicRoutes has app.get('/contact', ...). Failure here = 404 on
 * /contact end-to-end.
 */

import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import { mountPlugin } from './mount'
import type { Plugin } from './types'

describe('mountPlugin with root path', () => {
  it('resolves a /contact route when plugin is mounted at /', async () => {
    const app = new Hono()

    app.route('/api', new Hono().get('/foo', (c) => c.text('foo')))

    const publicRoutes = new Hono().get('/contact', (c) => c.text('contact'))
    const plugin: Plugin = {
      name: 'contact-form',
      version: '1.0.0',
      routes: [{ path: '/', handler: publicRoutes }],
    }
    mountPlugin(app, plugin)

    app.route('/admin', new Hono().get('/', (c) => c.text('admin')))
    app.notFound((c) => c.json({ error: 'Not Found' }, 404))

    const res = await app.request('/contact')
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('contact')
  })
})
