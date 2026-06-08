import { describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { PluginBuilder } from '../../plugins/sdk/plugin-builder'
import { mountPluginManagerRoutes } from '../../app'
import type { Bindings, Variables } from '../../app'

describe('mountPluginManagerRoutes', () => {
  it('responds for enabled plugin routes', async () => {
    const pluginRoutes = new Hono().get('/', (c) => c.text('active plugin'))
    const plugin = PluginBuilder.create({
      name: 'active-plugin',
      version: '1.0.0'
    })
      .addRoute('/api/active-plugin', pluginRoutes)
      .build()

    const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()
    const isPluginEnabled = vi.fn(async (pluginName: string) => pluginName === 'active-plugin')

    mountPluginManagerRoutes(app, [plugin], { isPluginEnabled })

    const response = await app.request('http://localhost/api/active-plugin')

    expect(response.status).toBe(200)
    expect(await response.text()).toBe('active plugin')
    expect(isPluginEnabled).toHaveBeenCalledWith('active-plugin', expect.anything())
  })

  it('returns 404 for inactive plugin routes', async () => {
    const pluginRoutes = new Hono().get('/', (c) => c.text('inactive plugin'))
    const plugin = PluginBuilder.create({
      name: 'inactive-plugin',
      version: '1.0.0'
    })
      .addRoute('/api/inactive-plugin', pluginRoutes)
      .build()

    const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

    mountPluginManagerRoutes(app, [plugin], {
      isPluginEnabled: vi.fn(async () => false)
    })

    const response = await app.request('http://localhost/api/inactive-plugin')

    expect(response.status).toBe(404)
  })
})
