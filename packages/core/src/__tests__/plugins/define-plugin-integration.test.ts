/**
 * End-to-end: a definePlugin() plugin through the real app factory.
 *
 * Proves the v3 authoring API drops into `plugins.register` and is mounted by
 * `createSonicJSApp` with no adapter — the same introspection approach as
 * mount-integration.test.ts (construction needs no Workers bindings).
 */
import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import { createSonicJSApp } from '../../app'
import { definePlugin } from '../../plugins/sdk/define-plugin'

function routePaths(app: ReturnType<typeof createSonicJSApp>): string[] {
  return app.routes.map((r) => r.path)
}
const hasPrefix = (paths: string[], prefix: string) => paths.some((p) => p.startsWith(prefix))

describe('definePlugin via createSonicJSApp', () => {
  it('mounts a v3 plugin passed through plugins.register', () => {
    const plugin = definePlugin({
      id: 'v3-demo',
      version: '1.0.0',
      routes: [{ path: '/api/v3-demo', handler: new Hono().get('/', (c) => c.json({ ok: true })) }],
    })
    const app = createSonicJSApp({ plugins: { register: [plugin as any] } })
    expect(hasPrefix(routePaths(app), '/api/v3-demo')).toBe(true)
  })

  it('honors disableAll for v3 plugins too', () => {
    const plugin = definePlugin({
      id: 'v3-off',
      version: '1.0.0',
      routes: [{ path: '/api/v3-off', handler: new Hono().get('/', (c) => c.text('x')) }],
    })
    const app = createSonicJSApp({ plugins: { disableAll: true, register: [plugin as any] } })
    expect(hasPrefix(routePaths(app), '/api/v3-off')).toBe(false)
  })

  it('runs a v3 plugin onBoot once on the first request (live wiring)', async () => {
    let boots = 0
    const plugin = definePlugin({
      id: 'v3-boot',
      version: '1.0.0',
      // public route so we can drive a request without admin auth
      routes: [{ path: '/api/v3-boot/ping', handler: new Hono().get('/', (c) => c.text('pong')) }],
      onBoot() {
        boots++
      },
    })

    const app = createSonicJSApp({ plugins: { register: [plugin as any] } })

    // Two requests; onBoot must run exactly once (once-guarded wiring).
    await app.request('/api/v3-boot/ping', {}, { DB: undefined, CACHE_KV: undefined } as any)
    await app.request('/api/v3-boot/ping', {}, { DB: undefined, CACHE_KV: undefined } as any)

    expect(boots).toBe(1)
  })
})
