/**
 * Integration tests for plugin route mounting through the real app factory.
 *
 * These assert against Hono's `app.routes` introspection rather than live
 * requests: `createSonicJSApp()` builds synchronously (DB-dependent bootstrap
 * runs per-request via middleware), so construction needs no Workers bindings,
 * and the registered route table is the precise thing we want to verify.
 */
import { describe, it, expect } from 'vitest'
import { Hono } from 'hono'
import { createSonicJSApp } from '../../app'
import type { Plugin } from '../../plugins/types'

/** Build a custom user plugin that mounts a public route. */
function makeCustomPlugin(): Plugin {
  const routes = new Hono()
  routes.get('/', (c) => c.json({ ok: true }))
  return {
    name: 'custom-test-plugin',
    version: '1.0.0',
    routes: [{ path: '/api/custom-test', handler: routes }],
  }
}

/** Collect the set of registered route paths for easy assertions. */
function routePaths(app: ReturnType<typeof createSonicJSApp>): string[] {
  return app.routes.map((r) => r.path)
}

function hasPathPrefix(paths: string[], prefix: string): boolean {
  return paths.some((p) => p === prefix || p.startsWith(prefix + '/') || p.startsWith(prefix))
}

describe('plugin mounting via createSonicJSApp', () => {
  it('mounts a user plugin passed through plugins.register (no core edits)', () => {
    const app = createSonicJSApp({ plugins: { register: [makeCustomPlugin()] } })
    const paths = routePaths(app)
    expect(hasPathPrefix(paths, '/api/custom-test')).toBe(true)
  })

  it('mounts global-variables and shortcodes routes (regression for #758)', () => {
    // These plugins declare routes via PluginBuilder.addRoute() but were never
    // mounted in app.ts before this fix — their endpoints 404'd in production.
    const app = createSonicJSApp()
    const paths = routePaths(app)
    expect(hasPathPrefix(paths, '/api/global-variables')).toBe(true)
    expect(hasPathPrefix(paths, '/admin/global-variables')).toBe(true)
    expect(hasPathPrefix(paths, '/api/shortcodes')).toBe(true)
    expect(hasPathPrefix(paths, '/admin/shortcodes')).toBe(true)
  })

  it('registers a user plugin admin route into the app', () => {
    // The behavioral "not shadowed by the /admin catch-all" guarantee is tested
    // in mount.test.ts; here we just confirm an /admin-prefixed user plugin
    // route lands in the real app's route table.
    const adminPlugin: Plugin = {
      name: 'admin-page-plugin',
      version: '1.0.0',
      routes: [
        {
          path: '/admin/my-feature',
          handler: new Hono().get('/', (c) => c.text('feature')),
        },
      ],
    }
    const app = createSonicJSApp({ plugins: { register: [adminPlugin] } })
    expect(hasPathPrefix(routePaths(app), '/admin/my-feature')).toBe(true)
  })

  describe('disableAll', () => {
    it('mounts no plugin routes (core or user) when disableAll is true', () => {
      const app = createSonicJSApp({
        plugins: { disableAll: true, register: [makeCustomPlugin()] },
      })
      const paths = routePaths(app)

      // User plugin: not mounted.
      expect(hasPathPrefix(paths, '/api/custom-test')).toBe(false)
      // Core plugins: not mounted.
      expect(hasPathPrefix(paths, '/api/global-variables')).toBe(false)
      expect(hasPathPrefix(paths, '/admin/cache')).toBe(false)
    })

    it('still mounts core framework routes when disableAll is true', () => {
      // disableAll turns off *plugins*, not the core CMS. Core admin/api routes
      // must remain.
      const app = createSonicJSApp({ plugins: { disableAll: true } })
      const paths = routePaths(app)
      expect(hasPathPrefix(paths, '/admin/content')).toBe(true)
      expect(hasPathPrefix(paths, '/api')).toBe(true)
    })
  })
})
