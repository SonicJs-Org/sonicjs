/**
 * Regression test: every plugin mounted via createSonicJSApp's
 * mountPluginManagerRoutes call must also be present in
 * BOOTSTRAP_PLUGIN_IDS, or the DB-backed `is_active` gate denies its
 * routes (404) on every request.
 *
 * Also: every plugin's `name` must equal its manifest `id`, because the
 * gate (and the plugins table key) uses the id but the gate is fed the
 * name from the registered Plugin.
 */

import { describe, it, expect } from 'vitest'

// Plugins fed to mountPluginManagerRoutes inside createSonicJSApp.
// Source: packages/core/src/app.ts.
const MOUNTED_PLUGIN_NAMES = [
  'security-audit',
  'ai-search',
  'oauth-providers',
  'user-profiles',
  'otp-login',
  'core-analytics',
  'stripe',
  'email',
  'magic-link-auth',
  'global-variables',
]

describe('plugin registration coverage', () => {
  it('every plugin mounted in app.ts is also bootstrapped', async () => {
    const file = await import('../services/plugin-bootstrap')
    // BOOTSTRAP_PLUGIN_IDS isn't exported, so derive coverage from the
    // service's runtime behavior: PluginBootstrapService.CORE_PLUGINS
    // exposes the resolved list. We just instantiate it with a stub DB.
    const stubDb: any = { prepare: () => ({ first: async () => null }) }
    const svc = new file.PluginBootstrapService(stubDb)
    const ids = (svc as any).CORE_PLUGINS.map((p: any) => p.id) as string[]

    for (const name of MOUNTED_PLUGIN_NAMES) {
      expect(
        ids,
        `plugin "${name}" is mounted via mountPluginManagerRoutes in app.ts ` +
          `but missing from BOOTSTRAP_PLUGIN_IDS — its admin routes will 404 ` +
          `because is_active is never set in the plugins table.`
      ).toContain(name)
    }
  })

  it('aiSearchPlugin.name matches its manifest.id (not display name)', async () => {
    const { aiSearchPlugin } = await import(
      './core-plugins/ai-search-plugin'
    )
    expect(aiSearchPlugin.name).toBe('ai-search')
  })

  it('turnstilePlugin.name matches its manifest.id (not display name)', async () => {
    const { turnstilePlugin } = await import(
      './core-plugins/turnstile-plugin'
    )
    expect(turnstilePlugin.name).toBe('turnstile')
  })
})
