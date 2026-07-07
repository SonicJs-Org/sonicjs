/**
 * Demo Login plugin
 *
 * Brings back credential autofill on the login page. The capability already
 * lives in core: `renderLoginPage(data, demoLoginActive)` renders a "Demo Mode"
 * notice + prefills admin@sonicjs.com / sonicjs! when `demoLoginActive` is true,
 * and `routes/auth.ts` computes that flag from the active state of the plugin
 * whose id is `demo-login-prefill` (the id MUST match the gate).
 *
 * This plugin's only job is to register itself as an ACTIVE plugin in the DB so
 * the gate flips on. It is hard-gated to ENVIRONMENT === 'demo' so copying it
 * into a real install never auto-enables credential prefill.
 */

import { definePlugin, PluginServiceClass as PluginService } from '@sonicjs-cms/core'
import type { D1Database } from '@cloudflare/workers-types'

/** MUST equal the id queried by routes/auth.ts to gate the login prefill. */
export const DEMO_LOGIN_PLUGIN_ID = 'demo-login-prefill'

/**
 * Idempotently ensure the demo-login plugin row exists and is active.
 * Shared so the demo-seed reseed path can re-assert it after a wipe.
 */
export async function ensureDemoLoginActive(db: D1Database): Promise<void> {
  const svc = new PluginService(db)
  await svc.ensurePlugin(DEMO_LOGIN_PLUGIN_ID, {
    displayName: 'Demo Login',
    description: 'Prefills the login form with demo credentials (admin@sonicjs.com / sonicjs!).',
    author: 'SonicJS',
    version: '1.0.0',
  })
  // ensurePlugin writes status:'active' on first install; activate again to stay
  // idempotent if a prior run left it inactive.
  await svc.activatePlugin(DEMO_LOGIN_PLUGIN_ID).catch(() => {})
}

export const demoLoginPlugin = definePlugin({
  id: DEMO_LOGIN_PLUGIN_ID,
  name: 'Demo Login',
  version: '1.0.0',
  description: 'Prefills the login form with demo credentials for easy site demonstration.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS' },

  async onBoot(ctx) {
    // Defense in depth: only ever activate credential prefill on the demo site.
    if (ctx.env?.ENVIRONMENT !== 'demo') return
    const db = ctx.env?.DB as D1Database | undefined
    if (!db) return
    try {
      await ensureDemoLoginActive(db)
    } catch (e) {
      console.warn('[demo-login] Could not activate demo login prefill:', e)
    }
  },
})

export default demoLoginPlugin
