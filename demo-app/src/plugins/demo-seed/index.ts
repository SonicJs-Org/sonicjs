/**
 * Demo Seed plugin
 *
 * Owns the demo's data-reset machinery. Two triggers, one shared `runReseed`:
 *   1. POST /__demo/reseed — called by the deploy workflow after each promotion
 *      to main. Hard-gated: ENVIRONMENT must be 'demo' AND a matching
 *      `Authorization: Bearer <DEMO_SEED_TOKEN>` header.
 *   2. Cron (every 2 hours, schedule in DEMO_RESEED_CRON) — so visitor edits never
 *      persist longer than ~2h even between deploys. Requires `[triggers] crons`
 *      in wrangler.toml.
 *
 * Both paths are env-gated to 'demo' so this plugin can never wipe a real install.
 */

import { definePlugin } from '@sonicjs-cms/core'
import { runReseed, type DemoEnv } from './reseed'

export const DEMO_RESEED_CRON = '0 */2 * * *'
const RESEED_HOOK_FAMILY = 'demo-reseed'

export const demoSeedPlugin = definePlugin({
  id: 'demo-seed',
  name: 'Demo Seed',
  version: '1.0.0',
  description: 'Resets the demo dataset on deploy and every 2 hours.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS' },

  crons: [{ schedule: DEMO_RESEED_CRON, hookFamily: RESEED_HOOK_FAMILY }],

  // Synchronous route registration. `/__demo/*` is top-level (not under /api or
  // /admin), so it dodges both catch-all routers.
  register(app) {
    app.post('/__demo/reseed', async (c: any) => {
      const env = c.env as DemoEnv

      // Gate 1: demo environment only.
      if (env.ENVIRONMENT !== 'demo') {
        return c.json({ error: 'Reseed is only available in the demo environment.' }, 403)
      }

      // Gate 2: bearer token. Refuse if no token is configured.
      const token = env.DEMO_SEED_TOKEN
      const provided = c.req.header('authorization') ?? ''
      if (!token || provided !== `Bearer ${token}`) {
        return c.json({ error: 'Unauthorized.' }, 401)
      }

      try {
        const summary = await runReseed(env)
        console.log('[demo-seed] Reseed via HTTP complete:', summary)
        return c.json({ ok: true, ...summary })
      } catch (e) {
        console.error('[demo-seed] Reseed failed:', e)
        return c.json({ error: 'Reseed failed.', details: e instanceof Error ? e.message : String(e) }, 500)
      }
    })
  },

  async onCronTick(event, ctx) {
    if (event.hookFamily !== RESEED_HOOK_FAMILY) return
    const env = ctx.env as DemoEnv | undefined
    if (!env?.DB) {
      console.warn('[demo-seed] No DB binding in cron env — skipping.')
      return
    }
    // Defense in depth: never wipe a non-demo install from the cron path.
    if (env.ENVIRONMENT !== 'demo') {
      console.warn('[demo-seed] ENVIRONMENT is not "demo" — skipping cron reseed.')
      return
    }
    try {
      const summary = await runReseed(env)
      console.log('[demo-seed] Reseed via cron complete:', summary)
    } catch (e) {
      console.error('[demo-seed] Cron reseed failed:', e)
    }
  },
})

export default demoSeedPlugin
