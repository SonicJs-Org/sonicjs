/**
 * Cache Prewarm Plugin
 *
 * Runs on a cron schedule to keep all filter-combo pages of the employees
 * collection pre-cached in KV so the first user request of the day is always
 * a KV hit, not a cold D1 query.
 *
 * Schedule: every 6 hours (must also appear in wrangler.client-backend.toml
 * under [triggers] crons).
 *
 * Required env var:
 *   CACHE_PREWARM_BASE_URL – origin of this Worker, e.g.
 *                            https://speed-backend.sonicjs.com
 */

import { definePlugin, prewarmFilterCombinations } from '@sonicjs-cms/core'
import type { CronTickEvent, CronContext } from '@sonicjs-cms/core'

const SCHEDULE    = '0 */6 * * *'  // every 6 hours
const HOOK_FAMILY = 'cache-prewarm'

export const cachePrwarmPlugin = definePlugin({
  id:      'cache-prewarm',
  version: '1.0.0',
  name:    'Cache Prewarm',

  crons: [{ schedule: SCHEDULE, hookFamily: HOOK_FAMILY }],

  async onCronTick(event: CronTickEvent, ctx: CronContext) {
    if (event.hookFamily !== HOOK_FAMILY) return

    const env     = (ctx.env ?? {}) as Record<string, unknown>
    const db      = env['DB']                     as D1Database | undefined
    const baseUrl = env['CACHE_PREWARM_BASE_URL'] as string    | undefined

    if (!db) {
      console.warn('[cache-prewarm] DB binding not available, skipping')
      return
    }
    if (!baseUrl) {
      console.warn('[cache-prewarm] CACHE_PREWARM_BASE_URL not set, skipping')
      return
    }

    console.log('[cache-prewarm] Starting scheduled prewarm…')
    try {
      const result = await prewarmFilterCombinations({
        db,
        baseUrl,
        // Sort must match the demo client's sort so cache keys align:
        // JSON.stringify([{ field: 'data.phone', order: 'asc' }])
        sort: JSON.stringify([{ field: 'data.phone', order: 'asc' }]),
        // defaults: employees × departments × regions, 3 pages of 10
      })
      console.log(
        `[cache-prewarm] Done: ${result.warmed}/${result.total} URLs warmed` +
        ` (${result.combinations} combos × ${result.pages} pages,` +
        ` ${result.errors} errors)`
      )
    } catch (err) {
      console.error('[cache-prewarm] Prewarm failed:', err)
    }
  },
})
