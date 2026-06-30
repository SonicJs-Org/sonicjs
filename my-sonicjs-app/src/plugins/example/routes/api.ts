/**
 * Example Plugin — Public API Routes
 *
 * Hono is SonicJS's HTTP framework. Each "route file" creates a small Hono app
 * (or returns one from a factory function) and exports it. The plugin's
 * `register(app)` call mounts these routes onto the root application.
 *
 * Route files are SYNCHRONOUS setup — they only wire up handlers, no async I/O.
 * Anything that needs env/DB access goes in the handler itself (called per-request)
 * or in the plugin's `onBoot` (called once per isolate warm-up).
 *
 * PATH NOTE: These routes are mounted at /example (NOT /api/...).
 * User plugins mount after the core /api/:collection catch-all, so any
 * /api/your-plugin path would be swallowed by the collection handler. See
 * the plugin index.ts register() comment for the full explanation.
 */

import { Hono } from 'hono'
import { DocumentRepository, PluginServiceClass as PluginService } from '@sonicjs-cms/core'

const MOODS_TYPE_ID = 'example'

async function getPluginSettings(db: any): Promise<{ greeting: string; defaultName: string }> {
  const defaults = { greeting: 'Hello, Cruel World!', defaultName: 'Stranger' }
  if (!db) return defaults
  try {
    const svc = new PluginService(db)
    const plugin = await svc.getPlugin('example')
    const s = (plugin?.settings ?? {}) as Record<string, unknown>
    return {
      greeting: typeof s.greeting === 'string' ? s.greeting : defaults.greeting,
      defaultName: typeof s.defaultName === 'string' ? s.defaultName : defaults.defaultName,
    }
  } catch {
    return defaults
  }
}

/**
 * Pick a random published mood from the DB, or null if none exist yet.
 * Uses DocumentRepository (the tenant-scoped read chokepoint — R4).
 */
async function getRandomMood(db: any): Promise<{ name: string; emoji: string; description: string } | null> {
  try {
    const repo = new DocumentRepository(db, 'default')
    const moods = await repo.list({ typeId: MOODS_TYPE_ID, status: 'published', limit: 100 })
    if (moods.length === 0) return null
    // Workers has no Math.random() restriction — safe to use here.
    const pick = moods[Math.floor(Math.random() * moods.length)]
    return pick.data as { name: string; emoji: string; description: string }
  } catch {
    return null
  }
}

/**
 * createExampleApiRoutes — factory that returns the public API router.
 *
 * Settings are read from the DB on each request so changes made via the admin UI
 * take effect immediately without waiting for a Worker isolate restart.
 */
export function createExampleApiRoutes(): Hono {
  const router = new Hono()

  // ── GET /example ────────────────────────────────────────────────────────────
  // Returns a JSON greeting with a randomly-selected mood from the moods collection.
  // c.env holds Cloudflare bindings (DB, KV, etc.) — accessed per-request, not at setup.
  router.get('/', async (c) => {
    const db = (c.env as any)?.DB
    const [mood, settings] = await Promise.all([
      db ? getRandomMood(db) : Promise.resolve(null),
      getPluginSettings(db),
    ])
    const name = settings.defaultName

    return c.json({
      message: `${settings.greeting} I am ${name}.`,
      mood: mood ? `${mood.emoji} ${mood.name}`.trim() : null,
      moodDescription: mood?.description ?? null,
      timestamp: new Date().toISOString(),
      plugin: 'example',
    })
  })

  // ── GET /example/moods ──────────────────────────────────────────────────────
  // Lists all published moods — must be registered BEFORE /:name so Hono's
  // route-registration-order matching doesn't swallow it as a name param.
  router.get('/moods', async (c) => {
    const db = (c.env as any)?.DB
    if (!db) return c.json({ moods: [] })

    try {
      const repo = new DocumentRepository(db, 'default')
      const docs = await repo.list({ typeId: MOODS_TYPE_ID, status: 'published', limit: 100 })
      return c.json({
        moods: docs.map(d => d.data),
        total: docs.length,
      })
    } catch {
      return c.json({ moods: [], total: 0 })
    }
  })

  // ── GET /example/:name ──────────────────────────────────────────────────────
  // Personalised greeting — :name from the URL, random mood from the collection.
  // Registered AFTER /moods so the literal path wins.
  router.get('/:name', async (c) => {
    const db = (c.env as any)?.DB
    const [mood, settings] = await Promise.all([
      db ? getRandomMood(db) : Promise.resolve(null),
      getPluginSettings(db),
    ])
    const name = c.req.param('name')

    return c.json({
      message: `${settings.greeting} I am ${name}.`,
      mood: mood ? `${mood.emoji} ${mood.name}`.trim() : null,
      moodDescription: mood?.description ?? null,
      timestamp: new Date().toISOString(),
      plugin: 'example',
    })
  })

  return router
}
