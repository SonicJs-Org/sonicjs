/**
 * SonicJS Stats Collector
 *
 * Self-hosted telemetry collection using SonicJS
 * Tracks anonymous installation metrics
 */

import { createSonicJSApp, registerCollections } from '@sonicjs-cms/core'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import collections
import installsCollection from './collections/installs.collection'
import eventsCollection from './collections/events.collection'

// Import plugins
import { statsDashboardPlugin } from './plugins/stats-dashboard'

// Register collections
registerCollections([
  installsCollection,
  eventsCollection,
])

// Application configuration
const config: SonicJSConfig = {
  collections: {
    autoSync: true
  },
  plugins: {
    autoLoad: false,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- DefinedPlugin is structurally compatible; type mismatch is dist/src version skew
    register: [statsDashboardPlugin as any],
  }
}

const app = createSonicJSApp(config)

// Unauthenticated telemetry ingestion for create-sonicjs CLI.
// CLI posts to /v1/events; this handler writes directly to D1 bypassing ACL.
app.post('/v1/events', async (c) => {
  try {
    const body = await c.req.json<{ data?: Record<string, unknown> }>()
    const data = body.data ?? {}
    const { installation_id, event_type, properties, timestamp } = data as {
      installation_id?: string
      event_type?: string
      properties?: unknown
      timestamp?: string
    }

    if (!installation_id || !event_type) {
      return c.json({ error: 'Missing required fields' }, 400)
    }

    const db = c.env.DB as D1Database
    const now = Math.floor(Date.now() / 1000)
    const id = crypto.randomUUID()
    const title = `${installation_id} - ${event_type}`
    // CF-IPCountry is a 2-letter ISO code injected by Cloudflare — no geo lookup needed, non-PII
    const country = c.req.header('CF-IPCountry') ?? null

    await db.prepare(
      `INSERT INTO documents
         (id, root_id, type_id, is_published, status, title, data, published_at, created_at, updated_at)
       VALUES (?, ?, 'events', 1, 'published', ?, ?, ?, ?, ?)`
    ).bind(
      id, id, title,
      JSON.stringify({ installation_id, event_type, properties: properties ?? {}, timestamp: timestamp ?? new Date().toISOString(), country }),
      now, now, now
    ).run()

    return c.json({ success: true }, 201)
  } catch (err) {
    // Log so CF Worker logs surface the failure — callers still see success
    console.error('[stats] /v1/events insert failed:', err)
    return c.json({ success: true }, 201)
  }
})

// Stats-specific health check — /health taken by core, /v1/* taken by API routes
app.get('/stats-health', async (c) => {
  try {
    const db = c.env.DB as D1Database
    const result = await db.prepare('SELECT COUNT(*) AS n FROM documents WHERE type_id = ?').bind('events').first<{ n: number }>()
    return c.json({ ok: true, event_count: result?.n ?? 0 })
  } catch (err) {
    console.error('[stats] /health D1 check failed:', err)
    return c.json({ ok: false, error: String(err) }, 500)
  }
})

export default app
