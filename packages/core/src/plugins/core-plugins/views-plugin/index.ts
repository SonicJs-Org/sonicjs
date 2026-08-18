/**
 * views-plugin — no-code views over document-type collections.
 *
 * Saved, named queries (filter/sort/column config, OR-logic groups) over any registered
 * document type, with: a visual admin builder (`/admin/views`), a public JSON/CSV API
 * (`/api/views/:name`, forced published-only), persistent displays (table/cards) and a
 * chromeless public embed (`/v/:path`) with unlisted share tokens, read-through KV caching
 * (CACHE_KV; disjoint API/embed keyspaces + content-change invalidation), and offset +
 * keyset-cursor pagination (the published-cursor index serves the keyset reads).
 *
 * Storage: two plugin-owned tables provisioned idempotently in `onBoot` (migrations.ts).
 * Reads: `documents`/`document_types` only — the engine maps filters onto native structural
 * columns, promoted `q_*` generated columns, or `json_extract(data, path)` fallback.
 */
import { definePlugin } from '../../sdk'
import type { D1Database } from '@cloudflare/workers-types'
import { adminViewsRoutes } from './routes/admin-views'
import { publicViewDisplaysRoutes } from './routes/public-view-displays'
import { registerViewCacheHooks } from './services/view-cache'
import { VIEWS_MIGRATION_STATEMENTS, VIEWS_COLUMN_MIGRATIONS, ensureViewsTenantUniqueness } from './migrations'

export const viewsPlugin = definePlugin({
  id: 'views',
  version: '1.0.0',
  name: 'Views',
  description: 'No-code saved queries, displays, and public embeds over document collections.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'Mark McIntosh' },

  register(app) {
    app.route('/admin/views', adminViewsRoutes)
    // NOTE: /api/views is mounted in app.ts BEFORE the bare `/api` router — plugin
    // registration runs after it, and its `/:collection` wildcard would shadow the
    // route (the documented /api sub-router ordering rule; security-audit does the same).
    app.route('/v', publicViewDisplaysRoutes)
  },

  async onBoot(ctx) {
    const env = (ctx.env ?? {}) as Record<string, unknown>
    const db = env.DB as D1Database | undefined
    if (!db) return

    // 1. Provision the plugin's storage (idempotent — every statement IF NOT EXISTS).
    try {
      for (const stmt of VIEWS_MIGRATION_STATEMENTS) {
        await db.prepare(stmt).run()
      }
    } catch (err) {
      console.error('[views-plugin] storage provisioning failed:', err)
      return // routes still mount; reads will surface a clean error until storage exists
    }

    // 1b. Additive column migrations (ALTER ADD COLUMN) — per-statement try/catch so a
    //     "duplicate column name" on a fresh table (which already has the column) is a no-op.
    for (const stmt of VIEWS_COLUMN_MIGRATIONS) {
      try {
        await db.prepare(stmt).run()
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        if (!msg.includes('duplicate column name')) {
          console.error('[views-plugin] column migration failed:', msg)
        }
      }
    }

    // 1c. Rebuild self-heal for an install that predates tenant scoping — the old
    //     single-column UNIQUE(name)/path constraints can't be dropped via ALTER.
    await ensureViewsTenantUniqueness(db)

    // 2. Content-change cache invalidation (no-ops without CACHE_KV).
    const kv = env.CACHE_KV as import('@cloudflare/workers-types').KVNamespace | undefined
    registerViewCacheHooks(ctx.hooks, db, kv)
  },

  menu: [
    {
      label: 'Views',
      path: '/admin/views',
      icon: 'document',
      order: 40,
      permissions: ['admin'],
    },
  ],
})

export function createViewsPlugin() {
  return viewsPlugin
}
