/**
 * Self-hosted SonicJS entry point — Node.js / Bun (Tier 1, no Cloudflare required).
 *
 * Runs on SQLite-on-disk + filesystem media storage + in-memory KV.
 * All Cloudflare bindings (D1, R2, KV) are replaced with local adapters.
 *
 * ## Bun
 *   bun run src/self-host.ts
 *
 * ## Node.js (requires @hono/node-server)
 *   npm install @hono/node-server
 *   node --experimental-strip-types src/self-host.ts
 *   # or build first: tsc && node dist/self-host.js
 *
 * ## Environment variables (copy from .env.example or set directly)
 *   SONICJS_DB_PATH      Path to SQLite file         (default: ./data/sonicjs.db)
 *   SONICJS_STORAGE_PATH Path to media upload dir    (default: ./data/media)
 *   SONICJS_KV_PATH      Path to KV persistence file (default: ./data/kv.json)
 *   PORT                 HTTP port                   (default: 3000)
 *   JWT_SECRET           Required for auth tokens
 *   BETTER_AUTH_SECRET   Required for Better Auth sessions
 *   BETTER_AUTH_URL      Public base URL, e.g. http://localhost:3000
 *   CORS_ORIGINS         Comma-separated allowed origins
 *   ENVIRONMENT          "development" or "production"
 */

import {
  createSonicJSApp,
  registerCollections,
  emailReconciliationPlugin,
} from '@sonicjs-cms/core'
import { createNodeSonicApp } from '@sonicjs-cms/core/adapters'
import type { SonicJSConfig } from '@sonicjs-cms/core'

// Import code-defined collections (same as the CF entry point).
import { siteSettingsCollection } from '@sonicjs-cms/core'
import blogPostsCollection from './collections/blog-posts.collection.ts'
import e2eTestCollection from './collections/e2e-test.collection.ts'

registerCollections([siteSettingsCollection, blogPostsCollection, e2eTestCollection])

const config: SonicJSConfig = {
  plugins: {
    register: [emailReconciliationPlugin],
    disableAll: false,
  },
}

const PORT = parseInt(process.env.PORT ?? '3000', 10)

const sonicApp = createSonicJSApp(config)

const app = await createNodeSonicApp(sonicApp, {
  dbPath: process.env.SONICJS_DB_PATH ?? './data/sonicjs.db',
  storagePath: process.env.SONICJS_STORAGE_PATH ?? './data/media',
  kvPersistPath: process.env.SONICJS_KV_PATH ?? './data/kv.json',
  env: {
    JWT_SECRET: process.env.JWT_SECRET,
    BETTER_AUTH_SECRET: process.env.BETTER_AUTH_SECRET,
    BETTER_AUTH_URL: process.env.BETTER_AUTH_URL ?? `http://localhost:${PORT}`,
    CORS_ORIGINS: process.env.CORS_ORIGINS ?? `http://localhost:${PORT}`,
    ENVIRONMENT: process.env.ENVIRONMENT ?? 'development',
  },
})

// ── Bun ───────────────────────────────────────────────────────────────────────
// `process.versions.bun` is set when running under Bun.
if (process.versions.bun) {
  // @ts-expect-error — Bun global is available at runtime on Bun
  Bun.serve({ fetch: app.fetch, port: PORT })
  console.log(`[SonicJS] Self-hosted on Bun — http://localhost:${PORT}`)
}

// ── Node.js ───────────────────────────────────────────────────────────────────
// Requires: npm install @hono/node-server
else {
  // Dynamic import so this file can be compiled without @hono/node-server in types.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { serve } = (await import('@hono/node-server' as any)) as { serve: (opts: any) => void }
  serve({ fetch: app.fetch, port: PORT })
  console.log(`[SonicJS] Self-hosted on Node — http://localhost:${PORT}`)
}

export default app
