/**
 * Node / Bun server adapter for self-hosted SonicJS deployments.
 *
 * Wires the local SQLite DB driver, filesystem storage, in-memory KV, and
 * optional sync queue into a SonicJS app so it can run outside Cloudflare Workers.
 *
 * ## Quick start (Node.js)
 *
 * ```ts
 * import { serve } from '@hono/node-server'
 * import { createSonicJSApp } from '@sonicjs-cms/core'
 * import { createNodeSonicApp } from '@sonicjs-cms/core/adapters'
 *
 * const app = createSonicJSApp({ ... })
 * const adapted = await createNodeSonicApp(app, {
 *   dbPath: './data/sonicjs.db',
 *   storagePath: './data/media',
 * })
 * serve({ fetch: adapted.fetch, port: 3000 })
 * ```
 *
 * ## Quick start (Bun)
 *
 * ```ts
 * import { createSonicJSApp } from '@sonicjs-cms/core'
 * import { createNodeSonicApp } from '@sonicjs-cms/core/adapters'
 *
 * const app = createSonicJSApp({ ... })
 * const adapted = await createNodeSonicApp(app, {
 *   dbPath: './data/sonicjs.db',
 *   storagePath: './data/media',
 * })
 * Bun.serve({ fetch: adapted.fetch, port: 3000 })
 * ```
 */

import { Hono } from 'hono'
import { createSqliteDriver } from './db/sqlite-driver'
import { createFilesystemDriver } from './storage/filesystem-driver'
import { createMemoryKVDriver } from './kv/memory-kv-driver'

export type { SqliteDriver, SqliteDriverOptions } from './db/sqlite-driver'
export type { StorageDriver, PutOptions, R2HttpMetadata, R2ObjectBody, R2ObjectInfo } from './storage/filesystem-driver'
export type { KVDriver, KVPutOptions, KVListOptions, KVListResult } from './kv/memory-kv-driver'
export type { QueueDriver, QueueHandler, QueueMessage, MessageBatch } from './queue/sync-queue-driver'

// ---------------------------------------------------------------------------
// NodeAdapterOptions
// ---------------------------------------------------------------------------

export interface NodeAdapterOptions {
  /**
   * Path to the SQLite database file.
   * Defaults to `./data/sonicjs.db`.
   */
  dbPath?: string

  /**
   * Root directory for uploaded media files (replaces R2).
   * Defaults to `./data/media`.
   */
  storagePath?: string

  /**
   * Path to a JSON file used to persist KV entries across restarts.
   * Omit for ephemeral in-memory KV (TTL-based caching only).
   */
  kvPersistPath?: string

  /**
   * Environment variables injected as `c.env.*` (JWT_SECRET, CORS_ORIGINS, etc.).
   * Values are merged with process.env so you can also use dotenv.
   */
  env?: Record<string, string | undefined>
}

// ---------------------------------------------------------------------------
// createNodeSonicApp
// ---------------------------------------------------------------------------

/**
 * Wrap a SonicJS Hono app with local adapter bindings injected before any
 * SonicJS middleware (bootstrap, auth, routes) executes.
 *
 * The injection MUST run first — SonicJS's bootstrap middleware accesses
 * `c.env.DB` on the very first request. If we append the middleware after
 * `createSonicJSApp()` we'd lose the ordering race. Instead we wrap the
 * sonicApp in a fresh Hono instance that injects env first, then routes
 * all requests through the sonicApp.
 *
 * @param sonicApp The SonicJS Hono app created by `createSonicJSApp()`.
 * @param options  Adapter configuration.
 */
export async function createNodeSonicApp<E extends { Bindings: Record<string, unknown> }>(
  sonicApp: Hono<E>,
  options: NodeAdapterOptions = {},
): Promise<Hono<E>> {
  const {
    dbPath = './data/sonicjs.db',
    storagePath = './data/media',
    kvPersistPath,
    env: extraEnv = {},
  } = options

  // Resolve all drivers before the first request arrives.
  const [db, mediaBucket] = await Promise.all([
    createSqliteDriver({ dbPath }),
    Promise.resolve(createFilesystemDriver(storagePath)),
  ])
  const cacheKV = createMemoryKVDriver({ persistPath: kvPersistPath })

  // Merge env vars: explicit options take priority over process.env.
  const resolvedEnv = {
    ...Object.fromEntries(
      Object.entries(process.env).filter(([, v]) => v !== undefined)
    ),
    ...extraEnv,
  }

  // Create a wrapper app so our env injection runs BEFORE sonicApp's middlewares.
  // Hono executes middleware in registration order; appending to sonicApp directly
  // would put injection AFTER bootstrap (too late). Wrapping gives us first-in ordering.
  const wrapper = new Hono<E>()

  wrapper.use('*', async (c, next) => {
    const env = c.env as Record<string, unknown>

    // DB binding (replaces D1Database)
    env.DB = db

    // Storage binding (replaces R2Bucket)
    env.MEDIA_BUCKET = mediaBucket

    // KV binding (replaces KVNamespace)
    env.CACHE_KV = cacheKV

    // String env vars (JWT_SECRET, CORS_ORIGINS, ENVIRONMENT, …)
    for (const [k, v] of Object.entries(resolvedEnv)) {
      if (v !== undefined && env[k] === undefined) {
        env[k] = v
      }
    }

    return next()
  })

  // Mount sonicApp under root — routes, middleware, and everything it registered.
  wrapper.route('/', sonicApp)

  return wrapper as unknown as Hono<E>
}
