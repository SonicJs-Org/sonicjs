// @ts-nocheck
// Resilience of the first-boot bootstrap (follow-up to the FK-race fix, issue #1017).
//
// Real better-sqlite3 D1 + the real bootstrapMiddleware. Each block pins one failure mode:
//   - a run that never settles must not hang every later request (single-flight + timeout);
//   - a failure that persists must not re-run the full bootstrap on every request (backoff),
//     nor send a telemetry snapshot each time;
//   - a KV marker must not short-circuit a database that lacks the system seed (CI previews
//     share one KV namespace, and the marker is keyed by version, not by database);
//   - a core plugin that fails to install must keep the marker unwritten.
import { Hono } from 'hono'
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapMiddleware, resetBootstrap, _setBootstrapTimingForTests } from '../../middleware/bootstrap'
import { MigrationService } from '../../services/migrations'
import { RbacService } from '../../services/rbac'
import { PluginService } from '../../services/plugin-service'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'
import { getTelemetryService } from '../../services/telemetry-service'
import { SONICJS_VERSION } from '../../utils/version'

const MARKER = `_sonicjs_bootstrap_v${SONICJS_VERSION}`

function makeKv(initial: Record<string, string> = {}) {
  const store = new Map(Object.entries(initial))
  return {
    store,
    get: vi.fn(async (k) => store.get(k) ?? null),
    put: vi.fn(async (k, v) => void store.set(k, v)),
    delete: vi.fn(async (k) => void store.delete(k)),
  }
}

function makeApp(config = { plugins: { disableAll: true } }) {
  const app = new Hono()
  app.use('*', bootstrapMiddleware(config, []))
  app.get('/', (c) => c.text('ok'))
  return app
}

const count = (db, sql) => db.raw.prepare(sql).get().n
const adminRoles = (db) =>
  count(db, "SELECT COUNT(*) AS n FROM documents WHERE type_id = 'rbac_role' AND slug = 'role-admin'")

/** Resolve to 'timeout' if `p` hasn't settled in `ms`. */
const within = (p, ms) => Promise.race([p, new Promise((r) => setTimeout(() => r('timeout'), ms))])

let db
let snapshot
beforeEach(() => {
  db = createTestD1()
  resetBootstrap()
  vi.spyOn(console, 'log').mockImplementation(() => {})
  vi.spyOn(console, 'warn').mockImplementation(() => {})
  vi.spyOn(console, 'error').mockImplementation(() => {})
  vi.stubGlobal('fetch', vi.fn(async () => new Response('{}')))
  snapshot = vi.spyOn(getTelemetryService(), 'trackProjectSnapshot').mockResolvedValue(undefined)
})
afterEach(() => {
  resetBootstrap()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  db.close()
})

describe('a bootstrap run that never settles', () => {
  it('does not hang the request that started it or the ones queued behind it', async () => {
    _setBootstrapTimingForTests({ waitMs: 50 })
    vi.spyOn(MigrationService.prototype, 'ensureSchemaCompatibility').mockReturnValue(new Promise(() => {}))
    const app = makeApp()

    const first = app.request('/', {}, { DB: db })
    const second = app.request('/', {}, { DB: db })
    const [a, b] = await Promise.all([within(first, 2000), within(second, 2000)])

    expect(a).not.toBe('timeout')
    expect(b).not.toBe('timeout')
    expect(a.status).toBe(200)
    expect(b.status).toBe(200)
  })

  it('is treated as dead once stale, so a later request runs a fresh bootstrap', async () => {
    _setBootstrapTimingForTests({ waitMs: 20, staleMs: 50 })
    const schema = vi
      .spyOn(MigrationService.prototype, 'ensureSchemaCompatibility')
      .mockReturnValueOnce(new Promise(() => {})) // the stuck first run
    const app = makeApp()

    await within(app.request('/', {}, { DB: db }), 2000)
    expect(adminRoles(db)).toBe(0)

    await new Promise((r) => setTimeout(r, 80)) // past staleMs
    const res = await within(app.request('/', {}, { DB: db }), 5000)
    expect(res.status).toBe(200)
    expect(schema).toHaveBeenCalledTimes(2)
    expect(adminRoles(db)).toBe(1)
  })
})

describe('a bootstrap that keeps failing', () => {
  it('is retried after the backoff window, not on every request', async () => {
    const schema = vi.spyOn(MigrationService.prototype, 'ensureSchemaCompatibility')
    vi.spyOn(RbacService.prototype, 'ensureSystemRbacSeed').mockRejectedValue(new Error('seed broken'))
    const kv = makeKv()
    const app = makeApp()

    for (let i = 0; i < 5; i++) {
      const res = await app.request('/', {}, { DB: db, CACHE_KV: kv })
      expect(res.status).toBe(200)
    }
    expect(schema).toHaveBeenCalledTimes(1)
    expect(kv.store.has(MARKER)).toBe(false)

    _setBootstrapTimingForTests({ retryBackoffMs: 0 }) // window elapsed
    await app.request('/', {}, { DB: db, CACHE_KV: kv })
    expect(schema).toHaveBeenCalledTimes(2)
  })

  it('sends no telemetry snapshot for a failed run, and one for a successful run', async () => {
    const seed = vi.spyOn(RbacService.prototype, 'ensureSystemRbacSeed').mockRejectedValueOnce(new Error('seed broken'))
    const app = makeApp()

    await app.request('/', {}, { DB: db })
    expect(snapshot).not.toHaveBeenCalled()

    _setBootstrapTimingForTests({ retryBackoffMs: 0 })
    seed.mockRestore()
    await app.request('/', {}, { DB: db })
    expect(snapshot).toHaveBeenCalledTimes(1)
  })
})

describe('the KV fast path', () => {
  it('ignores a marker over a database without the system seed, and seeds it', async () => {
    // What another CI preview sharing this KV leaves behind: a marker for this version,
    // over a DB whose types exist but whose RBAC seed never landed.
    await bootstrapDocumentTypes(db)
    expect(adminRoles(db)).toBe(0)
    const kv = makeKv({ [MARKER]: '1' })

    const res = await makeApp().request('/', {}, { DB: db, CACHE_KV: kv })
    expect(res.status).toBe(200)
    expect(adminRoles(db)).toBe(1)
  })

  it('still takes the fast path over a seeded database', async () => {
    const kv = makeKv()
    await makeApp().request('/', {}, { DB: db, CACHE_KV: kv })
    expect(kv.store.get(MARKER)).toBe('1')

    resetBootstrap() // a new isolate
    const schema = vi.spyOn(MigrationService.prototype, 'ensureSchemaCompatibility')
    const res = await makeApp().request('/', {}, { DB: db, CACHE_KV: kv })
    expect(res.status).toBe(200)
    expect(schema).not.toHaveBeenCalled()
  })
})

describe('core plugin install failure', () => {
  it('keeps the KV marker unwritten', async () => {
    vi.spyOn(PluginService.prototype, 'installPlugin').mockRejectedValue(new Error('install failed'))
    const kv = makeKv()

    const res = await makeApp({}).request('/', {}, { DB: db, CACHE_KV: kv })
    expect(res.status).toBe(200)
    expect(kv.store.has(MARKER)).toBe(false)
  })

  it('writes the marker when every core plugin installs', async () => {
    const kv = makeKv()
    await makeApp({}).request('/', {}, { DB: db, CACHE_KV: kv })
    expect(kv.store.get(MARKER)).toBe('1')
    expect(
      count(db, "SELECT COUNT(*) AS n FROM documents WHERE type_id = 'plugin' AND slug = 'core-auth'"),
    ).toBe(1)
  })
})
