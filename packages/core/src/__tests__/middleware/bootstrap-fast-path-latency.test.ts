import { describe, it, expect, vi, beforeEach } from 'vitest'

import { SONICJS_VERSION } from '../../utils/version'

// Cold-start latency regression guard for the KV fast path.
//
// The fast path exists so an isolate that has already bootstrapped this version skips the ~3-9s
// cold bootstrap. It was still awaiting three document-type syncs before handing the request on:
// three sequential D1 round trips, free against a local SQLite file and ~5-50ms each against a
// remote D1. On a single-threaded isolate that is not just the one request's latency — every
// request co-located with it waits too, which is the shape of the 120s stalls seen on preview
// deployments under a four-worker Playwright run.
//
// They are safe to offload because nothing downstream reads what they write on this request, and
// BOOTSTRAP_KV_KEY embeds SONICJS_VERSION — a deploy invalidates the flag, so the first request
// of any new version runs the full awaited bootstrap regardless. These tests pin that the syncs
// still happen and that the request no longer waits for them.

const seedCalls: string[] = []
let releaseSeeds: () => void = () => {}
let seedGate: Promise<void> = Promise.resolve()

vi.mock('../../services/collection-loader', () => ({ loadCollectionConfigs: vi.fn(async () => []) }))
vi.mock('../../services/collection-registry', () => ({
  getCollectionRegistry: () => ({ register: vi.fn(), listActive: () => [] }),
}))
vi.mock('../../services/document-types-seed', () => ({
  bootstrapDocumentTypes: vi.fn(async () => {
    seedCalls.push('bootstrapDocumentTypes')
    await seedGate
  }),
  autoRegisterCollectionDocumentTypes: vi.fn(async () => {
    seedCalls.push('autoRegisterCollectionDocumentTypes')
    await seedGate
  }),
  bootstrapDefaultContent: vi.fn(async () => {
    seedCalls.push('bootstrapDefaultContent')
    await seedGate
  }),
}))
vi.mock('../../plugins/cache/services/cache', () => ({ setGlobalKVNamespace: vi.fn() }))
vi.mock('../../plugins/cache/services/catalog', () => ({
  setGlobalCatalogKv: vi.fn(),
  loadKvCatalog: vi.fn(async () => {}),
}))

function makeContext(waited: Promise<unknown>[], kv: Record<string, string> = {}) {
  // Key-aware, because the fast path now reads two keys out of this namespace and the whole
  // point of the second one is that it can be absent while the first is present. A mock that
  // answers '1' to everything cannot express "bootstrapped, but not synced this minute".
  const puts: Array<{ key: string; ttl?: number }> = []
  const ctx = {
    env: {
      JWT_SECRET: 'a-strong-random-secret-value-for-tests',
      CORS_ORIGINS: 'http://localhost:8787',
      ENVIRONMENT: 'development',
      DB: {
        prepare() {
          return {
            bind: () => this,
            // Non-zero counts == "D1 has data", which is what validates the KV flag.
            // Satisfies both the old COUNT(*) guard and the new isSystemSeedPresent check.
            first: async () => ({ n: 1, roles: 1, auth: 1 }),
            all: async () => ({ results: [] }),
            run: async () => ({}),
          }
        },
        batch: async () => [],
      },
      CACHE_KV: {
        get: async (key: string) => kv[key] ?? null,
        put: async (key: string, value: string, opts?: { expirationTtl?: number }) => {
          kv[key] = value
          puts.push({ key, ttl: opts?.expirationTtl })
        },
        delete: async (key: string) => { delete kv[key] },
      },
    },
    req: {
      path: '/admin/content',
      url: 'https://sonicjs-pr-demo.workers.dev/admin/content',
      header: (name: string) => (name.toLowerCase() === 'host' ? 'sonicjs-pr-demo.workers.dev' : ''),
    },
    executionCtx: { waitUntil: (p: Promise<unknown>) => { waited.push(p) } },
    set: () => {},
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- minimal Hono context stand-in
  } as any
  return Object.assign(ctx, { kvPuts: puts })
}

/** The state a deployment is in once some earlier isolate has completed a full bootstrap. */
function bootstrapped(host = 'sonicjs-pr-demo.workers.dev') {
  return { [`_sonicjs_bootstrap_v${SONICJS_VERSION}:${host}`]: '1' }
}

async function freshMiddleware() {
  // `bootstrapComplete` is a per-isolate module global; without a reset the previous case's
  // completed bootstrap short-circuits this one before it ever reaches the fast path.
  vi.resetModules()
  const { bootstrapMiddleware } = await import('../../middleware/bootstrap')
  return bootstrapMiddleware({})
}

describe('bootstrapMiddleware KV fast path does not block the request on D1 syncs', () => {
  beforeEach(() => {
    seedCalls.length = 0
    seedGate = new Promise<void>((resolve) => { releaseSeeds = resolve })
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('reaches the handler while the document-type syncs are still in flight', async () => {
    const mw = await freshMiddleware()
    const waited: Promise<unknown>[] = []
    let handlerRan = false

    // The seeds are gated open-ended, so if the middleware awaited any of them this never
    // settles and the test times out rather than passing by luck.
    await mw(makeContext(waited, bootstrapped()), async () => { handlerRan = true })

    expect(handlerRan).toBe(true)
    // The first sync started — the work is dispatched, not dropped — and the request did not
    // wait for it to finish.
    expect(seedCalls).toEqual(['bootstrapDocumentTypes'])

    releaseSeeds()
  })

  it('hands the background work to waitUntil so it survives the response', async () => {
    // A floating promise is cancelled when the Worker's response is returned. Without the
    // keep-alive the syncs would be killed mid-write on the very deployments that need them.
    const mw = await freshMiddleware()
    const waited: Promise<unknown>[] = []

    await mw(makeContext(waited, bootstrapped()), async () => {})
    releaseSeeds()
    await Promise.all(waited)

    // All three ran, in order, after the response was already on its way.
    expect(seedCalls).toEqual([
      'bootstrapDocumentTypes',
      'autoRegisterCollectionDocumentTypes',
      'bootstrapDefaultContent',
    ])
  })

  it('skips the D1 syncs entirely when another isolate already synced this minute', async () => {
    // The reason this matters is aggregate, not per-request: D1 serialises writes per database,
    // and a four-worker Playwright run churns isolates for the length of the run. Once-per-cold-
    // isolate turns that churn into sustained write pressure on the one preview database; this
    // gate turns it into at most one batch per minute per deployment.
    const mw = await freshMiddleware()
    const waited: Promise<unknown>[] = []
    const kv = bootstrapped()
    kv[`${Object.keys(kv)[0]}:synced`] = '1'
    let handlerRan = false

    await mw(makeContext(waited, kv), async () => { handlerRan = true })
    releaseSeeds()
    await Promise.all(waited)

    expect(handlerRan).toBe(true)
    expect(seedCalls).toEqual([])
  })

  it('claims the throttle window with a 60s TTL so the sync still re-runs', async () => {
    // A marker without an expiry would silence the sync until the next deploy, which is the one
    // case the fast path exists to cover: a code collection added without a version bump.
    const mw = await freshMiddleware()
    const waited: Promise<unknown>[] = []
    const ctx = makeContext(waited, bootstrapped())

    await mw(ctx, async () => {})
    releaseSeeds()
    await Promise.all(waited)

    const marker = ctx.kvPuts.find((p: { key: string }) => p.key.endsWith(':synced'))
    expect(marker, 'the fast path ran its syncs without claiming the window').toBeDefined()
    expect(marker.ttl).toBe(60)
    expect(seedCalls).toContain('bootstrapDocumentTypes')
  })

  it('still serves the request when there is no execution context to offload to', async () => {
    // `c.executionCtx` throws outside a real fetch handler — app.request() in tests, for one.
    // The guard must swallow that, not turn a latency optimisation into a 500.
    const mw = await freshMiddleware()
    const ctx = makeContext([], bootstrapped())
    Object.defineProperty(ctx, 'executionCtx', {
      get() { throw new Error('This context has no ExecutionContext') },
    })
    let handlerRan = false

    await mw(ctx, async () => { handlerRan = true })

    expect(handlerRan).toBe(true)
    releaseSeeds()
  })
})
