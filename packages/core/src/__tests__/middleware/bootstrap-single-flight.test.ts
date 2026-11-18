import { describe, it, expect, vi, beforeEach } from 'vitest'

// Concurrency regression guard.
//
// `bootstrapComplete` is only set at the END of the bootstrap, so it cannot keep a second request
// out while the first is still working. Every request that landed on a cold isolate before the
// first one finished therefore saw `false` and ran the whole bootstrap again. The cost is not N
// parallel bootstraps but N interleaved ones — each copy's serial D1 round trips queue behind
// every other copy's — so all N requests take roughly N times what one cold bootstrap costs.
//
// Ordinary traffic reaches this: an admin dashboard load fires five fragment requests at once. A
// four-worker Playwright run hits it on every cold start, where it showed up as batches of
// unrelated requests — browser navigations and API calls alike — stalling past 30s on preview
// deployments with nothing in the logs. No errors, no 429s; the isolate was just redoing work it
// had already begun.
//
// These tests assert one bootstrap per isolate no matter how many requests race for it.

vi.mock('../../services/collection-loader', () => ({ loadCollectionConfigs: vi.fn(async () => []) }))
vi.mock('../../services/collection-registry', () => ({
  getCollectionRegistry: () => ({ register: vi.fn(), listActive: () => [] }),
}))
vi.mock('../../services/document-types-seed', () => ({
  bootstrapDocumentTypes: vi.fn(async () => {}),
  autoRegisterCollectionDocumentTypes: vi.fn(async () => {}),
  bootstrapDefaultContent: vi.fn(async () => {}),
}))
vi.mock('../../plugins/cache/services/cache', () => ({ setGlobalKVNamespace: vi.fn() }))
vi.mock('../../plugins/cache/services/catalog', () => ({
  setGlobalCatalogKv: vi.fn(),
  loadKvCatalog: vi.fn(async () => {}),
}))

type Probe = { kvGets: string[]; d1Queries: string[] }

/**
 * A context whose KV read does not resolve until the next macrotask.
 *
 * The gate is taken synchronously, so the race is already closed without this — but a mock that
 * resolves immediately would also pass against a middleware with no gate at all, since each
 * request could then run start-to-finish before the next one began. The delay forces genuine
 * overlap, so the test fails if the gate is removed.
 */
function makeContext(probe: Probe, opts: { failD1?: boolean } = {}) {
  return {
    env: {
      JWT_SECRET: 'a-strong-random-secret-value-for-tests',
      CORS_ORIGINS: 'http://localhost:8787',
      ENVIRONMENT: 'development',
      DB: {
        prepare(sql: string) {
          probe.d1Queries.push(sql)
          return {
            bind: () => this,
            first: async () => {
              if (opts.failD1) throw new Error('D1 unavailable')
              return { n: 1, roles: 1, auth: 1 }
            },
            all: async () => ({ results: [] }),
            run: async () => ({}),
          }
        },
        batch: async () => [],
      },
      CACHE_KV: {
        get: async (key: string) => {
          probe.kvGets.push(key)
          await new Promise((r) => setTimeout(r, 5))
          return '1'
        },
        put: async () => {},
        delete: async () => {},
      },
    },
    req: {
      path: '/admin/content',
      url: 'https://sonicjs-pr-demo.workers.dev/admin/content',
      header: (name: string) => (name.toLowerCase() === 'host' ? 'sonicjs-pr-demo.workers.dev' : ''),
    },
    executionCtx: { waitUntil: () => {} },
    set: () => {},
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- minimal Hono context stand-in
  } as any
}

async function freshMiddleware() {
  // `bootstrapComplete` and the in-flight holder are per-isolate module globals, so each case
  // needs the module re-evaluated or the previous case's completed bootstrap short-circuits it.
  vi.resetModules()
  const { bootstrapMiddleware } = await import('../../middleware/bootstrap')
  return bootstrapMiddleware({})
}

describe('bootstrapMiddleware runs one bootstrap per isolate under concurrency', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('collapses a burst of cold-start requests into a single bootstrap', async () => {
    const mw = await freshMiddleware()
    const probe: Probe = { kvGets: [], d1Queries: [] }
    let nextCalls = 0

    // Five at once: what a dashboard load costs, and what the fragment specs send.
    await Promise.all(
      Array.from({ length: 5 }, () =>
        mw(makeContext(probe), async () => {
          nextCalls += 1
        })
      )
    )

    // The work happened once. Counted as "no key was looked up twice" rather than as a fixed
    // number of reads: the fast path reads the bootstrap flag and its sync-throttle marker in one
    // parallel round, and what single-flight actually promises is that a second request does not
    // repeat the round -- not that the round is one key wide.
    expect(probe.kvGets).toEqual([...new Set(probe.kvGets)])
    expect(probe.kvGets.length).toBeGreaterThan(0)
    expect(probe.d1Queries.filter((q) => q.includes('documents'))).toHaveLength(1)
    // ...and every request still reached the handler behind it.
    expect(nextCalls).toBe(5)
  })

  it('serves later requests from the completed bootstrap without redoing it', async () => {
    const mw = await freshMiddleware()
    const probe: Probe = { kvGets: [], d1Queries: [] }

    await mw(makeContext(probe), async () => {})
    const afterFirst = probe.kvGets.length
    await mw(makeContext(probe), async () => {})

    expect(afterFirst).toBeGreaterThan(0)
    // The second request added nothing: `bootstrapComplete` short-circuits above the KV read.
    expect(probe.kvGets).toHaveLength(afterFirst)
  })

  it('does not wait forever on a holder whose request was torn down', async () => {
    // `bootstrapInFlight` is created inside one request's execution context, and Cloudflare
    // cancels a request's pending work the moment its client disconnects. A holder killed
    // before its `finally` ran leaves a promise nobody will ever resolve — and every later
    // request on the isolate then inherits it, so one timed-out client wedges the isolate for
    // everyone after it. That reads exactly like the reported failure: a request that leaves
    // the test runner and never produces a first byte.
    //
    // Simulated by taking the gate with a request whose KV read never settles, then letting a
    // second request in. The second one must still reach its handler.
    vi.useFakeTimers()
    try {
      const mw = await freshMiddleware()
      const probe: Probe = { kvGets: [], d1Queries: [] }
      let nextCalls = 0

      const wedged = makeContext(probe)
      wedged.env.CACHE_KV.get = () => new Promise(() => {})
      // Deliberately not awaited: this is the request that never comes back.
      void mw(wedged, async () => { nextCalls += 1 })
      await Promise.resolve()

      const follower = mw(makeContext(probe), async () => { nextCalls += 1 })
      // Past BOOTSTRAP_DEADLINE_MS (20s). The follower takes over rather than inheriting.
      await vi.advanceTimersByTimeAsync(21_000)
      await follower

      expect(nextCalls).toBe(1)
    } finally {
      vi.useRealTimers()
    }
  })

  it('leaves a taken-over gate alone when the original holder finally exits', async () => {
    // A holder that blew the deadline and was taken over must not null out the new holder's
    // gate on its way out — that reopens the stampede the gate exists to prevent.
    vi.resetModules()
    const mod = await import('../../middleware/bootstrap')
    const mw = mod.bootstrapMiddleware({})
    const probe: Probe = { kvGets: [], d1Queries: [] }

    let releaseWedged: (v: string) => void = () => {}
    const wedged = makeContext(probe)
    wedged.env.CACHE_KV.get = () => new Promise<string>((r) => { releaseWedged = r })

    vi.useFakeTimers()
    try {
      void mw(wedged, async () => {})
      await Promise.resolve()

      const follower = mw(makeContext(probe), async () => {})
      await vi.advanceTimersByTimeAsync(21_000)
      await follower

      // The follower completed a full bootstrap, so `bootstrapComplete` is set and a third
      // request short-circuits without touching KV at all.
      const before = probe.kvGets.length
      vi.useRealTimers()
      releaseWedged('1')
      await mw(makeContext(probe), async () => {})
      expect(probe.kvGets).toHaveLength(before)
    } finally {
      vi.useRealTimers()
    }
  })

  it('releases the gate when a bootstrap fails, so the next request can retry', async () => {
    // A gate held by a failed attempt would park every later request on this isolate forever —
    // strictly worse than the duplicate work it exists to prevent. The D1 mock throws from
    // `first()`, which is inside the fast path's own try/catch, so the run falls through to the
    // full bootstrap and completes; what matters is that a second request is not blocked.
    const mw = await freshMiddleware()
    const probe: Probe = { kvGets: [], d1Queries: [] }
    let nextCalls = 0

    await mw(makeContext(probe, { failD1: true }), async () => { nextCalls += 1 })
    await mw(makeContext(probe, { failD1: true }), async () => { nextCalls += 1 })

    expect(nextCalls).toBe(2)
  })
})
