import { describe, it, expect, vi, beforeEach } from 'vitest'

// Ordering regression guard.
//
// The static-asset/health skip and the Better Auth session-path skip used to sit BELOW the KV
// fast-path. The fast path is only "fast" relative to a cold full bootstrap — it still costs a KV
// read, a `SELECT COUNT(*) FROM document_types`, a collection-config load and three serial D1
// bootstrap calls. Any deployment that has served one request has the KV flag set, so the skips
// were dead exactly when they mattered: every health check, every .js/.css/.png and every Better
// Auth sign-in paid the full bootstrap on a cold isolate (~9s measured on a preview deployment,
// ~0.5s warm). In CI that stacked into 90s Playwright timeouts, most often on
// `POST /auth/sign-in/email` — the one request the skip's own comment says must not carry the tax.
//
// These tests assert the skips run FIRST: a skipped path must touch neither KV nor D1.

vi.mock('../../services/collection-loader', () => ({ loadCollectionConfigs: vi.fn(async () => []) }))
vi.mock('../../services/collection-registry', () => ({
  getCollectionRegistry: () => ({ register: vi.fn() }),
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

type Probe = { kvGets: string[]; kvDeletes: string[]; kvPuts: string[]; d1Queries: string[] }

function makeContext(path: string, probe: Probe, host = 'sonicjs-pr-demo.workers.dev', docTypeCount = 1) {
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
            first: async () => ({ n: docTypeCount, roles: docTypeCount, auth: docTypeCount }),
            all: async () => ({ results: [] }),
            run: async () => ({}),
          }
        },
        batch: async () => [],
      },
      // Present and already flagged: the state every deployed worker is in after its first
      // request, and the state in which the misordered skips were unreachable.
      CACHE_KV: {
        get: async (key: string) => {
          probe.kvGets.push(key)
          return '1'
        },
        put: async (key: string) => { probe.kvPuts.push(key) },
        delete: async (key: string) => { probe.kvDeletes.push(key) },
      },
    },
    req: { path, header: (name: string) => (name.toLowerCase() === 'host' ? host : '') },
    executionCtx: { waitUntil: () => {} },
    set: () => {},
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- minimal Hono context stand-in
  } as any
}

async function runMiddleware(path: string, host?: string, docTypeCount = 1) {
  // Fresh module per case: `bootstrapComplete` is a per-isolate module global, so a previous
  // case's full bootstrap would short-circuit the next one and hide a regression.
  vi.resetModules()
  const { bootstrapMiddleware } = await import('../../middleware/bootstrap')
  const probe: Probe = { kvGets: [], kvDeletes: [], kvPuts: [], d1Queries: [] }
  let nextCalled = false
  await bootstrapMiddleware({})(makeContext(path, probe, host, docTypeCount), async () => {
    nextCalled = true
  })
  return { ...probe, nextCalled }
}

describe('bootstrapMiddleware path skips run before the KV fast-path', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  const skipped = [
    ['the health check', '/health'],
    ['a bundled script', '/assets/admin.js'],
    ['a stylesheet', '/assets/admin.css'],
    ['an image', '/images/logo.png'],
    ['the favicon', '/favicon.ico'],
    ['Better Auth sign-in', '/auth/sign-in/email'],
    ['Better Auth session read', '/auth/get-session'],
    ['Better Auth sign-out', '/auth/sign-out'],
  ] as const

  for (const [label, path] of skipped) {
    it(`${label} (${path}) touches neither KV nor D1`, async () => {
      const { kvGets, d1Queries, nextCalled } = await runMiddleware(path)
      expect(kvGets).toEqual([])
      expect(d1Queries).toEqual([])
      expect(nextCalled).toBe(true)
    })
  }

  it('still runs the KV fast-path for a normal admin request', async () => {
    // Negative control: the skips were moved, not the fast path. Without this a middleware that
    // short-circuits everything would pass every assertion above.
    const { kvGets, kvDeletes, d1Queries, nextCalled } = await runMiddleware('/admin/content')
    expect(kvGets.length).toBeGreaterThan(0)
    expect(d1Queries.join(' ')).toContain('documents')
    expect(nextCalled).toBe(true)
    // Seeds present → fast path succeeds, no KV deletion
    expect(kvDeletes).toEqual([])
  })

  it('does not skip the login page render, which needs the full bootstrap', async () => {
    const { kvGets } = await runMiddleware('/auth/login')
    expect(kvGets.length).toBeGreaterThan(0)
  })
})

// The CACHE_KV namespace in wrangler.toml is shared by every deployment built from it, while the
// flag it holds describes one D1. `pr-tests.yml` recreates the D1 on every PR run and leaves the
// KV namespace alone, so an unscoped key let one preview read — and then delete — a flag written
// by another preview against a database it had never seen.
describe('the bootstrap KV flag is scoped to the deployment it describes', () => {
  beforeEach(() => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  it('reads a key carrying this deployment hostname', async () => {
    const { kvGets } = await runMiddleware('/admin/content', 'sonicjs-pr-feature-x.workers.dev')
    expect(kvGets.length).toBeGreaterThan(0)
    // Every key, not just the first: the fast path also reads a sync-throttle marker, and an
    // unscoped one would be just as cross-deployment as an unscoped flag.
    for (const key of kvGets) expect(key).toContain('sonicjs-pr-feature-x.workers.dev')
  })

  it('gives two deployments two different keys', async () => {
    const a = await runMiddleware('/admin/content', 'sonicjs-pr-one.workers.dev')
    const b = await runMiddleware('/admin/content', 'sonicjs-pr-two.workers.dev')
    expect(a.kvGets[0]).not.toBe(b.kvGets[0])
  })

  it('discards only its own flag when its D1 turns out to be empty', async () => {
    // docTypeCount 0 == a freshly created database: the flag is lying and must be dropped.
    const { kvDeletes } = await runMiddleware('/admin/content', 'sonicjs-pr-three.workers.dev', 0)
    expect(kvDeletes).toEqual([expect.stringContaining('sonicjs-pr-three.workers.dev')])
  })
})
