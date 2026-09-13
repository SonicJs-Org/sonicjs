import { Hono } from 'hono'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { verifySecurityConfig, isBetterAuthSessionPath, bootstrapMiddleware, resetBootstrap } from '../../middleware/bootstrap'
import { SONICJS_VERSION } from '../../utils/version'

// Minimal KVNamespace stand-in whose `get` is a spy, so a test can prove the
// bootstrap KV fast-path was never consulted — not merely that it was set up.
function fakeKv(seed: Record<string, string> = {}) {
  const store = new Map(Object.entries(seed))
  const get = vi.fn(async (key: string) => store.get(key) ?? null)
  const kv = {
    get,
    put: async (key: string, value: string) => { store.set(key, value) },
    delete: async (key: string) => { store.delete(key) },
  } as unknown as KVNamespace
  return { kv, get }
}

// A real Hono app + app.request(), same pattern as
// bootstrap-fk-ordering.test.ts's end-to-end block — not a hand-rolled `c`
// mock. That matters here specifically: a partial mock context can make a
// test "fail" for the wrong reason (crashing on a missing `c.req` before ever
// reaching the code under test) and mask a subtly-wrong fix. Going through
// the real middleware + Hono's own request/error handling means a failure
// here can only mean the security check itself didn't run.
function appWithBootstrap(config: Parameters<typeof bootstrapMiddleware>[0] = {}) {
  const app = new Hono()
  app.onError((err, c) => c.text(err instanceof Error ? err.message : String(err), 500))
  app.use('*', bootstrapMiddleware(config, []))
  app.get('/', (c) => c.text('ok'))
  return app
}

describe('verifySecurityConfig', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    warnSpy.mockRestore()
  })

  it('should not warn when all config is properly set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-random-secret-value-here',
      CORS_ORIGINS: 'https://mysite.com',
      ENVIRONMENT: 'production',
    })

    expect(warnSpy).not.toHaveBeenCalled()
  })

  it('should warn when JWT_SECRET is not set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      CORS_ORIGINS: 'http://localhost:8787',
      ENVIRONMENT: 'development',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('JWT_SECRET is not set')
    )
  })

  it('should warn when JWT_SECRET contains the default value', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'your-super-secret-jwt-key-change-in-production',
      CORS_ORIGINS: 'http://localhost:8787',
      ENVIRONMENT: 'development',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('JWT_SECRET contains the default value')
    )
  })

  it('should warn when CORS_ORIGINS is not set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-secret',
      ENVIRONMENT: 'development',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('CORS_ORIGINS is not set')
    )
  })

  it('should warn when ENVIRONMENT is not set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-secret',
      CORS_ORIGINS: 'http://localhost:8787',
    })

    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('ENVIRONMENT is not set')
    )
  })

  it('should log multiple warnings when multiple items are missing', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
    })

    expect(warnSpy).toHaveBeenCalledTimes(3)
  })

  it('should throw in production when JWT_SECRET is not set', () => {
    expect(() => {
      verifySecurityConfig({
        DB: {} as D1Database,
        KV: {} as KVNamespace,
        CORS_ORIGINS: 'https://mysite.com',
        ENVIRONMENT: 'production',
      })
    }).toThrow('[SonicJS Security] CRITICAL')
  })

  it('should throw in production when JWT_SECRET is the default value', () => {
    expect(() => {
      verifySecurityConfig({
        DB: {} as D1Database,
        KV: {} as KVNamespace,
        JWT_SECRET: 'your-super-secret-jwt-key-change-in-production',
        CORS_ORIGINS: 'https://mysite.com',
        ENVIRONMENT: 'production',
      })
    }).toThrow('[SonicJS Security] CRITICAL')
  })

  it('should NOT throw in production when JWT_SECRET is properly set', () => {
    verifySecurityConfig({
      DB: {} as D1Database,
      KV: {} as KVNamespace,
      JWT_SECRET: 'a-strong-random-secret-value',
      ENVIRONMENT: 'production',
    })

    // Should warn about CORS_ORIGINS but not throw
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('CORS_ORIGINS is not set')
    )
  })

  it('should NOT throw in development even when JWT_SECRET is missing', () => {
    expect(() => {
      verifySecurityConfig({
        DB: {} as D1Database,
        KV: {} as KVNamespace,
        ENVIRONMENT: 'development',
      })
    }).not.toThrow()

    // Should still warn
    expect(warnSpy).toHaveBeenCalled()
  })
})

// #1043: verifySecurityConfig() used to run once, deep in the slow cold-start
// path, AFTER `bootstrapComplete` was already set true — so it never actually
// protected a warm isolate or the KV fast-path (the normal path in
// production once any isolate has bootstrapped once). These prove the
// production hard-fail now runs on every request, not just a single
// best-case first request, by driving the REAL middleware through a REAL
// Hono app for every short-circuit it can take.
describe('bootstrapMiddleware — security check survives the bootstrap short-circuits', () => {
  let warnSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    resetBootstrap()
    warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})
  })

  afterEach(() => {
    resetBootstrap()
    warnSpy.mockRestore()
  })

  it('still throws in production with a bad JWT_SECRET even when this isolate already bootstrapped', async () => {
    resetBootstrap(true) // simulate a warm isolate — the old code skipped the check entirely here
    const app = appWithBootstrap()

    const res = await app.request('/', {}, { DB: {} as D1Database, ENVIRONMENT: 'production' })

    expect(res.status).toBe(500)
    expect(await res.text()).toContain('[SonicJS Security] CRITICAL')
  })

  it('still throws in production with a bad JWT_SECRET on a fresh (never-bootstrapped) isolate', async () => {
    resetBootstrap(false)
    const app = appWithBootstrap()

    const res = await app.request('/', {}, {
      DB: {} as D1Database,
      ENVIRONMENT: 'production',
      JWT_SECRET: 'your-super-secret-jwt-key-change-in-production',
    })

    expect(res.status).toBe(500)
    expect(await res.text()).toContain('[SonicJS Security] CRITICAL')
  })

  it('throws in production before the KV fast-path is even consulted — the branch the original bug skipped entirely', async () => {
    // This is the actual gap the bug lived in: the KV fast-path returns
    // `next()` on its own, well before the old call site. Give it everything it
    // needs to take that branch — a CACHE_KV holding the version-keyed marker —
    // and prove not only that the request fails, but that the check ran BEFORE
    // the fast-path ever read KV. Asserting on the spy is what makes this a
    // claim about ordering rather than just a second copy of the test above.
    resetBootstrap(false)
    const { kv, get } = fakeKv({ [`_sonicjs_bootstrap_v${SONICJS_VERSION}`]: '1' })
    const app = appWithBootstrap()

    const res = await app.request('/', {}, { DB: {} as D1Database, CACHE_KV: kv, ENVIRONMENT: 'production' })

    expect(res.status).toBe(500)
    expect(await res.text()).toContain('[SonicJS Security] CRITICAL')
    expect(get).not.toHaveBeenCalled()
  })

  it('keeps throwing on every later request, not only the first', async () => {
    resetBootstrap(true)
    const app = appWithBootstrap()
    const env = { DB: {} as D1Database, ENVIRONMENT: 'production' }

    for (let i = 0; i < 3; i++) {
      const res = await app.request('/', {}, env)
      expect(res.status).toBe(500)
      expect(await res.text()).toContain('[SonicJS Security] CRITICAL')
    }
  })

  it('logs the warnings once per isolate, not once per request', async () => {
    // Only JWT_SECRET is missing, so a single verification logs exactly one
    // warning. Three requests through a warm isolate must still log one.
    resetBootstrap(true)
    const app = appWithBootstrap()
    const env = { DB: {} as D1Database, ENVIRONMENT: 'development', CORS_ORIGINS: 'http://localhost:8787' }

    for (let i = 0; i < 3; i++) {
      expect((await app.request('/', {}, env)).status).toBe(200)
    }

    expect(warnSpy).toHaveBeenCalledTimes(1)
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('JWT_SECRET is not set'))
  })

  it('re-verifies when the bindings change, so a memoised failure cannot outlive a fix', async () => {
    resetBootstrap(true)
    const app = appWithBootstrap()

    const bad = await app.request('/', {}, { DB: {} as D1Database, ENVIRONMENT: 'production' })
    expect(bad.status).toBe(500)

    const good = await app.request('/', {}, {
      DB: {} as D1Database,
      ENVIRONMENT: 'production',
      JWT_SECRET: 'a-strong-random-secret-value-here',
      CORS_ORIGINS: 'https://example.com',
    })
    expect(good.status).toBe(200)
  })

  it('does not throw and proceeds normally in production with a real JWT_SECRET set (smoke check the fix does not break healthy boots)', async () => {
    resetBootstrap(true) // warm-isolate state; avoids mocking the full cold-start DB flow
    const app = appWithBootstrap()

    const res = await app.request('/', {}, {
      DB: {} as D1Database,
      ENVIRONMENT: 'production',
      JWT_SECRET: 'a-strong-random-secret-value-here',
      CORS_ORIGINS: 'https://example.com',
    })

    expect(res.status).toBe(200)
    expect(await res.text()).toBe('ok')
  })
})

// The heavy cold-start bootstrap must not run on Better Auth's stateless session
// API — on a cold Cloudflare isolate the ~10s D1 bootstrap otherwise shares the
// request's CPU/time budget with scrypt password verification and returns a bare
// 500 (observed in CI as intermittent `BA sign-in failed: 500`). These endpoints
// only touch auth_* migration tables, so skipping bootstrap for them is safe.
describe('isBetterAuthSessionPath', () => {
  it('matches the sign-in path that 500s on cold start', () => {
    expect(isBetterAuthSessionPath('/auth/sign-in/email')).toBe(true)
  })

  it('matches every stateless Better Auth session endpoint', () => {
    const skipped = [
      '/auth/sign-in',
      '/auth/sign-in/email',
      '/auth/sign-up/email',
      '/auth/sign-out',
      '/auth/get-session',
      '/auth/callback/github',
      '/auth/token',
    ]
    for (const p of skipped) {
      expect(isBetterAuthSessionPath(p)).toBe(true)
    }
  })

  it('does NOT skip the login page render or the self-seeding endpoints', () => {
    // /auth/login is an HTML page; /auth/seed-admin seeds its own prerequisites;
    // neither is a hot cold-start path, and both still get the full bootstrap.
    const notSkipped = [
      '/auth/login',
      '/auth/login/form',
      '/auth/register',
      '/auth/seed-admin',
      '/auth/accept-invitation',
      '/admin',
      '/admin/content',
      '/',
    ]
    for (const p of notSkipped) {
      expect(isBetterAuthSessionPath(p)).toBe(false)
    }
  })

  it('does not match a substring collision like /auth/sign-in-history', () => {
    // Only exact segment or `/auth/<seg>/...` — not arbitrary prefixes.
    expect(isBetterAuthSessionPath('/auth/sign-in-history')).toBe(false)
  })
})
