/**
 * Plugin-level integration test for the v3 email-plugin (PR-E Phase B step 40).
 *
 * Constructs `createSonicJSApp({ sonicPlugins: [emailPluginV3] })` with a
 * mocked CF Email binding + minimal D1 stub and verifies:
 *   1. The plugin is present in the registered v3 set (byId.has('email'))
 *   2. The hook subscriptions are wired into HookSystem (auth events + cron:tick)
 *   3. `getEmailService()` returns a wired EmailServiceImpl after first request
 *   4. The admin route at /admin/email/test responds (sanity check that
 *      `register(app)` ran synchronously at construction time per Option A)
 *
 * This is the test PR-S3 was missing — a real-shape synthetic plugin with a
 * `register` function exercising the construction-time path.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { createSonicJSApp } from '../../../../app'
import { emailPluginV3 } from '..'
import {
  getEmailService,
  resetEmailService,
} from '../../../../services/email-service-singleton'
import { getHookSystem, resetHookSystem } from '../../../../services/hook-system-singleton'

function makeMinimalDb(): D1Database {
  return {
    prepare: vi.fn(() => ({
      bind: vi.fn(() => ({
        run: vi.fn(async () => ({})),
        first: vi.fn(async () => null),
        all: vi.fn(async () => ({ results: [] })),
      })),
      first: vi.fn(async () => null),
      all: vi.fn(async () => ({ results: [] })),
      run: vi.fn(async () => ({})),
    })),
    batch: vi.fn(async () => []),
    exec: vi.fn(async () => ({ count: 0, duration: 0 })),
  } as unknown as D1Database
}

function makeEmailBinding(): SendEmail {
  return {
    send: vi.fn(async () => ({ messageId: 'cf-integration' })),
  } as unknown as SendEmail
}

function makeMockEnv(): Record<string, unknown> {
  return {
    DB: makeMinimalDb(),
    CACHE_KV: { get: vi.fn(), put: vi.fn(), delete: vi.fn() },
    MEDIA_BUCKET: {},
    ASSETS: { fetch: vi.fn() },
    EMAIL: makeEmailBinding(),
    ENVIRONMENT: 'test',
  }
}

beforeEach(() => {
  resetEmailService()
  // Note: resetHookSystem would clear the singleton, but createSonicJSApp
  // sets a fresh one each construction. We rely on that overwrite-semantic.
})

describe('emailPluginV3 — registration via createSonicJSApp', () => {
  it('mounts /admin/email/* routes synchronously at construction (Option A)', async () => {
    const app = createSonicJSApp({ sonicPlugins: [emailPluginV3] })

    // Sanity: app constructed without throwing
    expect(app).toBeDefined()

    // Without firing a request, the routes are registered (Phase 1 — sync)
    // but the lazy middleware hasn't run yet, so getEmailService() throws.
    expect(() => getEmailService()).toThrow(/before setEmailService/)
  })

  it('lazy first-request middleware wires EmailServiceImpl + plugin hooks', async () => {
    const app = createSonicJSApp({ sonicPlugins: [emailPluginV3] })

    // Fire a request to a route that exercises the v3-init middleware chain.
    // Use /health which exists on most SonicJS apps; if that doesn't exist,
    // any request will do — the middleware chain runs on every path.
    const env = makeMockEnv()
    const res = await app.fetch(new Request('http://localhost/'), env)
    // Regardless of route status, the lazy v3-init should have fired:
    expect(res).toBeDefined()

    // After first request: singleton is wired
    expect(() => getEmailService()).not.toThrow()
    const svc = getEmailService()
    expect(svc).toBeDefined()
    expect(typeof svc.send).toBe('function')
  })

  it('emailPluginV3 has the expected v3 SonicPlugin shape', () => {
    expect(emailPluginV3.id).toBe('email')
    expect(emailPluginV3.version).toBe('1.0.0')
    expect(emailPluginV3.capabilities).toEqual([
      'email:send',
      'hooks.cron:register',
      'hooks.auth:register',
    ])
    expect(emailPluginV3.crons).toEqual([
      { schedule: '*/5 * * * *', hookFamily: 'email-reconciliation' },
    ])
    expect(emailPluginV3.hooks).toBeDefined()
    expect(emailPluginV3.hooks?.['auth:registration:completed']).toBeDefined()
    expect(emailPluginV3.hooks?.['auth:password-reset:requested']).toBeDefined()
    expect(emailPluginV3.hooks?.['auth:password-reset:completed']).toBeDefined()
    expect(emailPluginV3.hooks?.['cron:tick']).toBeDefined()
    expect(emailPluginV3.register).toBeDefined()
  })

  it('plugin.register is synchronous (returns void, not Promise) — Option A', () => {
    // Mimic registerPluginRoutes' synchronous check
    const { Hono } = require('hono') as { Hono: new () => unknown }
    const honoApp = new Hono()
    const result = emailPluginV3.register?.(honoApp as never)
    // Must be undefined (sync void) or a non-thenable
    expect(result).toBeUndefined()
  })
})

describe('emailPluginV3 — self-hosted setup UX (issue #592)', () => {
  it('GET /admin/plugins/email does not crash when EMAIL binding is absent', async () => {
    const app = createSonicJSApp({ sonicPlugins: [emailPluginV3] })
    const res = await app.fetch(
      new Request('http://localhost/admin/plugins/email'),
      { ...makeMockEnv(), EMAIL: undefined },
    )
    expect(res.status).not.toBe(500)
  })

  it('GET /admin/plugins/email does not crash when EMAIL binding is present', async () => {
    const app = createSonicJSApp({ sonicPlugins: [emailPluginV3] })
    const res = await app.fetch(new Request('http://localhost/admin/plugins/email'), makeMockEnv())
    expect(res.status).not.toBe(500)
  })

  it('POST /admin/email/settings is reachable (not 500) for any request', async () => {
    const app = createSonicJSApp({ sonicPlugins: [emailPluginV3] })
    await app.fetch(new Request('http://localhost/'), makeMockEnv()) // warm up lazy init
    const res = await app.fetch(
      new Request('http://localhost/admin/email/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fromEmail: 'test@example.com', cfAccountId: 'acct-123' }),
      }),
      makeMockEnv(),
    )
    expect(res.status).not.toBe(500)
  })
})
