// @ts-nocheck
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import { DEFAULT_QUERY_TRACE_SETTINGS } from '../../../plugins/core-plugins/query-trace-plugin/constants'

const state = { active: true, settings: { ...DEFAULT_QUERY_TRACE_SETTINGS } }
vi.mock('../../../plugins/core-plugins/query-trace-plugin/state', () => ({
  getQueryTraceState: async () => state,
  invalidateQueryTraceState: () => {},
}))

import { queryTraceMiddleware } from '../../../plugins/core-plugins/query-trace-plugin/middleware/query-trace-middleware'
import { RAW } from '../../../utils/request-trace/traced-d1'

const mkDb = () => ({
  prepare: (sql: string) => {
    const st = {
      bind: () => st,
      all: async () => ({ results: [], meta: { duration: 1 } }),
      first: async () => null,
      run: async () => ({ meta: { duration: 1 } }),
      raw: async () => [],
    }
    return st
  },
  batch: async (s: any[]) => s.map(() => ({ results: [], meta: {} })),
})
const mkKv = () => ({ get: async () => null, put: async () => {}, delete: async () => {}, list: async () => ({ keys: [] }) })

function mkApp(opts: { role?: string | null; html?: string; handler?: (c: any) => any } = {}) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    if (opts.role !== null) c.set('user', { userId: 'u', email: 'e', role: opts.role ?? 'admin' })
    return next()
  })
  app.use('*', queryTraceMiddleware())
  const h = opts.handler ?? (async (c: any) => {
    await c.env.DB.prepare('select * from t where id = 1').all()
    return c.html(opts.html ?? '<html><body>hi</body></html>')
  })
  app.all('*', h)
  return app
}
const env = () => ({ DB: mkDb(), CACHE_KV: mkKv() })
const cookie = { headers: { cookie: 'sjs_trace=1' } }

beforeEach(() => {
  state.active = true
  state.settings = { ...DEFAULT_QUERY_TRACE_SETTINGS }
})

describe('queryTraceMiddleware', () => {
  it('inactive: untouched, but DB is a passthrough proxy that records nothing', async () => {
    state.active = false
    let seen: any
    const app = mkApp({ handler: async (c) => { seen = c.env.DB; await seen.prepare('select 1').all(); return c.html('<body></body>') } })
    const res = await app.request('/admin/x', cookie, env())
    expect(seen[RAW]).toBeDefined()
    expect(res.headers.get('server-timing')).toBeNull()
    expect(await res.text()).not.toContain('sjs-trace-panel')
  })

  it('singleton regression: service holding DB from earlier request traces in later request', async () => {
    let captured: any
    const e = env()
    const app = mkApp({
      handler: async (c) => {
        captured ??= c.env.DB
        await captured.prepare('select * from singleton_tbl').all()
        return c.html('<body></body>')
      },
    })
    state.active = false
    await app.request('/admin/a', {}, e)
    state.active = true
    const res = await app.request('/admin/b', cookie, e)
    expect(await res.text()).toContain('singleton_tbl')
  })

  it('only /admin and /admin/* traced', async () => {
    const app = mkApp()
    for (const p of ['/administrator', '/admin-foo']) {
      expect(await (await app.request(p, cookie, env())).text()).not.toContain('sjs-trace-panel')
    }
    for (const p of ['/admin', '/admin/x']) {
      expect(await (await app.request(p, cookie, env())).text()).toContain('sjs-trace-panel')
    }
  })

  it('opt-in without cookie: untouched', async () => {
    const res = await mkApp().request('/admin/x', {}, env())
    expect(res.headers.get('server-timing')).toBeNull()
    expect(await res.text()).not.toContain('sjs-trace-panel')
  })

  it('cookie + admin + html: panel + Server-Timing, no stale content-length', async () => {
    const app = new Hono()
    app.use('*', async (c, n) => { c.set('user', { role: 'admin' }); return n() })
    app.use('*', queryTraceMiddleware())
    app.get('*', (c) => c.body('<html><body>hi</body></html>', 200, { 'content-type': 'text/html', 'content-length': '26' }))
    const res = await app.request('/admin/x', cookie, env())
    const text = await res.text()
    expect(text).toContain('sjs-trace-panel')
    expect(res.headers.get('server-timing')).toMatch(/^total;dur=/)
    expect(res.headers.get('content-length')).toBeNull()
  })

  it('all-admins without cookie: panel', async () => {
    state.settings.visibility = 'all-admins'
    expect(await (await mkApp().request('/admin/x', {}, env())).text()).toContain('sjs-trace-panel')
  })

  it('all-admins + non-admin / anonymous: no header, no panel', async () => {
    state.settings.visibility = 'all-admins'
    for (const role of ['editor', null]) {
      const res = await mkApp({ role }).request('/admin/x', {}, env())
      expect(res.headers.get('server-timing')).toBeNull()
      expect(await res.text()).not.toContain('sjs-trace-panel')
    }
  })

  it('admin HX-Request: header only', async () => {
    const res = await mkApp().request('/admin/x', { headers: { cookie: 'sjs_trace=1', 'HX-Request': 'true' } }, env())
    expect(res.headers.get('server-timing')).toBeTruthy()
    expect(await res.text()).not.toContain('sjs-trace-panel')
  })

  it('JSON and redirect untouched', async () => {
    const j = await mkApp({ handler: (c) => c.json({ a: 1 }) }).request('/admin/x', cookie, env())
    expect(await j.json()).toEqual({ a: 1 })
    const r = await mkApp({ handler: (c) => c.redirect('/admin/y') }).request('/admin/x', cookie, env())
    expect(r.status).toBe(302)
    expect(r.headers.get('location')).toBe('/admin/y')
  })

  it('?trace=1 sets cookie and redirects clean; ?trace=0 clears', async () => {
    const res = await mkApp().request('/admin/x?trace=1&a=b', {}, env())
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/admin/x?a=b')
    expect(res.headers.get('set-cookie')).toMatch(/sjs_trace=1.*Path=\/admin.*HttpOnly.*SameSite=Lax/i)
    const off = await mkApp().request('/admin/x?trace=0', cookie, env())
    expect(off.status).toBe(302)
    expect(off.headers.get('set-cookie')).toMatch(/sjs_trace=;/)
  })

  it('concurrent requests: each panel only its own queries', async () => {
    const app = mkApp({
      handler: async (c) => {
        const q = c.req.query('q')
        await new Promise((r) => setTimeout(r, q === 'a' ? 10 : 1))
        await c.env.DB.prepare(`select * from tbl_${q}`).all()
        return c.html('<body></body>')
      },
    })
    const e = env()
    const [a, b] = await Promise.all([app.request('/admin/x?q=a', cookie, e), app.request('/admin/x?q=b', cookie, e)])
    const ta = await a.text(), tb = await b.text()
    expect(ta).toContain('tbl_a'); expect(ta).not.toContain('tbl_b')
    expect(tb).toContain('tbl_b'); expect(tb).not.toContain('tbl_a')
  })

  it('ALS unavailable: passthrough', async () => {
    vi.resetModules()
    vi.doMock('../../../utils/request-trace/trace-context', async (orig) => ({ ...(await orig()), loadAsyncLocalStorage: async () => null }))
    const { queryTraceMiddleware: mw } = await import('../../../plugins/core-plugins/query-trace-plugin/middleware/query-trace-middleware')
    const app = new Hono()
    app.use('*', async (c, n) => { c.set('user', { role: 'admin' }); return n() })
    app.use('*', mw())
    app.get('*', (c) => c.html('<body></body>'))
    const res = await app.request('/admin/x', cookie, env())
    expect(await res.text()).not.toContain('sjs-trace-panel')
    vi.doUnmock('../../../utils/request-trace/trace-context')
  })
})
