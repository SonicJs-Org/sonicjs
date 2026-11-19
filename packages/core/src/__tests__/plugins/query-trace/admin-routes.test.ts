// @ts-nocheck
import { describe, it, expect, vi } from 'vitest'
import { Hono } from 'hono'
import { DEFAULT_QUERY_TRACE_SETTINGS } from '../../../plugins/core-plugins/query-trace-plugin/constants'

const state = { active: true, settings: { ...DEFAULT_QUERY_TRACE_SETTINGS } }
const seenDb: any[] = []
const alsFlag = { available: true }
vi.mock('../../../utils/request-trace', async (orig) => ({
  ...(await orig<any>()),
  loadAsyncLocalStorage: async () => (alsFlag.available ? {} : null),
}))
vi.mock('../../../plugins/core-plugins/query-trace-plugin/state', () => ({
  getQueryTraceState: async (db: any) => { seenDb.push(db); return state },
  invalidateQueryTraceState: () => {},
}))
import { queryTraceAdminRoutes } from '../../../plugins/core-plugins/query-trace-plugin/routes/admin'

const mk = (user: any) => {
  const app = new Hono()
  app.use('*', async (c, n) => { if (user) c.set('user', user); return n() })
  app.route('/admin/plugins/query-trace', queryTraceAdminRoutes)
  return app
}
const env = { DB: {} }
const P = '/admin/plugins/query-trace'
import { getTracedD1 } from '../../../utils/request-trace'

describe('query-trace admin routes', () => {
  it('anonymous → redirect, non-admin → 403', async () => {
    expect((await mk(null).request(P, {}, env)).status).toBe(302)
    expect((await mk({ role: 'editor' }).request(P, {}, env)).status).toBe(403)
    expect((await mk({ role: 'editor' }).request(`${P}/me`, { method: 'POST' }, env)).status).toBe(403)
  })

  it('admin sees state and enable button; opted-in sees disable', async () => {
    const app = mk({ role: 'admin' })
    const html = await (await app.request(P, {}, env)).text()
    expect(html).toContain('data-testid="trace-me-enable"')
    expect(html).toContain('Active')
    const html2 = await (await app.request(P, { headers: { cookie: 'sjs_trace=1' } }, env)).text()
    expect(html2).toContain('data-testid="trace-me-disable"')
  })

  it('POST /me sets and clears cookie', async () => {
    const app = mk({ role: 'admin' })
    const on = await app.request(`${P}/me`, { method: 'POST', body: new URLSearchParams({ enabled: '1' }) }, env)
    expect(on.status).toBe(303)
    expect(on.headers.get('set-cookie')).toMatch(/sjs_trace=1/)
    const off = await app.request(`${P}/me`, { method: 'POST', headers: { 'HX-Request': 'true' }, body: new URLSearchParams({ enabled: '0' }) }, env)
    expect(off.headers.get('hx-redirect')).toBe(P)
    expect(off.headers.get('set-cookie')).toMatch(/sjs_trace=;/)
  })

  it('all-admins hides personal toggle; inactive shown', async () => {
    state.settings = { ...state.settings, visibility: 'all-admins' }
    state.active = false
    const html = await (await mk({ role: 'admin' }).request(P, {}, env)).text()
    expect(html).not.toContain('trace-me-enable')
    expect(html).toContain('Inactive')
  })

  it('reads state through the RAW db, not the traced proxy', async () => {
    const raw = { prepare: () => ({}) }
    const traced = getTracedD1(raw)
    seenDb.length = 0
    await mk({ role: 'admin' }).request(P, {}, { DB: traced })
    expect(seenDb[0]).toBe(raw)
  })

  it('"Tracing for you" is Off when plugin inactive or ALS unavailable', async () => {
    state.active = true
    state.settings = { ...DEFAULT_QUERY_TRACE_SETTINGS, visibility: 'all-admins' }
    const me = (h: string) => /trace-state-me">(\w+)</.exec(h)![1]
    expect(me(await (await mk({ role: 'admin' }).request(P, {}, env)).text())).toBe('On')
    alsFlag.available = false
    expect(me(await (await mk({ role: 'admin' }).request(P, {}, env)).text())).toBe('Off')
    alsFlag.available = true
    state.active = false
    expect(me(await (await mk({ role: 'admin' }).request(P, {}, env)).text())).toBe('Off')
    state.active = true
  })
})
