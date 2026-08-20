import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'

// The public /api/search routes carry no auth middleware of their own; the
// app-level session middleware populates c.get('user'). These tests pin the
// per-route authorization: anonymous callers are locked to published results
// and cannot read analytics; privileged sessions retain full access.

const searchSpy = vi.fn().mockResolvedValue({ results: [], total: 0 })
const analyticsSpy = vi.fn().mockResolvedValue({ popular_queries: [] })

vi.mock('../../plugins/core-plugins/ai-search-plugin/services/ai-search', () => ({
  AISearchService: class {
    search = (...args: any[]) => searchSpy(...args)
    getSearchAnalytics = (...args: any[]) => analyticsSpy(...args)
    getSearchSuggestions = vi.fn().mockResolvedValue([])
  },
}))

import apiRoutes from '../../plugins/core-plugins/ai-search-plugin/routes/api'

// Mount behind a middleware that optionally sets a user, mirroring the app's
// session middleware. A test header selects the principal.
function makeApp() {
  const app = new Hono()
  app.use('*', async (c, next) => {
    const role = c.req.header('x-test-role')
    if (role) c.set('user' as never, { userId: 'u1', email: 'u@x.com', role } as never)
    await next()
  })
  app.route('/api/search', apiRoutes)
  return app
}

const env = { DB: {} } as any

beforeEach(() => {
  searchSpy.mockClear()
  analyticsSpy.mockClear()
})

describe('ai-search public route authorization @api-keys', () => {
  it('forces status=[published] for an anonymous search, overriding a draft filter', async () => {
    const app = makeApp()
    const res = await app.request('/api/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query: 'x', filters: { status: ['draft'] } }),
    }, env)

    expect(res.status).toBe(200)
    expect(searchSpy).toHaveBeenCalledTimes(1)
    expect(searchSpy.mock.calls[0][0].filters.status).toEqual(['published'])
  })

  it('preserves the requested status filter for a privileged (editor) search', async () => {
    const app = makeApp()
    const res = await app.request('/api/search', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-test-role': 'editor' },
      body: JSON.stringify({ query: 'x', filters: { status: ['draft'] } }),
    }, env)

    expect(res.status).toBe(200)
    expect(searchSpy.mock.calls[0][0].filters.status).toEqual(['draft'])
  })

  it('denies analytics to an anonymous caller (403)', async () => {
    const app = makeApp()
    const res = await app.request('/api/search/analytics', { method: 'GET' }, env)
    expect(res.status).toBe(403)
    expect(analyticsSpy).not.toHaveBeenCalled()
  })

  it('allows analytics for an admin session', async () => {
    const app = makeApp()
    const res = await app.request('/api/search/analytics', {
      method: 'GET',
      headers: { 'x-test-role': 'admin' },
    }, env)
    expect(res.status).toBe(200)
    expect(analyticsSpy).toHaveBeenCalledTimes(1)
  })
})
