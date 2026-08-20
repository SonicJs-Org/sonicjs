import { test, expect } from '@playwright/test'

// Hardening for the public /api/search endpoint (ai-search-plugin):
//  - the dateRange.field SQL-injection sink is allowlisted (no 500 / no injection)
//  - the result limit is clamped
//  - analytics is no longer readable by anonymous callers
// These run unauthenticated (no seed needed) against the deployed preview.

test.describe('public search security @smoke @search', () => {
  test('malicious dateRange.field does not error or inject', async ({ request }) => {
    const res = await request.post('/api/search', {
      data: {
        query: 'test',
        filters: { dateRange: { field: 'id) OR (SELECT 1 FROM auth_user) -- ', start: '2020-01-01' } },
      },
    })
    // The allowlist falls back to a safe column, so the query executes normally
    // (200) rather than surfacing a SQL error (500).
    expect(res.status()).toBe(200)
    const body = await res.json()
    expect(body.success).toBe(true)
  })

  test('an oversized limit is clamped to the ceiling', async ({ request }) => {
    const res = await request.post('/api/search', {
      data: { query: 'a', limit: 999999 },
    })
    expect(res.status()).toBe(200)
    const body = await res.json()
    const results = body?.data?.results ?? []
    expect(Array.isArray(results)).toBe(true)
    expect(results.length).toBeLessThanOrEqual(100)
  })

  test('analytics is denied to anonymous callers', async ({ request }) => {
    const res = await request.get('/api/search/analytics')
    expect(res.status()).toBe(403)
  })
})
