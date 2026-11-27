import { test, expect } from './fixtures'
import { loginAsAdmin, TEST_ORIGIN } from './utils/test-helpers'

// Regression guard for the /api/events route-order fix (#1289).
//
// Before the fix, app.ts mounted app.route('/api/events', eventsApiRoutes) AFTER the
// bare app.route('/api', apiRoutes) catch-all.  Hono's first-match rule routed every
// /api/events request to the /:collection wildcard:
//   POST /api/events (anonymous) → /:collection requireAuth() → 401
//   GET  /api/events (anonymous) → /:collection optionalAuth() → 404 "Collection not found"
//
// The fix moves /api/events before /api in app.ts (same class as #1058, #1218).

test.describe('Events API route-order fix (#1289) @api', () => {
  let adminCookie = ''

  test.beforeAll(async ({ browser }) => {
    const context = await browser.newContext()
    const page = await context.newPage()
    await loginAsAdmin(page)
    adminCookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join('; ')
    await context.close()
  })

  const baseHeaders = () => ({
    'Content-Type': 'application/json',
    Origin: TEST_ORIGIN,
  })

  const adminHeaders = () => ({
    ...baseHeaders(),
    Cookie: adminCookie,
  })

  // ── 3c-i: anonymous POST /api/events ───────────────────────────────────────

  test('anonymous POST /api/events returns 200 with eventId', async ({ request }) => {
    const res = await request.post(`${TEST_ORIGIN}/api/events`, {
      data: { event: 'page_view', path: '/e2e-test' },
      headers: baseHeaders(),
    })

    // 401 means the request hit /api/:collection's requireAuth — the shadow bug is present.
    // 404 means no route matched at all.
    expect(res.status()).toBe(200)
    const json = await res.json()
    expect(json.success).toBe(true)
    expect(typeof json.eventId).toBe('string')
    expect(json.eventId.length).toBeGreaterThan(0)
  })

  // ── 3c-ii: anonymous GET /api/events ──────────────────────────────────────

  test('anonymous GET /api/events returns 403 (admin-only), not 404', async ({ request }) => {
    const res = await request.get(`${TEST_ORIGIN}/api/events`, {
      headers: baseHeaders(),
    })

    // 404 "Collection not found" would mean the /:collection shadow is still active.
    // 200 would mean auth is not being enforced — also wrong.
    expect(res.status()).toBe(403)
    const json = await res.json()
    expect(json.error).toBe('Admin access required')
  })

  // ── 3c-iii: admin GET /api/events ─────────────────────────────────────────

  test('admin GET /api/events returns 200 with events list', async ({ request }) => {
    // Seed an event first so there is something to query.
    const postRes = await request.post(`${TEST_ORIGIN}/api/events`, {
      data: { event: 'e2e_admin_check', path: '/e2e-test' },
      headers: baseHeaders(),
    })
    expect(postRes.status()).toBe(200)
    const { eventId } = await postRes.json()

    const getRes = await request.get(`${TEST_ORIGIN}/api/events`, {
      headers: adminHeaders(),
    })

    expect(getRes.status()).toBe(200)
    const json = await getRes.json()
    expect(Array.isArray(json.events)).toBe(true)
    // The event we just seeded should be in the response.
    expect(json.events.map((e: any) => e.id)).toContain(eventId)
  })
})
