// @ts-nocheck
// Behavioural proof that the public /api/events endpoint is not shadowed by the
// generic /api/:collection catch-all.
//
// #1289 found that app.ts mounted app.route('/api/events', eventsApiRoutes) AFTER
// app.route('/api', apiRoutes), so Hono's first-match rule routed every /api/events
// request to the /:collection wildcard:
//   POST /api/events → /:collection requireAuth() → 401
//   GET  /api/events → /:collection optionalAuth() → 404 "Collection not found"
//   GET  /api/events/stats → /:collection/:id optionalAuth() → 404 "Collection not found"
//
// Same shadow class as /api/search (#1058) and /api/v1/* (#1218).
//
// This file locks in two properties:
//   1. Behaviour — with the fix applied, anonymous POST works (200), anonymous GET
//      and GET /stats are gated (403 "Admin access required", NOT 404), and admin
//      GET returns events.
//   2. Order sensitivity — reversing the mount order (catch-all first) reproduces
//      the historical 401/404, proving the test is actually sensitive to the fix.
//
// The route-table order check (does the real app.ts register /api/events before /api?)
// lives in packages/core/src/__tests__/plugins/mount-integration.test.ts (see the
// "registers /api/events before the /api catch-all" test added there).
//
// createSonicJSApp() is quarantined from CI (better-auth transitive dep gap), so
// we reconstruct the minimal app topology here, following the same pattern as
// ai-search-disableall.integration.test.ts.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Hono } from 'hono'
import { createTestD1 } from '../utils/d1-sqlite'
import { bootstrapDocumentTypes } from '../../services/document-types-seed'

// Stub the core middleware so importing the generic content router does not
// pull in better-auth.  requireAuth() mirrors production: 401 for anonymous
// callers — the exact response that shadowed /api/events on `main` before the fix.
const h = vi.hoisted(() => ({
  user: undefined as undefined | { userId: string; email: string; role: string },
}))
vi.mock('../../middleware', () => ({
  optionalAuth: () => async (c: any, next: any) => {
    if (h.user) c.set('user', h.user)
    await next()
  },
  isPluginActive: async () => false,
  requireAuth: () => async (c: any, next: any) => {
    if (!c.get('user')) return c.json({ error: 'Authentication required' }, 401)
    await next()
  },
  requireRole: () => async (_c: any, next: any) => next(),
}))

import apiRoutes from '../../routes/api'
import { eventsApiRoutes } from '../../plugins/core-plugins/analytics/routes/api'

/**
 * Build a minimal app with the events route and the generic content catch-all.
 * `eventsFirst` = true is the fixed (correct) order; false reproduces the pre-fix shadow.
 */
function buildApp(db: any, eventsFirst: boolean) {
  const app = new Hono()
  // Inject the DB binding and seed the user from the hoisted variable.
  app.use('*', async (c, next) => {
    ;(c as any).env = { DB: db }
    c.set('tenantId', 'default')
    if (h.user) c.set('user', h.user)
    await next()
  })
  if (eventsFirst) {
    app.route('/api/events', eventsApiRoutes as any)
    app.route('/api', apiRoutes)
  } else {
    app.route('/api', apiRoutes)
    app.route('/api/events', eventsApiRoutes as any)
  }
  return app
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function post(app: any, path: string, body: unknown) {
  return app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

function get(app: any, path: string) {
  return app.request(path, { method: 'GET' })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

describe('/api/events route-order fix (#1289)', () => {
  let db: any

  beforeEach(async () => {
    h.user = undefined
    db = createTestD1()
    // bootstrapDocumentTypes registers 'analytics_event' and applies its scalar
    // schema (q_evt_event, q_evt_category, q_evt_user_id, q_evt_session_id,
    // q_evt_path), which the EventTrackingService queries directly.
    await bootstrapDocumentTypes(db)
  })

  afterEach(() => db.close())

  // ── 3a: Behaviour tests (eventsFirst = true — the fixed order) ─────────────

  it('anonymous POST /api/events with a valid body returns 200 {success, eventId}', async () => {
    const app = buildApp(db, /* eventsFirst */ true)
    const res = await post(app, '/api/events', { event: 'page_view', path: '/home' })

    // 401 here would mean the request fell through to /api/:collection's requireAuth — the shadow bug.
    expect(res.status).toBe(200)
    const json = await res.json()
    expect(json.success).toBe(true)
    expect(typeof json.eventId).toBe('string')
    expect(json.eventId.length).toBeGreaterThan(0)

    // Verify the event row actually landed in the DB.
    const row = db.raw
      .prepare("SELECT id FROM documents WHERE type_id='analytics_event' AND title='page_view'")
      .get()
    expect(row).toBeTruthy()
    expect(row.id).toBe(json.eventId)
  })

  it('POST /api/events without an "event" field returns 400 with the events router error', async () => {
    const app = buildApp(db, /* eventsFirst */ true)
    const res = await post(app, '/api/events', { path: '/home' }) // missing "event"

    expect(res.status).toBe(400)
    const json = await res.json()
    // This message comes from the events router, not from the collection catch-all.
    expect(json.error).toMatch(/"event" field is required/)
  })

  it('anonymous GET /api/events returns 403 "Admin access required", not 404', async () => {
    const app = buildApp(db, /* eventsFirst */ true)
    const res = await get(app, '/api/events')

    // 404 "Collection not found" would indicate the /:collection shadow is still active.
    expect(res.status).toBe(403)
    const json = await res.json()
    expect(json.error).toBe('Admin access required')
  })

  it('anonymous GET /api/events/stats returns 403, not 404', async () => {
    const app = buildApp(db, /* eventsFirst */ true)
    const res = await get(app, '/api/events/stats')

    expect(res.status).toBe(403)
    const json = await res.json()
    expect(json.error).toBe('Admin access required')
  })

  it('admin GET /api/events returns 200 and includes the previously posted event', async () => {
    const app = buildApp(db, /* eventsFirst */ true)

    // Seed an event anonymously (POST is open).
    const postRes = await post(app, '/api/events', { event: 'button_click', path: '/checkout' })
    expect(postRes.status).toBe(200)
    const { eventId } = await postRes.json()

    // Now query as admin.
    h.user = { userId: 'admin1', email: 'admin@sonicjs.com', role: 'admin' }
    const getRes = await get(app, '/api/events')

    expect(getRes.status).toBe(200)
    const json = await getRes.json()
    expect(json.events).toBeDefined()
    expect(json.events.map((e: any) => e.id)).toContain(eventId)
  })

  // ── 3b: Order-sensitivity regression guard ─────────────────────────────────

  it('regression guard: pre-fix mount order (catch-all first) shadows POST /api/events → 401', async () => {
    const app = buildApp(db, /* eventsFirst */ false) // wrong order — catch-all wins
    const res = await post(app, '/api/events', { event: 'page_view' })

    // The /api/:collection route uses requireAuth(); anonymous → 401.
    // This proves the test is actually sensitive to mount order, not just
    // that the events router happens to exist somewhere.
    expect(res.status).toBe(401)
  })

  it('regression guard: pre-fix mount order (catch-all first) shadows GET /api/events → 404', async () => {
    const app = buildApp(db, /* eventsFirst */ false) // wrong order — catch-all wins
    const res = await get(app, '/api/events')

    // The /api/:collection route uses optionalAuth(); "events" is not a collection → 404.
    expect(res.status).toBe(404)
    const json = await res.json()
    // The collection router's not-found message (not the events router's 403).
    expect(json.error ?? json.message ?? JSON.stringify(json)).toMatch(/not found/i)
  })
})
