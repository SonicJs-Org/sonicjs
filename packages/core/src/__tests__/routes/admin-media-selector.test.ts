/**
 * Regression test: media selector search fragment
 *
 * The "Select Media" picker (GET /admin/media/selector) had two defects:
 *   1. its search input had an `id` but no `name`, while it used
 *      `hx-include="[name='search']"` — so the typed term was never sent; and
 *   2. the endpoint always returned the full panel (search box + grid), but the
 *      input's `hx-target` is the inner grid — so every keystroke swapped a
 *      whole new panel *into* the grid, nesting one panel per keystroke.
 *
 * The endpoint now returns the full panel only on the initial modal load and a
 * grid-only fragment for HTMX search requests (HX-Target: media-selector-grid),
 * and the input carries `name="search"`.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'

vi.mock('../../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => {
    c.set('user', { userId: 'u1', id: 'u1', email: 'admin@test.com', role: 'admin' })
    await next()
  },
  requireRole: () => async (_c: any, next: any) => {
    await next()
  },
}))

import { adminMediaRoutes } from '../../routes/admin-media'

function makeRow(i: number) {
  return {
    id: `m${i}`,
    filename: `file-${i}.png`,
    original_name: `File ${i}.png`,
    mime_type: 'image/png',
    size: 1234,
    r2_key: `uploads/file-${i}.png`,
    alt: null,
    tags: null,
    uploaded_at: 1_700_000_000_000,
  }
}

function createMockEnv(rows = [makeRow(0), makeRow(1)]) {
  const queryLog: { sql: string; params: unknown[] }[] = []
  const db = {
    prepare: vi.fn((sql: string) => {
      const statement: any = {
        bind: vi.fn((...params: unknown[]) => {
          queryLog.push({ sql, params })
          return statement
        }),
        all: vi.fn(async () => ({ results: rows })),
      }
      return statement
    }),
  }
  return { env: { DB: db, KV: {} }, queryLog }
}

describe('GET /admin/media/selector', () => {
  let app: Hono

  beforeEach(() => {
    vi.clearAllMocks()
    app = new Hono()
    app.route('/admin/media', adminMediaRoutes)
  })

  it('initial load returns the full panel with a NAMED search input', async () => {
    const { env } = createMockEnv()
    const res = await app.fetch(new Request('https://test.com/admin/media/selector'), env as any)
    expect(res.status).toBe(200)
    const html = await res.text()

    // The input must have a name so hx-include actually sends the term.
    expect(html).toMatch(/<input[^>]*name="search"/)
    // Full panel includes the grid container the search targets.
    expect(html).toContain('id="media-selector-grid"')
    expect(html).toContain('data-media-id="m0"')
  })

  it('HTMX search request returns ONLY the grid fragment (no nested panel)', async () => {
    const { env, queryLog } = createMockEnv()
    const res = await app.fetch(
      new Request('https://test.com/admin/media/selector?search=file', {
        headers: { 'HX-Target': 'media-selector-grid' },
      }),
      env as any
    )
    expect(res.status).toBe(200)
    const html = await res.text()

    // Cards are present...
    expect(html).toContain('data-media-id="m0"')
    // ...but NOT a second search box or grid container (would nest on keystroke).
    expect(html).not.toContain('<input')
    expect(html).not.toContain('id="media-selector-grid"')

    // The search term was bound into the query.
    const listQuery = queryLog.find((q) => q.sql.includes('FROM media'))
    expect(listQuery?.params).toEqual(['%file%', '%file%', '%file%'])
  })

  it('empty HTMX search returns the empty-state inside the grid (no input)', async () => {
    const { env } = createMockEnv([])
    const res = await app.fetch(
      new Request('https://test.com/admin/media/selector?search=zzz', {
        headers: { 'HX-Target': 'media-selector-grid' },
      }),
      env as any
    )
    const html = await res.text()
    expect(html).toContain('No media files found')
    expect(html).toContain('col-span-full')
    expect(html).not.toContain('<input')
  })
})
