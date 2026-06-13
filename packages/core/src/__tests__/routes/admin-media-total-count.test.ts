/**
 * Regression test: media library "All Files" total + pagination
 *
 * The GET /admin/media handler used to report `totalFiles: results.length`,
 * where `results` is a single page (LIMIT 24). The sidebar therefore always
 * showed "All Files (24)" and `hasNextPage` was wrong. The handler now runs a
 * COUNT(*) over the same WHERE filters and derives pagination from that total.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'

// Bypass authentication for the admin route group.
vi.mock('../../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => {
    c.set('user', { userId: 'u1', id: 'u1', email: 'admin@test.com', role: 'admin' })
    await next()
  },
  requireRole: () => async (_c: any, next: any) => {
    await next()
  },
}))

// Echo the values under test so assertions don't depend on full page markup.
vi.mock('../../templates/pages/admin-media-library.template', () => ({
  renderMediaLibraryPage: (data: any) =>
    `<html>All Files (${data.totalFiles}) hasNextPage=${data.hasNextPage} page=${data.currentPage}</html>`,
  MediaLibraryPageData: {},
  FolderStats: {},
  TypeStats: {},
}))

import { adminMediaRoutes } from '../../routes/admin-media'

const PAGE_SIZE = 24
const TOTAL = 50

function makeRow(i: number) {
  return {
    id: `m${i}`,
    filename: `file-${i}.png`,
    original_name: `File ${i}.png`,
    mime_type: 'image/png',
    size: 1234,
    r2_key: `uploads/file-${i}.png`,
    alt: null,
    caption: null,
    tags: null,
    uploaded_at: 1_700_000_000_000,
  }
}

function createMockEnv() {
  const queryLog: { sql: string; params: unknown[] }[] = []
  const pageRows = Array.from({ length: PAGE_SIZE }, (_, i) => makeRow(i))

  const db = {
    prepare: vi.fn((sql: string) => {
      const statement: any = {
        bind: vi.fn((...params: unknown[]) => {
          queryLog.push({ sql, params })
          return statement
        }),
        first: vi.fn(async () => {
          if (sql.includes('COUNT(*) as total')) return { total: TOTAL }
          return null
        }),
        all: vi.fn(async () => {
          if (sql.includes('GROUP BY folder')) return { results: [] }
          if (sql.includes('GROUP BY type')) return { results: [] }
          // The paginated list query
          return { results: pageRows }
        }),
      }
      return statement
    }),
  }

  return { env: { DB: db, KV: {} }, queryLog }
}

describe('GET /admin/media — All Files total', () => {
  let app: Hono

  beforeEach(() => {
    vi.clearAllMocks()
    app = new Hono()
    app.use('*', async (c, next) => {
      c.set('appVersion', 'test')
      await next()
    })
    app.route('/admin/media', adminMediaRoutes)
  })

  it('reports the library total from COUNT(*), not the page size', async () => {
    const { env, queryLog } = createMockEnv()

    const res = await app.fetch(new Request('https://test.com/admin/media'), env as any)
    expect(res.status).toBe(200)
    const html = await res.text()

    // Was "All Files (24)" before the fix.
    expect(html).toContain(`All Files (${TOTAL})`)
    expect(html).toContain('hasNextPage=true')

    // A COUNT(*) over the same base filter must have been issued.
    const countQuery = queryLog.find((q) => q.sql.includes('COUNT(*) as total'))
    expect(countQuery).toBeDefined()
    expect(countQuery!.sql).toContain('deleted_at IS NULL')
  })

  it('passes folder/type filters through to the count query', async () => {
    const { env, queryLog } = createMockEnv()

    const res = await app.fetch(
      new Request('https://test.com/admin/media?folder=press&type=images'),
      env as any
    )
    expect(res.status).toBe(200)

    const countQuery = queryLog.find((q) => q.sql.includes('COUNT(*) as total'))
    expect(countQuery).toBeDefined()
    // Same WHERE conditions as the list query → same bound params.
    expect(countQuery!.sql).toContain('folder = ?')
    expect(countQuery!.sql).toContain('mime_type LIKE ?')
    expect(countQuery!.params).toEqual(['press', 'image/%'])
  })

  it('marks hasNextPage false on the last page', async () => {
    const queryLog: { sql: string; params: unknown[] }[] = []
    // Only 10 rows total, all on page 1 → no next page.
    const rows = Array.from({ length: 10 }, (_, i) => makeRow(i))
    const db = {
      prepare: vi.fn((sql: string) => {
        const statement: any = {
          bind: vi.fn((...params: unknown[]) => {
            queryLog.push({ sql, params })
            return statement
          }),
          first: vi.fn(async () => (sql.includes('COUNT(*) as total') ? { total: 10 } : null)),
          all: vi.fn(async () => {
            if (sql.includes('GROUP BY')) return { results: [] }
            return { results: rows }
          }),
        }
        return statement
      }),
    }

    const res = await app.fetch(new Request('https://test.com/admin/media'), { DB: db, KV: {} } as any)
    const html = await res.text()
    expect(html).toContain('All Files (10)')
    expect(html).toContain('hasNextPage=false')
  })
})
