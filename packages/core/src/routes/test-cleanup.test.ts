import { describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import testCleanupRoutes from './test-cleanup'

function createMockDbWithoutContent() {
  const preparedSql: string[] = []

  const db = {
    prepare: vi.fn((sql: string) => {
      preparedSql.push(sql)
      if (sql.includes('FROM content')) {
        throw new Error(`legacy content table was queried: ${sql}`)
      }
      return {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue(null),
        all: vi.fn().mockResolvedValue({ results: [] }),
        run: vi.fn().mockResolvedValue({ meta: { changes: 0 } }),
      }
    }),
  }

  return { db, preparedSql }
}

function createTestApp(db: any) {
  const app = new Hono()
  app.use('*', async (c, next) => {
    c.env = { DB: db, ENVIRONMENT: 'test' } as any
    await next()
  })
  app.route('', testCleanupRoutes)
  return app
}

describe('test cleanup routes', () => {
  it('does not query legacy content tables on a greenfield document schema', async () => {
    const { db, preparedSql } = createMockDbWithoutContent()
    const app = createTestApp(db)

    const res = await app.request('/test-cleanup', { method: 'POST' })
    const body = await res.json()

    expect(res.status).toBe(200)
    expect(body.success).toBe(true)
    expect(preparedSql.some((sql) => /\bFROM\s+content\b/i.test(sql))).toBe(false)
  })
})
