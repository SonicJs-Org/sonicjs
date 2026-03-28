import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import apiRoutes from '../../routes/api'
import { AuthManager } from '../../middleware/auth'

type MockQueryRecord = {
  sql: string
  params: unknown[]
}

function createMockEnv() {
  const queryLog: MockQueryRecord[] = []
  const collection = {
    id: 'pages-collection',
    name: 'pages',
    display_name: 'Pages',
    schema: '{}',
    is_active: 1
  }

  const contentResults = [
    {
      id: 'published-1',
      title: 'Published',
      slug: 'published',
      status: 'published',
      collection_id: 'pages-collection',
      data: '{}',
      created_at: 1,
      updated_at: 1
    }
  ]

  const db = {
    prepare: vi.fn((sql: string) => {
      const statement = {
        bind: vi.fn((...params: unknown[]) => {
          queryLog.push({ sql, params })
          return statement
        }),
        first: vi.fn(async () => {
          if (sql.includes('SELECT id FROM plugins')) {
            return null
          }

          if (sql.includes('SELECT * FROM collections WHERE name = ? AND is_active = 1')) {
            return collection
          }

          if (sql.includes('SELECT id FROM collections WHERE name = ? AND is_active = 1')) {
            return { id: collection.id }
          }

          return null
        }),
        all: vi.fn(async () => ({ results: contentResults }))
      }

      return statement
    })
  }

  return {
    env: {
      DB: db,
      KV: {}
    },
    queryLog
  }
}

describe('Public content API status policy', () => {
  let app: Hono

  beforeEach(() => {
    vi.clearAllMocks()
    app = new Hono()
    app.route('/api', apiRoutes)
  })

  it('forces anonymous /api/content requests to published status', async () => {
    const { env, queryLog } = createMockEnv()

    const response = await app.fetch(new Request('https://test.com/api/content?status=draft'), env as any)
    expect(response.status).toBe(200)

    const contentQuery = queryLog.find(entry => entry.sql.startsWith('SELECT * FROM content'))
    expect(contentQuery).toBeDefined()
    expect(contentQuery?.params).toEqual(['published', 50])
  })

  it('forces anonymous collection content requests to published status even with raw where status filters', async () => {
    const { env, queryLog } = createMockEnv()
    const where = encodeURIComponent(JSON.stringify({
      or: [
        { field: 'status', operator: 'not_equals', value: 'published' },
        { field: 'slug', operator: 'equals', value: 'published' }
      ]
    }))

    const response = await app.fetch(
      new Request(`https://test.com/api/collections/pages/content?where=${where}`),
      env as any
    )

    expect(response.status).toBe(200)

    const contentQuery = queryLog.find(entry => entry.sql.startsWith('SELECT * FROM content'))
    expect(contentQuery).toBeDefined()
    expect(contentQuery?.params).toEqual(['published', 'pages-collection', 'published', 50])
  })

  it('preserves explicit draft filtering for authenticated requests', async () => {
    const { env, queryLog } = createMockEnv()
    vi.spyOn(AuthManager, 'verifyToken').mockResolvedValue({
      userId: 'user-1',
      email: 'admin@sonicjs.com',
      role: 'admin',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    })

    const response = await app.fetch(new Request('https://test.com/api/content?status=draft', {
      headers: {
        Cookie: 'auth_token=valid-token'
      }
    }), env as any)

    expect(response.status).toBe(200)

    const contentQuery = queryLog.find(entry => entry.sql.startsWith('SELECT * FROM content'))
    expect(contentQuery).toBeDefined()
    expect(contentQuery?.params).toEqual(['draft', 50])
  })

  it('forces published filtering for authenticated viewer requests', async () => {
    const { env, queryLog } = createMockEnv()
    vi.spyOn(AuthManager, 'verifyToken').mockResolvedValue({
      userId: 'user-2',
      email: 'viewer@sonicjs.com',
      role: 'viewer',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    })

    const response = await app.fetch(new Request('https://test.com/api/content?status=draft', {
      headers: {
        Cookie: 'auth_token=viewer-token'
      }
    }), env as any)

    expect(response.status).toBe(200)

    const contentQuery = queryLog.find(entry => entry.sql.startsWith('SELECT * FROM content'))
    expect(contentQuery).toBeDefined()
    expect(contentQuery?.params).toEqual(['published', 50])
  })

  it('forces published filtering for authenticated author requests', async () => {
    const { env, queryLog } = createMockEnv()
    vi.spyOn(AuthManager, 'verifyToken').mockResolvedValue({
      userId: 'user-3',
      email: 'author@sonicjs.com',
      role: 'author',
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000)
    })

    const response = await app.fetch(new Request('https://test.com/api/content?status=archived', {
      headers: {
        Cookie: 'auth_token=author-token'
      }
    }), env as any)

    expect(response.status).toBe(200)

    const contentQuery = queryLog.find(entry => entry.sql.startsWith('SELECT * FROM content'))
    expect(contentQuery).toBeDefined()
    expect(contentQuery?.params).toEqual(['published', 50])
  })
})
