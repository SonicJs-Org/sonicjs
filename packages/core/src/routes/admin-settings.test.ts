import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'

// Mock requireAuth to pass through with admin user
vi.mock('../middleware', () => ({
  requireAuth: () => async (c: any, next: any) => {
    c.set('user', { userId: 'test-admin', email: 'admin@test.com', role: 'admin', exp: 0, iat: 0 })
    await next()
  }
}))

// Mock dependencies that aren't relevant to the truncate test
vi.mock('../templates/pages/admin-settings.template', () => ({
  renderSettingsPage: () => '<html></html>'
}))
vi.mock('../services/migrations', () => ({
  MigrationService: vi.fn()
}))
vi.mock('../services/settings', () => ({
  SettingsService: vi.fn()
}))

import { adminSettingsRoutes } from './admin-settings'

function createMockDb(validTableNames: string[] = []) {
  const runResults = new Map<string, any>()
  const mockRun = vi.fn().mockResolvedValue({ success: true })

  const mockPrepare = vi.fn().mockImplementation((sql: string) => {
    // sqlite_master query returns the valid table list
    if (sql.includes('sqlite_master')) {
      return {
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({
          results: validTableNames.map(name => ({ name }))
        }),
        first: vi.fn().mockResolvedValue(null),
        run: vi.fn().mockResolvedValue({ success: true })
      }
    }
    // DELETE FROM queries
    if (sql.startsWith('DELETE FROM')) {
      return {
        bind: vi.fn().mockReturnThis(),
        all: vi.fn().mockResolvedValue({ results: [] }),
        first: vi.fn().mockResolvedValue(null),
        run: mockRun
      }
    }
    // Default
    return {
      bind: vi.fn().mockReturnThis(),
      all: vi.fn().mockResolvedValue({ results: [] }),
      first: vi.fn().mockResolvedValue(null),
      run: vi.fn().mockResolvedValue({ success: true })
    }
  })

  return { prepare: mockPrepare, _mockRun: mockRun }
}

function createTestApp(db: any) {
  const app = new Hono()

  app.use('/admin/settings/*', async (c, next) => {
    c.env = { DB: db } as any
    c.set('appVersion' as any, '2.0.0')
    await next()
  })

  app.route('/admin/settings', adminSettingsRoutes)
  return app
}

describe('POST /admin/settings/api/database-tools/truncate', () => {
  let mockDb: ReturnType<typeof createMockDb>
  let app: ReturnType<typeof createTestApp>

  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('should truncate a valid table', async () => {
    mockDb = createMockDb(['users', 'content', 'forms'])
    app = createTestApp(mockDb)

    const res = await app.request('/admin/settings/api/database-tools/truncate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tables: ['content'] })
    })

    const json = await res.json() as any
    expect(res.status).toBe(200)
    expect(json.success).toBe(true)
    expect(json.results).toHaveLength(1)
    expect(json.results[0]).toEqual({ table: 'content', success: true })
  })

  it('should reject a table name not in sqlite_master', async () => {
    mockDb = createMockDb(['users', 'content', 'forms'])
    app = createTestApp(mockDb)

    const res = await app.request('/admin/settings/api/database-tools/truncate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tables: ['nonexistent_table'] })
    })

    const json = await res.json() as any
    expect(res.status).toBe(200)
    expect(json.results).toHaveLength(1)
    expect(json.results[0]).toEqual({
      table: 'nonexistent_table',
      success: false,
      error: 'Table not found'
    })
    // DELETE should never have been called
    expect(mockDb._mockRun).not.toHaveBeenCalled()
  })

  it('should reject SQL injection in table name', async () => {
    mockDb = createMockDb(['users', 'content', 'forms'])
    app = createTestApp(mockDb)

    const res = await app.request('/admin/settings/api/database-tools/truncate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tables: ['users; DROP TABLE content--'] })
    })

    const json = await res.json() as any
    expect(json.results[0]).toEqual({
      table: 'users; DROP TABLE content--',
      success: false,
      error: 'Table not found'
    })
    expect(mockDb._mockRun).not.toHaveBeenCalled()
  })

  it('should handle mix of valid and invalid table names', async () => {
    mockDb = createMockDb(['users', 'content', 'forms'])
    app = createTestApp(mockDb)

    const res = await app.request('/admin/settings/api/database-tools/truncate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tables: ['content', 'injected_table', 'forms'] })
    })

    const json = await res.json() as any
    expect(res.status).toBe(200)
    expect(json.results).toHaveLength(3)
    expect(json.results[0]).toEqual({ table: 'content', success: true })
    expect(json.results[1]).toEqual({ table: 'injected_table', success: false, error: 'Table not found' })
    expect(json.results[2]).toEqual({ table: 'forms', success: true })
    expect(json.message).toBe('Truncated 2 of 3 tables')
  })

  it('should return 400 when no tables specified', async () => {
    mockDb = createMockDb([])
    app = createTestApp(mockDb)

    const res = await app.request('/admin/settings/api/database-tools/truncate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tables: [] })
    })

    const json = await res.json() as any
    expect(res.status).toBe(400)
    expect(json.error).toBe('No tables specified for truncation')
  })

  it('should reject subquery injection attempts', async () => {
    mockDb = createMockDb(['users', 'content'])
    app = createTestApp(mockDb)

    const injections = [
      'users UNION SELECT * FROM content',
      "users WHERE 1=1; INSERT INTO users VALUES('hacked'",
      'users; ATTACH DATABASE',
      "content' OR '1'='1",
    ]

    const res = await app.request('/admin/settings/api/database-tools/truncate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tables: injections })
    })

    const json = await res.json() as any
    for (const result of json.results) {
      expect(result.success).toBe(false)
      expect(result.error).toBe('Table not found')
    }
    expect(mockDb._mockRun).not.toHaveBeenCalled()
  })
})
