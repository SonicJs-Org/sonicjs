import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Hono } from 'hono'

// Track what gets stored
let capturedSubmissionData: string | null = null

// Mock TurnstileService — disabled by default so submissions go through
vi.mock('../plugins/core-plugins/turnstile-plugin/services/turnstile', () => ({
  TurnstileService: class MockTurnstileService {
    getSettings = vi.fn().mockResolvedValue(null)
    isEnabled = vi.fn().mockResolvedValue(false)
    verifyToken = vi.fn().mockResolvedValue({ success: true })
  }
}))

import { publicFormsRoutes } from './public-forms'

function createMockDb(formExists = true) {
  return {
    prepare: vi.fn().mockImplementation((sql: string) => {
      // Form lookup
      if (sql.includes('FROM forms WHERE')) {
        return {
          bind: vi.fn().mockReturnThis(),
          first: vi.fn().mockResolvedValue(
            formExists
              ? {
                  id: 'form-1',
                  name: 'test_form',
                  display_name: 'Test Form',
                  is_active: 1,
                  turnstile_enabled: 0,
                  turnstile_settings: null
                }
              : null
          ),
          all: vi.fn().mockResolvedValue({ results: [] }),
          run: vi.fn().mockResolvedValue({ success: true })
        }
      }
      // INSERT into form_submissions — capture the data
      if (sql.includes('INSERT INTO form_submissions')) {
        return {
          bind: vi.fn().mockImplementation((...args: any[]) => {
            // submission_data is the 3rd bound param (index 2)
            capturedSubmissionData = args[2]
            return {
              run: vi.fn().mockResolvedValue({ success: true }),
              first: vi.fn().mockResolvedValue(null),
              all: vi.fn().mockResolvedValue({ results: [] })
            }
          }),
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] })
        }
      }
      // UPDATE forms (submission count)
      if (sql.includes('UPDATE forms')) {
        return {
          bind: vi.fn().mockReturnThis(),
          run: vi.fn().mockResolvedValue({ success: true }),
          first: vi.fn().mockResolvedValue(null),
          all: vi.fn().mockResolvedValue({ results: [] })
        }
      }
      // Default
      return {
        bind: vi.fn().mockReturnThis(),
        first: vi.fn().mockResolvedValue(null),
        all: vi.fn().mockResolvedValue({ results: [] }),
        run: vi.fn().mockResolvedValue({ success: true })
      }
    })
  }
}

function createTestApp(db: any) {
  const app = new Hono()

  app.use('/api/forms/*', async (c, next) => {
    c.env = { DB: db } as any
    await next()
  })

  app.route('/api/forms', publicFormsRoutes)
  return app
}

describe('POST /api/forms/:identifier/submit — XSS sanitization', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    capturedSubmissionData = null
  })

  it('should HTML-encode script tags in string fields', async () => {
    const db = createMockDb()
    const app = createTestApp(db)

    const res = await app.request('/api/forms/form-1/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          name: 'John',
          comment: '<script>alert("xss")</script>'
        }
      })
    })

    const json = await res.json() as any
    expect(res.status).toBe(200)
    expect(json.success).toBe(true)

    // Verify stored data has encoded HTML
    const stored = JSON.parse(capturedSubmissionData!)
    expect(stored.name).toBe('John')
    expect(stored.comment).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
  })

  it('should sanitize nested objects recursively', async () => {
    const db = createMockDb()
    const app = createTestApp(db)

    const res = await app.request('/api/forms/form-1/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          user: {
            name: '<img src=x onerror=alert(1)>',
            address: {
              street: '123 Main St',
              city: '<b>Baltimore</b>'
            }
          }
        }
      })
    })

    expect(res.status).toBe(200)
    const stored = JSON.parse(capturedSubmissionData!)
    expect(stored.user.name).toBe('&lt;img src=x onerror=alert(1)&gt;')
    expect(stored.user.address.street).toBe('123 Main St')
    expect(stored.user.address.city).toBe('&lt;b&gt;Baltimore&lt;/b&gt;')
  })

  it('should sanitize arrays of strings', async () => {
    const db = createMockDb()
    const app = createTestApp(db)

    const res = await app.request('/api/forms/form-1/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          tags: ['safe', '<script>bad</script>', 'also safe']
        }
      })
    })

    expect(res.status).toBe(200)
    const stored = JSON.parse(capturedSubmissionData!)
    expect(stored.tags).toEqual([
      'safe',
      '&lt;script&gt;bad&lt;/script&gt;',
      'also safe'
    ])
  })

  it('should pass through numbers, booleans, and null unchanged', async () => {
    const db = createMockDb()
    const app = createTestApp(db)

    const res = await app.request('/api/forms/form-1/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          age: 25,
          active: true,
          optional: null,
          name: 'Test'
        }
      })
    })

    expect(res.status).toBe(200)
    const stored = JSON.parse(capturedSubmissionData!)
    expect(stored.age).toBe(25)
    expect(stored.active).toBe(true)
    expect(stored.optional).toBeNull()
    expect(stored.name).toBe('Test')
  })

  it('should handle event handler injection attempts', async () => {
    const db = createMockDb()
    const app = createTestApp(db)

    const res = await app.request('/api/forms/form-1/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          field1: '" onmouseover="alert(1)',
          field2: "' onclick='alert(1)'",
          field3: '<img src=x onerror=alert(1)>'
        }
      })
    })

    expect(res.status).toBe(200)
    const stored = JSON.parse(capturedSubmissionData!)
    // All angle brackets and quotes should be encoded
    expect(stored.field1).not.toContain('"')
    expect(stored.field2).not.toContain("'")
    expect(stored.field3).not.toContain('<')
    expect(stored.field3).not.toContain('>')
  })
})
