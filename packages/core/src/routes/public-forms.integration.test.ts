import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { Hono } from 'hono'
import { vi } from 'vitest'

// Real-SQLite coverage for public-forms.ts. The mock-DB suite (public-forms.test.ts)
// can't catch SQL-level regressions — e.g. a WHERE clause silently dropping a
// condition — because its mock matches on `sql.includes('FROM forms WHERE')` and
// ignores the rest of the query. This harness runs the real `forms`/`form_submissions`
// schema from migration 0004 against better-sqlite3 so the actual SQL executes.

vi.mock('../plugins/core-plugins/turnstile-plugin/services/turnstile', () => ({
  TurnstileService: class MockTurnstileService {
    getSettings = vi.fn().mockResolvedValue(null)
    isEnabled = vi.fn().mockResolvedValue(false)
    verifyToken = vi.fn().mockResolvedValue({ success: true })
  }
}))

import { publicFormsRoutes } from './public-forms'

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../migrations')

function normalize(v: unknown): number | string | bigint | Buffer | null {
  if (v === undefined || v === null) return null
  if (typeof v === 'boolean') return v ? 1 : 0
  return v as number | string | bigint | Buffer
}

class TestStatement {
  constructor(private sqlite: Database.Database, private sql: string, private binds: unknown[] = []) {}
  bind(...args: unknown[]): TestStatement {
    return new TestStatement(this.sqlite, this.sql, args.map(normalize))
  }
  async run() {
    const info = this.sqlite.prepare(this.sql).run(...(this.binds as never[]))
    return { success: true, meta: { changes: info.changes, last_row_id: info.lastInsertRowid } }
  }
  async first<T = unknown>(): Promise<T | null> {
    const row = this.sqlite.prepare(this.sql).get(...(this.binds as never[]))
    return (row ?? null) as T | null
  }
  async all<T = unknown>() {
    const rows = this.sqlite.prepare(this.sql).all(...(this.binds as never[]))
    return { results: rows as T[], success: true, meta: {} }
  }
}

function createFormsTestD1() {
  const sqlite = new Database(':memory:')
  sqlite.pragma('foreign_keys = OFF') // mirrors D1 — see __tests__/utils/d1-sqlite.ts
  const sql = readFileSync(join(MIGRATIONS_DIR, '0004_forms.sql'), 'utf-8')
  sqlite.exec(sql)
  return {
    sqlite,
    db: {
      prepare(sql: string) {
        return new TestStatement(sqlite, sql)
      }
    } as unknown as D1Database
  }
}

function insertForm(sqlite: Database.Database, overrides: Partial<Record<string, unknown>> = {}) {
  const now = Date.now()
  const form = {
    id: 'form-1',
    name: 'test_form',
    display_name: 'Test Form',
    description: null,
    category: 'general',
    formio_schema: JSON.stringify({ components: [] }),
    settings: JSON.stringify({}),
    is_active: 1,
    is_public: 1,
    turnstile_enabled: 0,
    turnstile_settings: null,
    submission_count: 0,
    created_at: now,
    updated_at: now,
    ...overrides
  }
  sqlite.prepare(`
    INSERT INTO forms (id, name, display_name, description, category, formio_schema, settings, is_active, is_public, submission_count, created_at, updated_at)
    VALUES (@id, @name, @display_name, @description, @category, @formio_schema, @settings, @is_active, @is_public, @submission_count, @created_at, @updated_at)
  `).run(form)
  return form
}

function createTestApp(db: D1Database) {
  const app = new Hono()
  app.use('/api/forms/*', async (c, next) => {
    c.env = { DB: db } as any
    await next()
  })
  app.route('/api/forms', publicFormsRoutes)
  return app
}

describe('public-forms.ts — real-SQLite regression coverage', () => {
  let harness: ReturnType<typeof createFormsTestD1>

  beforeEach(() => {
    harness = createFormsTestD1()
  })

  afterEach(() => {
    harness.sqlite.close()
  })

  describe('POST /:identifier/submit — is_public gate', () => {
    it('rejects submission to a private (is_public=0) form with 404', async () => {
      insertForm(harness.sqlite, { is_public: 0 })
      const app = createTestApp(harness.db)

      const res = await app.request('/api/forms/test_form/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { name: 'attacker' } })
      })

      expect(res.status).toBe(404)
    })

    it('accepts submission to a public (is_public=1) form', async () => {
      insertForm(harness.sqlite, { is_public: 1 })
      const app = createTestApp(harness.db)

      const res = await app.request('/api/forms/test_form/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { name: 'legit' } })
      })

      expect(res.status).toBe(200)
      const row = harness.sqlite.prepare('SELECT * FROM form_submissions WHERE form_id = ?').get('form-1') as any
      expect(row).toBeTruthy()
      expect(JSON.parse(row.submission_data).name).toBe('legit')
    })

    it('rejects an inactive (is_active=0) form even if public', async () => {
      insertForm(harness.sqlite, { is_active: 0, is_public: 1 })
      const app = createTestApp(harness.db)

      const res = await app.request('/api/forms/test_form/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: {} })
      })

      expect(res.status).toBe(404)
    })
  })

  describe('GET /:name — HTML escaping of admin-authored fields', () => {
    it('escapes display_name and description against stored XSS', async () => {
      insertForm(harness.sqlite, {
        display_name: '</title><script>alert(1)</script>',
        description: '<img src=x onerror=alert(2)>'
      })
      const app = createTestApp(harness.db)

      const res = await app.request('/api/forms/test_form')
      const html = await res.text()

      expect(res.status).toBe(200)
      expect(html).not.toContain('<script>alert(1)</script>')
      expect(html).not.toContain('<img src=x onerror=alert(2)>')
      expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
      expect(html).toContain('&lt;img src=x onerror=alert(2)&gt;')
    })

    it('neutralizes a </script> breakout inside the embedded formio_schema JSON', async () => {
      insertForm(harness.sqlite, {
        formio_schema: JSON.stringify({
          components: [{ type: 'textfield', label: '</script><script>alert(3)</script>' }]
        })
      })
      const app = createTestApp(harness.db)

      const res = await app.request('/api/forms/test_form')
      const html = await res.text()

      expect(res.status).toBe(200)
      // The literal breakout sequence must never appear — the leading `<` (all a
      // parser needs to recognize a closing tag) must be escaped to \u003c.
      expect(html).not.toContain('</script><script>alert(3)</script>')
      expect(html).toContain('\\u003c/script>\\u003cscript>alert(3)\\u003c/script>')
      // And the schema must still be valid JSON once parsed back out of the script body.
      const match = html.match(/const formioSchema = (.*);\s*\n\s*const settings/)
      expect(match).toBeTruthy()
      const parsed = JSON.parse(match![1])
      expect(parsed.components[0].label).toBe('</script><script>alert(3)</script>')
    })
  })
})
