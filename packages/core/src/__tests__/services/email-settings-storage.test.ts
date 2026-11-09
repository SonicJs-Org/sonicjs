import { afterEach, describe, expect, it, vi } from 'vitest'
import Database from 'better-sqlite3'
import { loadDbEmailSettings } from '../../services/email/db-settings'
import { ResendProvider } from '../../services/email/providers/resend'
import { SendGridProvider } from '../../services/email/providers/sendgrid'
import { wireRegisteredPlugins } from '../../plugins/wire'
import { HookSystemImpl } from '../../plugins/hook-system'
import { createTestD1 } from '../utils/d1-sqlite'

const databases: Database.Database[] = []
afterEach(() => {
  vi.unstubAllGlobals()
  for (const db of databases.splice(0)) db.close()
})

function storage() {
  const raw = new Database(':memory:')
  databases.push(raw)
  raw.exec(`CREATE TABLE documents (type_id TEXT, slug TEXT, is_current_draft INTEGER, deleted_at INTEGER, data TEXT);
    CREATE TABLE plugins (id TEXT, settings TEXT);`)
  raw.prepare('INSERT INTO plugins VALUES (?, ?)').run('email', JSON.stringify({ apiKey: 'legacy' }))
  const db = { prepare: (sql: string) => ({ first: async () => raw.prepare(sql).get() as { settings: string | null } | null }) }
  const document = (settings: unknown, draft = 1, deleted: number | null = null) => {
    raw.prepare('INSERT INTO documents VALUES (?, ?, ?, ?, ?)').run('plugin', 'email', draft, deleted, JSON.stringify({ settings }))
  }
  return { raw, db, document }
}

describe('email settings storage precedence', () => {
  it('reads the current live document before legacy settings', async () => {
    const { db, document } = storage()
    document({ apiKey: 'old-version' }, 0)
    document({ apiKey: 'deleted' }, 1, 1)
    const settings = { resendApiKey: 'document-key', fromEmail: 'sender@example.com', fromName: 'Site' }
    document(settings)
    expect(await loadDbEmailSettings(db)).toEqual(settings)
  })

  it.each([null, 'invalid', 42])('falls back when document settings are %j', async settings => {
    const { db, document } = storage()
    document(settings)
    expect(await loadDbEmailSettings(db)).toEqual({ apiKey: 'legacy' })
  })

  it('falls back when documents table is absent', async () => {
    const { raw, db } = storage()
    raw.exec('DROP TABLE documents')
    expect(await loadDbEmailSettings(db)).toEqual({ apiKey: 'legacy' })
  })

  it('returns null when both storage paths fail', async () => {
    const { raw, db } = storage()
    raw.exec('DROP TABLE documents; DROP TABLE plugins')
    expect(await loadDbEmailSettings(db)).toBeNull()
  })
})

describe.each([ResendProvider, SendGridProvider])('%s Worker fetch receiver', Provider => {
  it('binds default fetch to globalThis', async () => {
    const fetchImpl = vi.fn(function (this: unknown) {
      if (this !== globalThis) throw new TypeError('Illegal invocation')
      return Promise.resolve(new Response(JSON.stringify({ id: 'sent' }), { status: 200 }))
    })
    vi.stubGlobal('fetch', fetchImpl)
    const result = await new Provider({ apiKey: 'test-key' }).send({
      to: ['recipient@example.com'], from: 'sender@example.com', subject: 'Test', text: 'Test',
    })
    expect(result.ok).toBe(true)
    expect(fetchImpl).toHaveBeenCalledOnce()
  })

  it('keeps explicitly injected fetch', async () => {
    const injected = vi.fn(async () => new Response('unavailable', { status: 503 }))
    const globalFetch = vi.fn(() => { throw new Error('Unexpected global fetch') })
    vi.stubGlobal('fetch', globalFetch)
    const result = await new Provider({ apiKey: 'test-key', fetchImpl: injected }).send({
      to: ['recipient@example.com'], from: 'sender@example.com', subject: 'Test', text: 'Test',
    })
    expect(result.ok).toBe(false)
    expect(result.error).toContain('503')
    expect(injected).toHaveBeenCalledOnce()
    expect(globalFetch).not.toHaveBeenCalled()
  })
})


describe('wired plugin legacy settings storage', () => {
  it.each([false, true])('creates/upgrades plugins table (existing=%s) without replacing settings', async existing => {
    const db = createTestD1()
    try {
      if (existing) {
        db.raw.exec(`CREATE TABLE plugins (
          id TEXT PRIMARY KEY, name TEXT, display_name TEXT, description TEXT, version TEXT,
          author TEXT, category TEXT, status TEXT, is_core INTEGER, installed_at INTEGER, last_updated INTEGER,
          settings TEXT)`)
        db.raw.prepare('INSERT INTO plugins (id, status, settings) VALUES (?, ?, ?)')
          .run('email', 'active', JSON.stringify({ apiKey: 'saved-key' }))
      }
      await wireRegisteredPlugins([{ name: 'email', version: '2.0.0' }], { hooks: new HookSystemImpl(), env: { DB: db } })
      // Reflection is deliberately asynchronous; wait for its observable upsert.
      await vi.waitFor(() => {
        expect(db.raw.prepare('SELECT version FROM plugins WHERE id = ?').get('email')).toEqual({ version: '2.0.0' })
      })
      expect(db.raw.prepare('SELECT settings FROM plugins WHERE id = ?').get('email')).toEqual({
        settings: existing ? JSON.stringify({ apiKey: 'saved-key' }) : null,
      })
      db.raw.prepare('UPDATE plugins SET settings = ?, updated_at = ? WHERE id = ?')
        .run(JSON.stringify({ apiKey: 'updated-key' }), 123, 'email')
      expect(db.raw.prepare('SELECT settings, updated_at, status FROM plugins WHERE id = ?').get('email'))
        .toEqual({ settings: JSON.stringify({ apiKey: 'updated-key' }), updated_at: 123, status: existing ? 'active' : 'inactive' })
    } finally {
      db.close()
    }
  })
})
