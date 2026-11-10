import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { Hono } from 'hono'
import { createAuth } from '../../auth/config'
import { PluginService } from '../../services/plugin-service'
import { PLUGIN_REGISTRY } from '../../plugins/manifest-registry'
import { csrfProtection, generateCsrfToken } from '../../middleware/csrf'
import type { Bindings, Variables } from '../../app'
import { adminRoutes } from '../../plugins/core-plugins/email-plugin/routes/admin'
import { EmailSettingsService } from '../../plugins/core-plugins/email-plugin/services/settings.service'
import { loadDbEmailSettings } from '../../services/email/db-settings'
import { createTestD1, type TestD1 } from '../utils/d1-sqlite'

let db: TestD1
const oldSettings = { resendApiKey: 'old-document-key', fromEmail: 'old@sonic.test' }
const legacySettings = { apiKey: 'legacy-key', fromEmail: 'legacy@sonic.test' }
const newSettings = { provider: 'resend', resendApiKey: 'new-key', fromEmail: 'new@sonic.test' }

function document(settings: unknown, tenant = 'default', locale = 'default', parent = '', status = 'active') {
  const id = crypto.randomUUID()
  db.raw.prepare(`INSERT INTO documents (id, root_id, type_id, slug, tenant_id, locale, parent_root_id, data)
    VALUES (?, ?, 'plugin', 'email', ?, ?, ?, ?)`)
    .run(id, id, tenant, locale, parent, JSON.stringify({ settings, status, isCore: true }))
  return id
}

function data(id: string) {
  const row = db.raw.prepare('SELECT data FROM documents WHERE id = ?').get(id) as { data: string }
  return JSON.parse(row.data)
}

function postSettings(body: unknown, role = 'admin', headers: Record<string, string> = {}) {
  const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()
  app.use('*', async (c, next) => {
    c.set('user', { userId: 'admin', role, email: 'admin@sonic.test', exp: 9999999999, iat: 0 })
    // Request tenant does not own the global plugin configuration.
    c.set('tenantId', 'tenant-a')
    await next()
  })
  app.use('*', csrfProtection())
  app.route('/admin/email', adminRoutes)
  return app.request('/admin/email/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body),
  }, { DB: db, JWT_SECRET: 'csrf-integration-secret' } as unknown as Bindings)
}

async function magicLink(expectedStatus = 200) {
  const auth = createAuth({
    DB: db, BETTER_AUTH_SECRET: 'test-better-auth-secret-at-least-32-chars', BETTER_AUTH_URL: 'https://sonic.test',
  } as unknown as Bindings)
  const response = await auth.handler(new Request('https://sonic.test/auth/sign-in/magic-link', {
    method: 'POST', headers: { Origin: 'https://sonic.test', 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'recipient@sonic.test', callbackURL: '/admin' }),
  }))
  expect(response.status, await response.text()).toBe(expectedStatus)
}

beforeEach(() => {
  db = createTestD1()
  db.raw.exec('CREATE TABLE plugins (id TEXT PRIMARY KEY, settings TEXT, updated_at INTEGER, status TEXT)')
  db.raw.prepare('INSERT INTO plugins (id, settings, status) VALUES (?, ?, ?)')
    .run('email', JSON.stringify(legacySettings), 'inactive')
  vi.spyOn(console, 'log').mockImplementation(() => {})
})

afterEach(() => {
  db.close()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('global email settings consumers', () => {
  it.each([undefined, {}, PLUGIN_REGISTRY.email!.defaultSettings])('migrates legacy settings when first installation receives seed %j', async settings => {
    const service = new PluginService(db as unknown as D1Database)
    const installed = await service.installPlugin({ id: 'email', settings })
    expect(PLUGIN_REGISTRY.email!.defaultSettings).toMatchObject({ provider: 'cloudflare', resendApiKey: '' })
    expect(installed.settings).toEqual(legacySettings)
    expect(await loadDbEmailSettings(db)).toEqual(legacySettings)
  })

  it.each([{}, PLUGIN_REGISTRY.email!.defaultSettings])('does not resurrect legacy credentials when reinstalling deliberately cleared %j', async clearedSettings => {
    const service = new PluginService(db as unknown as D1Database)
    await service.installPlugin({ id: 'email' })
    await service.updatePluginSettings('email', clearedSettings)
    const installed = await service.installPlugin({ id: 'email', settings: PLUGIN_REGISTRY.email!.defaultSettings })
    expect(installed.settings).toEqual(clearedSettings)
    expect(await loadDbEmailSettings(db)).toEqual(clearedSettings)
  })

  it('preserves explicitly supplied installation settings over legacy credentials', async () => {
    const installed = await new PluginService(db as unknown as D1Database).installPlugin({ id: 'email', settings: newSettings })
    expect(installed.settings).toEqual(newSettings)
    expect(await loadDbEmailSettings(db)).toEqual(newSettings)
  })

  it('preserves a deliberate legacy clear during first document installation', async () => {
    db.raw.prepare("UPDATE plugins SET settings = '{}' WHERE id = 'email'").run()
    const installed = await new PluginService(db as unknown as D1Database).installPlugin({ id: 'email' })
    expect(installed.settings).toEqual({})
    expect(await loadDbEmailSettings(db)).toEqual({})
  })

  it.each(['document', 'legacy'])('auth uses development logging for exact registry seed defaults in %s storage', async storage => {
    const defaults = PLUGIN_REGISTRY.email!.defaultSettings
    expect(defaults).toEqual({
      provider: 'cloudflare', resendApiKey: '', fromEmail: '', fromName: '',
      replyTo: '', logoUrl: '', cfAccountId: '', cfEmailApiToken: '',
    })
    if (storage === 'document') {
      db.raw.exec("DELETE FROM plugins WHERE id = 'email'")
      const installed = await new PluginService(db as unknown as D1Database).installPlugin({ id: 'email', settings: defaults })
      expect(installed.settings).toEqual(defaults)
    } else {
      db.raw.prepare("UPDATE plugins SET settings = ? WHERE id = 'email'").run(JSON.stringify(defaults))
    }
    expect(await loadDbEmailSettings(db)).toEqual(defaults)
    const fetchImpl = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchImpl)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await magicLink()
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(console.log).toHaveBeenCalledWith('[email-dev] To:recipient@sonic.test | Subject:Your sign-in link')
  })

  it.each(['', 'stale-resend-key'])('auth rejects configured Cloudflare without a wrong transport fetch (Resend key: %j)', async resendApiKey => {
    document({
      ...PLUGIN_REGISTRY.email!.defaultSettings, resendApiKey,
      cfAccountId: 'configured-account', cfEmailApiToken: 'configured-token',
    })
    const fetchImpl = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchImpl)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await magicLink(500)
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('[email-dev]'))
  })

  it.each(['cloudflare', 'invalid-provider'])('auth refuses selected %s instead of using a stale Resend key', async provider => {
    document({ ...oldSettings, provider })
    const fetchImpl = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchImpl)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await magicLink(500)
    expect(fetchImpl).not.toHaveBeenCalled()
    expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('[email-dev]'))
  })

  it.each([401, 503])('auth surfaces Resend HTTP %s failures', async status => {
    document(newSettings)
    const fetchImpl = vi.fn(async () => new Response('delivery failed', { status }))
    vi.stubGlobal('fetch', fetchImpl)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await magicLink(500)
    expect(fetchImpl).toHaveBeenCalledOnce()
    expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('[email-dev]'))
  })

  it('auth surfaces a transport exception instead of reporting a dev send', async () => {
    document(newSettings)
    const fetchImpl = vi.fn(async () => { throw new Error('network unavailable') })
    vi.stubGlobal('fetch', fetchImpl)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    await magicLink(500)
    expect(fetchImpl).toHaveBeenCalledOnce()
    expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('[email-dev]'))
  })

  it('reads only the default tenant, locale and root plugin document', async () => {
    document({ resendApiKey: 'tenant-key' }, 'tenant-a')
    document({ resendApiKey: 'translated-key' }, 'default', 'fr')
    document({ resendApiKey: 'nested-key' }, 'default', 'default', 'other-root')
    document(oldSettings)
    expect(await loadDbEmailSettings(db)).toEqual(oldSettings)
  })

  it('ignores another tenant when the global document is absent', async () => {
    document({ resendApiKey: 'tenant-key' }, 'tenant-a')
    expect(await loadDbEmailSettings(db)).toEqual(legacySettings)
  })

  it('plugin settings service agrees with the core document reader', async () => {
    document(oldSettings)
    expect(await new EmailSettingsService(db as unknown as D1Database).load()).toEqual(oldSettings)
  })

  it('auth sends with the global document key and sender', async () => {
    document({ resendApiKey: 'tenant-key', fromEmail: 'tenant@sonic.test' }, 'tenant-a')
    document(oldSettings)
    const fetchImpl = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchImpl)
    await magicLink()
    expect(fetchImpl).toHaveBeenCalledOnce()
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe('https://api.resend.com/emails')
    expect(init.headers).toMatchObject({ Authorization: 'Bearer old-document-key' })
    expect(JSON.parse(init.body as string)).toMatchObject({ from: 'SonicJS <old@sonic.test>', to: ['recipient@sonic.test'] })
  })

  it('auth rejects array settings and uses legacy fallback', async () => {
    document([])
    const fetchImpl = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchImpl)
    await magicLink()
    expect(fetchImpl).toHaveBeenCalledOnce()
    expect(fetchImpl.mock.calls[0]).toEqual([
      'https://api.resend.com/emails', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer legacy-key' }) }),
    ])
  })

  it('empty global settings disable DB email across readers without reviving legacy keys', async () => {
    document({})
    const fetchImpl = vi.fn(() => { throw new Error('Unexpected network call') })
    vi.stubGlobal('fetch', fetchImpl)
    expect(await loadDbEmailSettings(db)).toEqual({})
    expect(await new EmailSettingsService(db as unknown as D1Database).load()).toEqual({})
    await magicLink()
    expect(fetchImpl).not.toHaveBeenCalled()
  })
})

describe('POST /admin/email/settings storage round trip', () => {
  it('uses schema seconds for both document and legacy updated_at', async () => {
    const now = Math.floor(Date.now() / 1000)
    vi.spyOn(Date, 'now').mockReturnValue(now * 1000 + 123)
    expect((await postSettings(newSettings)).status).toBe(200)
    expect(db.raw.prepare("SELECT updated_at FROM plugins WHERE id = 'email'").get()).toEqual({ updated_at: now })
    const id = document(oldSettings)
    expect((await postSettings(newSettings)).status).toBe(200)
    expect(db.raw.prepare('SELECT updated_at FROM documents WHERE id = ?').get(id)).toEqual({ updated_at: now })
  })

  it('existing CSRF middleware rejects missing/mismatched cookie-auth tokens and accepts a signed token', async () => {
    const id = document(oldSettings)
    const cookie = 'auth_token=session; csrf_token=unsigned'
    expect((await postSettings(newSettings, 'admin', { Cookie: cookie })).status).toBe(403)
    expect((await postSettings(newSettings, 'admin', { Cookie: cookie, 'X-CSRF-Token': 'different' })).status).toBe(403)
    expect(data(id).settings).toEqual(oldSettings)
    const token = await generateCsrfToken('csrf-integration-secret')
    const response = await postSettings(newSettings, 'admin', {
      Cookie: `auth_token=session; csrf_token=${token}`, 'X-CSRF-Token': token,
    })
    expect(response.status).toBe(200)
    expect(data(id).settings).toEqual(newSettings)
  })

  it('updates the authoritative document and preserves status, history and tenant ownership', async () => {
    const foreign = document({ resendApiKey: 'tenant-key' }, 'tenant-a')
    const translated = document({ resendApiKey: 'translated-key' }, 'default', 'fr')
    const nested = document({ resendApiKey: 'nested-key' }, 'default', 'default', 'other-root')
    const historical = document({ resendApiKey: 'historical-key' })
    db.raw.prepare('UPDATE documents SET is_current_draft = 0 WHERE id = ?').run(historical)
    const deleted = document({ resendApiKey: 'deleted-key' })
    db.raw.prepare('UPDATE documents SET deleted_at = 1 WHERE id = ?').run(deleted)
    const canonical = document(oldSettings, 'default', 'default', '', 'inactive')
    const response = await postSettings({ ...newSettings, fromEmail: ' new@sonic.test ', ignored: 'value' })
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ success: true, settings: newSettings })
    expect(await loadDbEmailSettings(db)).toEqual(newSettings)
    expect(await new EmailSettingsService(db as unknown as D1Database).load()).toEqual(newSettings)
    expect(data(canonical)).toMatchObject({ settings: newSettings, status: 'inactive', isCore: true })
    expect(data(foreign).settings).toEqual({ resendApiKey: 'tenant-key' })
    expect(data(translated).settings).toEqual({ resendApiKey: 'translated-key' })
    expect(data(nested).settings).toEqual({ resendApiKey: 'nested-key' })
    expect(data(historical).settings).toEqual({ resendApiKey: 'historical-key' })
    expect(data(deleted).settings).toEqual({ resendApiKey: 'deleted-key' })
    // Auth reads per send; this also proves the POST is visible outside the admin page.
    const fetchImpl = vi.fn(async () => new Response('{}'))
    vi.stubGlobal('fetch', fetchImpl)
    await magicLink()
    expect(fetchImpl.mock.calls[0]).toEqual([
      'https://api.resend.com/emails', expect.objectContaining({ headers: expect.objectContaining({ Authorization: 'Bearer new-key' }) }),
    ])
  })

  it('clears document credentials rather than merging stale keys back in', async () => {
    const id = document(oldSettings)
    expect((await postSettings({})).status).toBe(200)
    expect(data(id).settings).toEqual({})
    expect(await loadDbEmailSettings(db)).toEqual({})
    expect(await new EmailSettingsService(db as unknown as D1Database).load()).toEqual({})
  })

  it.each([false, true])('keeps legacy-only writes working (documents table missing=%s)', async missingTable => {
    if (missingTable) db.raw.exec('DROP TABLE documents')
    expect((await postSettings(newSettings)).status).toBe(200)
    expect(await loadDbEmailSettings(db)).toEqual(newSettings)
  })

  it('does not hide document write failures by updating legacy settings', async () => {
    document(oldSettings)
    db.raw.exec(`CREATE TRIGGER reject_email_update BEFORE UPDATE ON documents BEGIN SELECT RAISE(ABORT, 'write failed'); END`)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    expect((await postSettings(newSettings)).status).toBe(500)
    expect(await loadDbEmailSettings(db)).toEqual(oldSettings)
    expect(JSON.parse((db.raw.prepare("SELECT settings FROM plugins WHERE id = 'email'").get() as { settings: string }).settings)).toEqual(legacySettings)
  })

  it('rejects array bodies without clearing credentials', async () => {
    const id = document(oldSettings)
    expect((await postSettings([])).status).toBe(400)
    expect(data(id).settings).toEqual(oldSettings)
  })

  it('rejects non-admin writes', async () => {
    const id = document(oldSettings)
    expect((await postSettings(newSettings, 'editor')).status).toBe(403)
    expect(data(id).settings).toEqual(oldSettings)
  })
})
