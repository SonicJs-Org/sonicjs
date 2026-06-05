import { describe, it, expect, beforeEach } from 'vitest'
import { loadDbEmailSettings, dbSettingsFrom } from '../../services/email/db-settings'
import { createSonicJSApp } from '../../app'
import {
  getEmailService,
  resetEmailService,
} from '../../services/email/email-service-singleton'
import { resetHookSystem } from '../../plugins/hooks/hook-system-singleton'

// A fake D1 whose `plugins` row carries the given settings JSON.
function dbWith(settingsJson: string | null) {
  return {
    prepare(sql: string) {
      return {
        bind: (..._a: unknown[]) => ({
          first: async () => null,
          run: async () => ({ success: true }),
          all: async () => ({ results: [] }),
        }),
        first: async () =>
          /FROM plugins WHERE id = 'email'/.test(sql) ? { settings: settingsJson } : null,
        run: async () => ({ success: true }),
        all: async () => ({ results: [] }),
      }
    },
    batch: async () => [],
    exec: async () => ({ count: 0 }),
  }
}

describe('loadDbEmailSettings', () => {
  it('parses the email plugin settings row', async () => {
    const settings = await loadDbEmailSettings(
      dbWith(JSON.stringify({ apiKey: 're_x', fromEmail: 'a@b.com', fromName: 'Site' })) as never
    )
    expect(settings).toMatchObject({ apiKey: 're_x', fromEmail: 'a@b.com', fromName: 'Site' })
  })

  it('returns null when there is no settings row', async () => {
    expect(await loadDbEmailSettings(dbWith(null) as never)).toBeNull()
  })

  it('returns null (never throws) for malformed JSON', async () => {
    expect(await loadDbEmailSettings(dbWith('not-json') as never)).toBeNull()
  })

  it('returns null for a missing db', async () => {
    expect(await loadDbEmailSettings(undefined)).toBeNull()
  })
})

describe('dbSettingsFrom', () => {
  it('formats "Name <email>" when a name is present', () => {
    expect(dbSettingsFrom({ fromEmail: 'a@b.com', fromName: 'Site' })).toBe('Site <a@b.com>')
  })
  it('uses the bare email when no name', () => {
    expect(dbSettingsFrom({ fromEmail: 'a@b.com' })).toBe('a@b.com')
  })
  it('is undefined without a from email', () => {
    expect(dbSettingsFrom({})).toBeUndefined()
  })
})

describe('EmailService honors admin-UI (DB) settings when no config/env provider', () => {
  beforeEach(() => {
    resetEmailService()
    resetHookSystem()
  })

  it('resolves the Resend provider from DB settings on first request', async () => {
    const env = { DB: dbWith(JSON.stringify({ apiKey: 're_db', fromEmail: 'noreply@site.com', fromName: 'Site' })) }
    const app = createSonicJSApp() // no config.email, no env keys

    await app.request('/health', {}, env as never)

    expect(getEmailService().getProviderName()).toBe('resend')
  })

  it('falls back to console when DB has no API key', async () => {
    const env = { DB: dbWith(JSON.stringify({ fromEmail: 'noreply@site.com' })) }
    const app = createSonicJSApp()

    await app.request('/health', {}, env as never)

    expect(getEmailService().getProviderName()).toBe('console')
  })
})
