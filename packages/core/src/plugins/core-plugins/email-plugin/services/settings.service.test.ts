import { describe, it, expect, vi } from 'vitest'
import { EmailSettingsService } from './settings.service'

function makeDb(settings: string | null | undefined): D1Database {
  return {
    prepare: vi.fn(() => ({
      first: vi.fn(async () =>
        settings === undefined ? null : { settings },
      ),
    })),
  } as unknown as D1Database
}

describe('EmailSettingsService.load', () => {
  it('returns empty when the plugins row is absent', async () => {
    const svc = new EmailSettingsService(makeDb(undefined))
    expect(await svc.load()).toEqual({})
  })

  it('returns empty when settings is NULL', async () => {
    const svc = new EmailSettingsService(makeDb(null))
    expect(await svc.load()).toEqual({})
  })

  it('parses valid JSON into typed settings', async () => {
    const json = JSON.stringify({
      fromEmail: 'noreply@example.com',
      fromName: 'Example',
      replyTo: 'support@example.com',
      logoUrl: 'https://example.com/logo.png',
    })
    const svc = new EmailSettingsService(makeDb(json))
    const settings = await svc.load()
    expect(settings.fromEmail).toBe('noreply@example.com')
    expect(settings.fromName).toBe('Example')
    expect(settings.replyTo).toBe('support@example.com')
    expect(settings.logoUrl).toBe('https://example.com/logo.png')
  })

  it('returns empty when settings JSON is malformed', async () => {
    const svc = new EmailSettingsService(makeDb('{ not: valid json'))
    expect(await svc.load()).toEqual({})
  })

  it('returns empty when settings JSON parses to a non-object', async () => {
    const svc = new EmailSettingsService(makeDb('"just-a-string"'))
    expect(await svc.load()).toEqual({})
  })

  it('queries the canonical global email document before legacy settings', async () => {
    const prepare = vi.fn(() => ({ first: vi.fn(async () => ({ settings: '{}' })) }))
    const db = { prepare } as unknown as D1Database
    await new EmailSettingsService(db).load()
    const sql = prepare.mock.calls[0]?.[0] as string
    expect(sql).toContain('FROM documents')
    expect(sql).toContain("slug = 'email' AND tenant_id = 'default'")
    expect(sql).toContain("locale = 'default' AND parent_root_id = ''")
    expect(sql).toContain('is_current_draft = 1 AND deleted_at IS NULL')
    expect(prepare).toHaveBeenCalledOnce()
  })

  it('keeps the legacy query when no canonical document exists', async () => {
    const prepare = vi.fn((sql: string) => ({
      first: vi.fn(async () => sql.includes('FROM documents') ? null : { settings: '{"fromEmail":"legacy@example.com"}' }),
    }))
    const settings = await new EmailSettingsService({ prepare } as unknown as D1Database).load()
    expect(settings).toEqual({ fromEmail: 'legacy@example.com' })
    expect(prepare).toHaveBeenCalledTimes(2)
    expect(prepare.mock.calls[1]?.[0]).toBe("SELECT settings FROM plugins WHERE id = 'email'")
  })
})
