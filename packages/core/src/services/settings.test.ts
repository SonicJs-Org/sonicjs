/**
 * Settings Service Tests — real SQLite (better-sqlite3 harness).
 *
 * SettingsService is document-backed: settings live in the `documents` table as
 * type_id='site_settings' rows (slug='general' / 'security'), not a legacy `settings`
 * table. These tests run the actual SQL against migrations 0001+0002 so they exercise
 * the real round-trip (saveSettingsDocument auto-creates the document_types row).
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../__tests__/utils/d1-sqlite'
import { SettingsService } from './settings'

describe('SettingsService — real SQLite', () => {
  let db: ReturnType<typeof createTestD1>
  let service: SettingsService

  beforeEach(() => {
    db = createTestD1()
    service = new SettingsService(db as any)
  })
  afterEach(() => db.close())

  describe('getGeneralSettings', () => {
    it('returns defaults when nothing is saved', async () => {
      const result = await service.getGeneralSettings()

      expect(result).toEqual({
        siteName: 'SonicJS AI',
        siteDescription: 'A modern headless CMS powered by AI',
        adminEmail: 'admin@example.com',
        timezone: 'UTC',
        language: 'en',
        maintenanceMode: false,
      })
    })

    it('uses the provided userEmail as the default adminEmail', async () => {
      const result = await service.getGeneralSettings('user@example.com')
      expect(result.adminEmail).toBe('user@example.com')
    })
  })

  describe('saveGeneralSettings / getGeneralSettings round-trip', () => {
    it('persists saved values and merges them with defaults', async () => {
      const ok = await service.saveGeneralSettings({
        siteName: 'Custom Site',
        language: 'fr',
      })
      expect(ok).toBe(true)

      const result = await service.getGeneralSettings()
      expect(result).toEqual({
        siteName: 'Custom Site',
        siteDescription: 'A modern headless CMS powered by AI',
        adminEmail: 'admin@example.com',
        timezone: 'UTC',
        language: 'fr',
        maintenanceMode: false,
      })
    })

    it('round-trips every general field, including boolean maintenanceMode', async () => {
      const ok = await service.saveGeneralSettings({
        siteName: 'Test',
        siteDescription: 'Description',
        adminEmail: 'admin@test.com',
        timezone: 'America/New_York',
        language: 'de',
        maintenanceMode: true,
      })
      expect(ok).toBe(true)

      const result = await service.getGeneralSettings()
      expect(result).toEqual({
        siteName: 'Test',
        siteDescription: 'Description',
        adminEmail: 'admin@test.com',
        timezone: 'America/New_York',
        language: 'de',
        maintenanceMode: true,
      })
    })

    it('prefers a stored adminEmail over the provided userEmail', async () => {
      await service.saveGeneralSettings({ adminEmail: 'stored@example.com' })

      const result = await service.getGeneralSettings('user@example.com')
      expect(result.adminEmail).toBe('stored@example.com')
    })

    it('merges successive partial saves instead of overwriting', async () => {
      await service.saveGeneralSettings({ siteName: 'First Name' })
      await service.saveGeneralSettings({ language: 'es' })

      const result = await service.getGeneralSettings()
      // The first save's siteName survives the second (partial) save.
      expect(result.siteName).toBe('First Name')
      expect(result.language).toBe('es')
    })

    it('updates the existing document in place rather than creating a second draft', async () => {
      await service.saveGeneralSettings({ siteName: 'V1' })
      await service.saveGeneralSettings({ siteName: 'V2' })

      const row = db.raw
        .prepare(
          `SELECT COUNT(*) n FROM documents WHERE type_id = 'site_settings' AND slug = 'general' AND is_current_draft = 1`,
        )
        .get() as { n: number }
      expect(row.n).toBe(1)

      expect((await service.getGeneralSettings()).siteName).toBe('V2')
    })

    it('auto-creates the site_settings document_type row on first save', async () => {
      await service.saveGeneralSettings({ siteName: 'X' })

      const row = db.raw
        .prepare(`SELECT id FROM document_types WHERE id = 'site_settings'`)
        .get() as { id: string } | undefined
      expect(row?.id).toBe('site_settings')
    })
  })

  describe('getSecuritySettings', () => {
    it('returns defaults when nothing is saved', async () => {
      const result = await service.getSecuritySettings()
      expect(result).toEqual({
        jwtExpiresIn: '30d',
        jwtRefreshGraceSeconds: 60 * 60 * 24 * 7,
      })
    })
  })

  describe('saveSecuritySettings / getSecuritySettings round-trip', () => {
    it('persists saved security values', async () => {
      const ok = await service.saveSecuritySettings({
        jwtExpiresIn: '7d',
        jwtRefreshGraceSeconds: 3600,
      })
      expect(ok).toBe(true)

      const result = await service.getSecuritySettings()
      expect(result).toEqual({
        jwtExpiresIn: '7d',
        jwtRefreshGraceSeconds: 3600,
      })
    })

    it('keeps a numeric jwtRefreshGraceSeconds of 0 instead of falling back to the default', async () => {
      await service.saveSecuritySettings({ jwtRefreshGraceSeconds: 0 })

      const result = await service.getSecuritySettings()
      expect(result.jwtRefreshGraceSeconds).toBe(0)
      expect(result.jwtExpiresIn).toBe('30d') // unset field keeps its default
    })

    it('merges a partial save with previously stored security values', async () => {
      await service.saveSecuritySettings({ jwtExpiresIn: '14d', jwtRefreshGraceSeconds: 120 })
      await service.saveSecuritySettings({ jwtExpiresIn: '1d' })

      const result = await service.getSecuritySettings()
      expect(result.jwtExpiresIn).toBe('1d')
      expect(result.jwtRefreshGraceSeconds).toBe(120)
    })
  })

  describe('category isolation', () => {
    it('keeps general and security settings in separate documents', async () => {
      await service.saveGeneralSettings({ siteName: 'General Site' })
      await service.saveSecuritySettings({ jwtExpiresIn: '90d' })

      expect((await service.getGeneralSettings()).siteName).toBe('General Site')
      expect((await service.getSecuritySettings()).jwtExpiresIn).toBe('90d')

      const rows = db.raw
        .prepare(
          `SELECT slug FROM documents WHERE type_id = 'site_settings' AND is_current_draft = 1 ORDER BY slug`,
        )
        .all() as Array<{ slug: string }>
      expect(rows.map((r) => r.slug)).toEqual(['general', 'security'])
    })
  })
})
