/**
 * EmailSettingsService — D1 read for the email-plugin's stored settings.
 *
 * Settings live in the `plugins.settings` JSON column for plugin id `'email'`
 * (the project's standard plugin-settings storage pattern, shared with all
 * other plugins via `routes/admin-plugins.ts`).
 *
 * Per Decision 7 (LOCKED), settings are read on every send — no caching in
 * the first iteration. Cost is ~1ms per send for a small JSON parse,
 * acceptable for v1. A cache-with-TTL + cache-bust-on-POST optimization is
 * documented as a follow-up issue.
 *
 * Reads are tolerant: a missing row, a NULL settings field, or a
 * non-JSON-parseable string all resolve to an empty `EmailSettings` object.
 * The consumer (EmailServiceImpl) is responsible for surfacing the
 * resulting "missing fromEmail" condition as an `EmailValidationError` when
 * the caller didn't supply `from` on `SendEmailOptions`.
 */
import type { EmailSettings } from '../types'

interface PluginSettingsRow {
  settings: string | null
}

export class EmailSettingsService {
  constructor(private readonly db: D1Database) {}

  async load(): Promise<EmailSettings> {
    let row: PluginSettingsRow | null = null
    try {
      row = await this.db
        .prepare(`SELECT settings FROM plugins WHERE id = 'email'`)
        .first<PluginSettingsRow>()
    } catch {
      // Table missing (pre-migration) or other D1 error — return empty defaults.
      return {}
    }

    if (!row?.settings) {
      return {}
    }

    try {
      const parsed = JSON.parse(row.settings) as unknown
      if (typeof parsed !== 'object' || parsed === null) {
        return {}
      }
      return parsed as EmailSettings
    } catch {
      return {}
    }
  }
}
