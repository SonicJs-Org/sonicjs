/**
 * Admin-UI email settings (DB-backed)
 *
 * SonicJS lets operators configure email from the admin Plugins page, which
 * persists an API key + from-identity as JSON in `plugins.settings` for the
 * `email` plugin. Historically each send path read this row itself (OTP, the
 * test button) and called Resend directly. The provider-agnostic EmailService
 * consolidates that: when no provider is configured via `config.email` or env,
 * the app falls back to these DB settings so existing installs keep delivering.
 */

import type { EmailLogDb } from './email-service'

export interface DbEmailSettings {
  /** Selected transport ('resend' | 'cloudflare'). */
  provider?: string
  /** Legacy Resend key (old apiKey field — kept for backward compat). */
  apiKey?: string
  /** Current Resend key field from the provider selector UI. */
  resendApiKey?: string
  fromEmail?: string
  fromName?: string
  replyTo?: string
}

/** Minimal D1 surface needed to read the settings row. */
interface SettingsDb {
  prepare(query: string): { first(): Promise<{ data: string | null } | null> }
}

/**
 * Load the admin-UI email settings, or null if the row is absent/unparseable.
 * Never throws — a bad settings blob just yields null.
 *
 * v3 stores plugin settings in the `documents` table (type_id='plugin', slug='email'),
 * not the legacy `plugins` table which no longer exists on greenfield installs.
 */
export async function loadDbEmailSettings(db: SettingsDb | EmailLogDb | undefined): Promise<DbEmailSettings | null> {
  if (!db || typeof (db as SettingsDb).prepare !== 'function') return null
  try {
    const row = await (db as SettingsDb)
      .prepare(
        `SELECT data FROM documents
         WHERE type_id = 'plugin'
           AND slug = 'email'
           AND is_current_draft = 1
           AND deleted_at IS NULL
         LIMIT 1`
      )
      .first()
    if (!row?.data) return null
    const parsed = JSON.parse(row.data) as DbEmailSettings
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch {
    return null
  }
}

/** Build a `from` header from DB settings (`"Name <email>"` or bare email). */
export function dbSettingsFrom(settings: DbEmailSettings): string | undefined {
  if (!settings.fromEmail) return undefined
  return settings.fromName ? `${settings.fromName} <${settings.fromEmail}>` : settings.fromEmail
}
