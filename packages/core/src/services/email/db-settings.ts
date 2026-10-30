/**
 * Admin-UI email settings (DB-backed)
 *
 * SonicJS stores email plugin settings in two places depending on which admin
 * path was used to save them:
 *
 *   1. `documents` table (v3 primary) — the general plugin settings page uses
 *      `PluginService.updatePluginSettings`, which writes via
 *      `json_set(data, '$.settings', json(?))`. Read with `json_extract`.
 *
 *   2. `plugins` table (legacy fallback) — the dedicated email admin route
 *      (`POST /admin/email/settings`) writes to `plugins.settings` directly.
 *
 * We try the `documents` path first and fall back to `plugins` so both storage
 * paths remain functional. Both queries return a column named `settings`
 * containing a JSON string, so the parsing logic is identical.
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
  prepare(query: string): { first(): Promise<{ settings: string | null } | null> }
}

/**
 * Load the admin-UI email settings, or null if the row is absent/unparseable.
 * Never throws — a bad settings blob just yields null.
 *
 * Tries the v3 `documents` table first (primary storage written by the plugin
 * settings page), then falls back to the legacy `plugins` table (written by
 * the dedicated email admin route).
 */
export async function loadDbEmailSettings(db: SettingsDb | EmailLogDb | undefined): Promise<DbEmailSettings | null> {
  if (!db || typeof (db as SettingsDb).prepare !== 'function') return null
  const tryParse = (settings: string | null | undefined): DbEmailSettings | null => {
    if (!settings) return null
    try {
      const parsed = JSON.parse(settings) as DbEmailSettings
      return parsed && typeof parsed === 'object' ? parsed : null
    } catch {
      return null
    }
  }
  try {
    // Primary: v3 documents table — settings saved via the plugin settings admin page.
    const docRow = await (db as SettingsDb)
      .prepare(
        `SELECT json_extract(data, '$.settings') AS settings
         FROM documents
         WHERE type_id = 'plugin' AND slug = 'email'
           AND is_current_draft = 1 AND deleted_at IS NULL
         LIMIT 1`
      )
      .first()
    const fromDoc = tryParse(docRow?.settings)
    if (fromDoc) return fromDoc
  } catch { /* documents table absent or json_extract unsupported — fall through */ }
  try {
    // Fallback: legacy plugins table — settings saved via POST /admin/email/settings.
    const pluginRow = await (db as SettingsDb)
      .prepare(`SELECT settings FROM plugins WHERE id = 'email'`)
      .first()
    return tryParse(pluginRow?.settings)
  } catch {
    return null
  }
}

/** Build a `from` header from DB settings (`"Name <email>"` or bare email). */
export function dbSettingsFrom(settings: DbEmailSettings): string | undefined {
  if (!settings.fromEmail) return undefined
  return settings.fromName ? `${settings.fromName} <${settings.fromEmail}>` : settings.fromEmail
}
