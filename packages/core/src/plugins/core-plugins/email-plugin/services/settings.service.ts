/**
 * Plugin consumers share the core documents-first email settings contract.
 * A missing/unparseable row yields empty defaults; an empty document stays empty.
 */
import { loadDbEmailSettings } from '../../../../services/email/db-settings'
import type { EmailSettings } from '../types'

export class EmailSettingsService {
  constructor(private readonly db: D1Database) {}

  async load(): Promise<EmailSettings> {
    return (await loadDbEmailSettings(this.db) ?? {}) as EmailSettings
  }
}
