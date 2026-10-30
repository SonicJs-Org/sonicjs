export interface GeneralSettings {
  siteName: string
  siteDescription: string
  adminEmail: string
  timezone: string
  language: string
  maintenanceMode: boolean
}

export interface SecuritySettings {
  jwtExpiresIn: string
  jwtRefreshGraceSeconds: number
}

const TYPE_ID = 'site_settings'
const TENANT = 'default'

export class SettingsService {
  constructor(private db: D1Database) {}

  /**
   * Get settings document for a category (general or security)
   */
  private async getSettingsDocument(category: string): Promise<any | null> {
    try {
      const row = await this.db.prepare(`
        SELECT data FROM documents
        WHERE type_id = ? AND slug = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
      `).bind(TYPE_ID, category, TENANT).first()

      if (!row) {
        return null
      }

      return JSON.parse((row as any).data)
    } catch (error) {
      console.error(`Error getting settings document for ${category}:`, error)
      return null
    }
  }

  /**
   * Save settings document for a category (general or security)
   */
  private async saveSettingsDocument(category: string, data: Record<string, any>): Promise<boolean> {
    try {
      const now = Math.floor(Date.now() / 1000)
      const jsonData = JSON.stringify(data)

      // Ensure document_types row exists (FK constraint on documents.type_id)
      await this.db.prepare(`
        INSERT OR IGNORE INTO document_types (id, name, display_name, description, schema, source, is_system, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        TYPE_ID, TYPE_ID, 'Site Settings',
        'Global site configuration settings',
        '{}', 'system', 1, 1, now, now
      ).run()

      // Check if document already exists
      const existing = await this.db.prepare(`
        SELECT id FROM documents
        WHERE type_id = ? AND slug = ? AND tenant_id = ? AND is_current_draft = 1 AND deleted_at IS NULL
      `).bind(TYPE_ID, category, TENANT).first() as any

      if (existing) {
        // Update existing document
        await this.db.prepare(`
          UPDATE documents
          SET data = ?, updated_at = ?
          WHERE id = ? AND is_current_draft = 1
        `).bind(jsonData, now, existing.id).run()
      } else {
        // Create new document
        const docId = crypto.randomUUID()
        const rootId = docId
        const title = category === 'general' ? 'General Settings' : 'Security Settings'

        await this.db.prepare(`
          INSERT INTO documents (
            id, root_id, type_id, version_number, is_current_draft, is_published, status,
            parent_root_id, slug, title, tenant_id, locale, translation_group_id,
            data, metadata, created_at, updated_at
          ) VALUES (
            ?, ?, ?, 1, 1, 1, 'published',
            '', ?, ?, ?, 'default', '',
            ?, '{}', ?, ?
          )
        `).bind(
          docId, rootId, TYPE_ID,
          category, title, TENANT,
          jsonData, now, now
        ).run()
      }

      return true
    } catch (error) {
      console.error(`Error saving settings document for ${category}:`, error)
      return false
    }
  }

  /**
   * Get general settings with defaults
   */
  async getGeneralSettings(userEmail?: string): Promise<GeneralSettings> {
    const settings = await this.getSettingsDocument('general')

    return {
      siteName: settings?.siteName || 'SonicJS AI',
      siteDescription: settings?.siteDescription || 'A modern headless CMS powered by AI',
      adminEmail: settings?.adminEmail || userEmail || 'admin@example.com',
      timezone: settings?.timezone || 'UTC',
      language: settings?.language || 'en',
      maintenanceMode: settings?.maintenanceMode || false
    }
  }

  /**
   * Save general settings
   */
  async saveGeneralSettings(settings: Partial<GeneralSettings>): Promise<boolean> {
    const existing = await this.getSettingsDocument('general')
    const merged = { ...existing, ...settings }
    return await this.saveSettingsDocument('general', merged)
  }

  /**
   * Get security settings with defaults
   */
  async getSecuritySettings(): Promise<SecuritySettings> {
    const settings = await this.getSettingsDocument('security')

    return {
      jwtExpiresIn: settings?.jwtExpiresIn || '30d',
      jwtRefreshGraceSeconds:
        typeof settings?.jwtRefreshGraceSeconds === 'number'
          ? settings.jwtRefreshGraceSeconds
          : 60 * 60 * 24 * 7
    }
  }

  /**
   * Save security settings
   */
  async saveSecuritySettings(settings: Partial<SecuritySettings>): Promise<boolean> {
    const existing = await this.getSettingsDocument('security')
    const merged = { ...existing, ...settings }
    return await this.saveSettingsDocument('security', merged)
  }
}
