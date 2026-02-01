import manifest from '../manifest.json'
import type {
  QRCode,
  CreateQRCodeInput,
  UpdateQRCodeInput,
  QRCodeGenerateOptions,
  QRCodeGenerateResult,
  QRCodeOperationResult,
  QRGeneratorSettings,
  ErrorCorrectionLevel
} from '../types'
import type { D1Database } from '@cloudflare/workers-types'
import { normalizeHexColor, isValidHexColor } from '../utils/color-validator'
import { validateDestinationUrl } from '../utils/url-validator'
import { getContrastWarning } from '../utils/contrast-checker'
import QRCodeLib from 'qrcode-svg'

/**
 * QR Code Generation and Management Service
 * Handles CRUD operations for QR codes and SVG generation with qrcode-svg library
 */
export class QRService {
  constructor(private db: D1Database) {}

  /**
   * Get plugin settings from the database
   */
  async getSettings(): Promise<{ status: string; data: QRGeneratorSettings }> {
    try {
      const record = await this.db
        .prepare(`SELECT settings, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (!record) {
        return {
          status: 'inactive',
          data: this.getDefaultSettings()
        }
      }

      return {
        status: (record?.status as string) || 'inactive',
        data: record?.settings ? JSON.parse(record.settings as string) : this.getDefaultSettings()
      }
    } catch (error) {
      console.error('[QRService] Error getting settings:', error)
      return {
        status: 'inactive',
        data: this.getDefaultSettings()
      }
    }
  }

  /**
   * Get default plugin settings
   */
  getDefaultSettings(): QRGeneratorSettings {
    return {
      defaultForegroundColor: '#000000',
      defaultBackgroundColor: '#ffffff',
      defaultErrorCorrection: 'M',
      defaultSize: 300
    }
  }

  /**
   * Save plugin settings to the database
   */
  async saveSettings(settings: QRGeneratorSettings): Promise<void> {
    try {
      console.log('[QRService] Saving settings for plugin:', manifest.id)
      console.log('[QRService] Settings:', JSON.stringify(settings))

      // Check if plugin row exists
      const existing = await this.db
        .prepare(`SELECT id, status FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .first()

      if (existing) {
        // Update existing row
        const result = await this.db
          .prepare(`UPDATE plugins SET settings = ?, last_updated = ? WHERE id = ?`)
          .bind(JSON.stringify(settings), Date.now(), manifest.id)
          .run()
        console.log('[QRService] Settings updated successfully')
      } else {
        // Insert new row
        const result = await this.db
          .prepare(`
            INSERT INTO plugins (id, name, display_name, description, version, author, category, status, settings, installed_at, last_updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          `)
          .bind(
            manifest.id,
            manifest.id,
            manifest.name,
            manifest.description || '',
            manifest.version || '1.0.0',
            manifest.author || 'Unknown',
            manifest.category || 'utilities',
            JSON.stringify(settings),
            Date.now(),
            Date.now()
          )
          .run()
        console.log('[QRService] Settings inserted successfully')
      }
    } catch (error) {
      console.error('[QRService] Error saving settings:', error)
      throw new Error(`Failed to save QR generator settings: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  // QR Code Generation

  /**
   * Generate QR code SVG from content with customizable options
   * Returns both raw SVG string and data URL
   */
  generate(options: QRCodeGenerateOptions): QRCodeGenerateResult {
    const {
      content,
      size = 300,
      foregroundColor = '#000000',
      backgroundColor = '#ffffff',
      errorCorrection = 'M'
    } = options

    // Validate colors
    const normalizedFg = normalizeHexColor(foregroundColor)
    const normalizedBg = normalizeHexColor(backgroundColor)

    if (!normalizedFg || !normalizedBg) {
      throw new Error('Invalid hex color format. Use #RRGGBB or #RGB format.')
    }

    // Generate QR code using qrcode-svg library
    // padding: 4 provides the required 4-module quiet zone per ISO 18004
    const qr = new QRCodeLib({
      content: content,
      padding: 4,
      width: size,
      height: size,
      color: normalizedFg,
      background: normalizedBg,
      ecl: errorCorrection as 'L' | 'M' | 'Q' | 'H'
    })

    const svg = qr.svg()

    // Create data URL for direct embedding
    const dataUrl = `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`

    return {
      svg,
      dataUrl
    }
  }

  // CRUD Operations

  /**
   * Create a new QR code with validation
   */
  async create(input: CreateQRCodeInput, userId: string): Promise<QRCodeOperationResult> {
    try {
      // Validate destination URL
      const urlValidation = validateDestinationUrl(input.destinationUrl)
      if (!urlValidation.valid) {
        return {
          success: false,
          qrCode: undefined,
          error: urlValidation.error
        }
      }

      // Get default settings
      const { data: settings } = await this.getSettings()

      // Apply defaults
      const foregroundColor = input.foregroundColor ?? settings.defaultForegroundColor
      const backgroundColor = input.backgroundColor ?? settings.defaultBackgroundColor
      const errorCorrection = input.errorCorrection ?? settings.defaultErrorCorrection
      const size = input.size ?? settings.defaultSize

      // Validate and normalize colors
      const normalizedFg = normalizeHexColor(foregroundColor)
      const normalizedBg = normalizeHexColor(backgroundColor)

      if (!normalizedFg) {
        return {
          success: false,
          qrCode: undefined,
          error: `Invalid foreground color: ${foregroundColor}. Use #RRGGBB or #RGB format.`
        }
      }

      if (!normalizedBg) {
        return {
          success: false,
          qrCode: undefined,
          error: `Invalid background color: ${backgroundColor}. Use #RRGGBB or #RGB format.`
        }
      }

      // Check contrast ratio
      const contrastWarning = getContrastWarning(normalizedFg, normalizedBg)

      // Generate unique ID
      const id = crypto.randomUUID()
      const now = Date.now()

      // Insert into database
      await this.db
        .prepare(`
          INSERT INTO qr_codes (
            id, name, destination_url, foreground_color, background_color,
            error_correction, size, created_by, created_at, updated_at
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          id,
          input.name ?? null,
          urlValidation.normalizedUrl!,
          normalizedFg,
          normalizedBg,
          errorCorrection,
          size,
          userId,
          now,
          now
        )
        .run()

      // Fetch the created QR code
      const qrCode = await this.getById(id)

      return {
        success: true,
        qrCode: qrCode!,
        error: undefined,
        warning: contrastWarning ?? undefined
      }
    } catch (error) {
      console.error('[QRService] Error creating QR code:', error)
      return {
        success: false,
        qrCode: undefined,
        error: `Failed to create QR code: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Get QR code by ID
   */
  async getById(id: string): Promise<QRCode | null> {
    try {
      const row = await this.db
        .prepare(`
          SELECT
            id, name, destination_url, foreground_color, background_color,
            error_correction, size, created_by, created_at, updated_at, deleted_at
          FROM qr_codes
          WHERE id = ? AND deleted_at IS NULL
        `)
        .bind(id)
        .first()

      if (!row) {
        return null
      }

      return this.mapRowToQRCode(row)
    } catch (error) {
      console.error('[QRService] Error getting QR code by ID:', error)
      return null
    }
  }

  /**
   * List all QR codes with optional pagination
   */
  async list(options?: { limit?: number; offset?: number; search?: string }): Promise<QRCode[]> {
    try {
      const limit = options?.limit ?? 50
      const offset = options?.offset ?? 0
      const search = options?.search

      let query = `
        SELECT
          id, name, destination_url, foreground_color, background_color,
          error_correction, size, created_by, created_at, updated_at, deleted_at
        FROM qr_codes
        WHERE deleted_at IS NULL
      `

      const bindings: any[] = []

      if (search) {
        query += ` AND (name LIKE ? OR destination_url LIKE ?)`
        const searchPattern = `%${search}%`
        bindings.push(searchPattern, searchPattern)
      }

      query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
      bindings.push(limit, offset)

      const result = await this.db.prepare(query).bind(...bindings).all()

      return result.results.map(row => this.mapRowToQRCode(row))
    } catch (error) {
      console.error('[QRService] Error listing QR codes:', error)
      return []
    }
  }

  /**
   * Count QR codes (for pagination)
   */
  async count(options?: { search?: string }): Promise<number> {
    try {
      let query = `SELECT COUNT(*) as count FROM qr_codes WHERE deleted_at IS NULL`
      const bindings: any[] = []

      if (options?.search) {
        query += ` AND (name LIKE ? OR destination_url LIKE ?)`
        const searchPattern = `%${options.search}%`
        bindings.push(searchPattern, searchPattern)
      }

      const result = await this.db.prepare(query).bind(...bindings).first()

      return (result?.count as number) ?? 0
    } catch (error) {
      console.error('[QRService] Error counting QR codes:', error)
      return 0
    }
  }

  /**
   * Update an existing QR code
   */
  async update(id: string, input: UpdateQRCodeInput, userId?: string): Promise<QRCodeOperationResult> {
    try {
      // Fetch existing QR code
      const existing = await this.getById(id)
      if (!existing) {
        return {
          success: false,
          qrCode: undefined,
          error: 'QR code not found'
        }
      }

      // Validate destination URL if provided
      if (input.destinationUrl) {
        const urlValidation = validateDestinationUrl(input.destinationUrl)
        if (!urlValidation.valid) {
          return {
            success: false,
            qrCode: undefined,
            error: urlValidation.error
          }
        }
      }

      // Build update query dynamically based on provided fields
      const updates: string[] = []
      const bindings: any[] = []

      if (input.name !== undefined) {
        updates.push('name = ?')
        bindings.push(input.name)
      }

      if (input.destinationUrl !== undefined) {
        const urlValidation = validateDestinationUrl(input.destinationUrl)
        updates.push('destination_url = ?')
        bindings.push(urlValidation.normalizedUrl!)
      }

      if (input.foregroundColor !== undefined) {
        const normalized = normalizeHexColor(input.foregroundColor)
        if (!normalized) {
          return {
            success: false,
            qrCode: undefined,
            error: `Invalid foreground color: ${input.foregroundColor}`
          }
        }
        updates.push('foreground_color = ?')
        bindings.push(normalized)
      }

      if (input.backgroundColor !== undefined) {
        const normalized = normalizeHexColor(input.backgroundColor)
        if (!normalized) {
          return {
            success: false,
            qrCode: undefined,
            error: `Invalid background color: ${input.backgroundColor}`
          }
        }
        updates.push('background_color = ?')
        bindings.push(normalized)
      }

      if (input.errorCorrection !== undefined) {
        updates.push('error_correction = ?')
        bindings.push(input.errorCorrection)
      }

      if (input.size !== undefined) {
        updates.push('size = ?')
        bindings.push(input.size)
      }

      // Always update updated_at
      updates.push('updated_at = ?')
      bindings.push(Date.now())

      // Add ID to bindings
      bindings.push(id)

      if (updates.length === 1) {
        // Only updated_at would change, nothing to do
        return {
          success: true,
          qrCode: existing,
          error: undefined
        }
      }

      // Execute update
      await this.db
        .prepare(`UPDATE qr_codes SET ${updates.join(', ')} WHERE id = ?`)
        .bind(...bindings)
        .run()

      // Fetch updated QR code
      const updated = await this.getById(id)

      // Check contrast ratio if colors were updated
      let contrastWarning: string | undefined
      if (updated && (input.foregroundColor || input.backgroundColor)) {
        const warning = getContrastWarning(updated.foregroundColor, updated.backgroundColor)
        contrastWarning = warning ?? undefined
      }

      return {
        success: true,
        qrCode: updated!,
        error: undefined,
        warning: contrastWarning
      }
    } catch (error) {
      console.error('[QRService] Error updating QR code:', error)
      return {
        success: false,
        qrCode: undefined,
        error: `Failed to update QR code: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Delete a QR code (soft delete - sets deleted_at timestamp)
   */
  async delete(id: string): Promise<QRCodeOperationResult> {
    try {
      const now = Date.now()
      const result = await this.db
        .prepare(`UPDATE qr_codes SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`)
        .bind(now, id)
        .run()

      if (result.meta.changes > 0) {
        return {
          success: true,
          qrCode: undefined,
          error: undefined
        }
      } else {
        return {
          success: false,
          qrCode: undefined,
          error: 'QR code not found'
        }
      }
    } catch (error) {
      console.error('[QRService] Error deleting QR code:', error)
      return {
        success: false,
        qrCode: undefined,
        error: `Failed to delete QR code: ${error instanceof Error ? error.message : String(error)}`
      }
    }
  }

  /**
   * Map database row to QRCode type
   * @internal Helper method for type conversion
   */
  private mapRowToQRCode(row: any): QRCode {
    return {
      id: row.id as string,
      name: row.name as string | null,
      destinationUrl: row.destination_url as string,
      foregroundColor: row.foreground_color as string,
      backgroundColor: row.background_color as string,
      errorCorrection: row.error_correction as ErrorCorrectionLevel,
      size: row.size as number,
      createdBy: row.created_by as string,
      createdAt: row.created_at as number,
      updatedAt: row.updated_at as number,
      deletedAt: row.deleted_at as number | null
    }
  }

  // Lifecycle methods

  /**
   * Install the plugin (create database entry)
   */
  async install(): Promise<void> {
    try {
      const defaultSettings = this.getDefaultSettings()
      await this.db
        .prepare(`
          INSERT INTO plugins (
            id, name, display_name, description, version, author,
            category, status, settings, installed_at, last_updated
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, 'inactive', ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET
            display_name = excluded.display_name,
            description = excluded.description,
            version = excluded.version,
            updated_at = excluded.last_updated
        `)
        .bind(
          manifest.id,
          manifest.id,
          manifest.name,
          manifest.description,
          manifest.version,
          manifest.author,
          manifest.category,
          JSON.stringify(defaultSettings),
          Date.now(),
          Date.now()
        )
        .run()
      console.log('[QRService] Plugin installed successfully')
    } catch (error) {
      console.error('[QRService] Error installing plugin:', error)
      throw new Error('Failed to install QR generator plugin')
    }
  }

  /**
   * Activate the plugin
   */
  async activate(): Promise<void> {
    try {
      await this.db
        .prepare(`
          UPDATE plugins
          SET status = 'active', last_updated = ?
          WHERE id = ?
        `)
        .bind(Date.now(), manifest.id)
        .run()
      console.log('[QRService] Plugin activated')
    } catch (error) {
      console.error('[QRService] Error activating plugin:', error)
      throw new Error('Failed to activate QR generator plugin')
    }
  }

  /**
   * Deactivate the plugin
   */
  async deactivate(): Promise<void> {
    try {
      await this.db
        .prepare(`
          UPDATE plugins
          SET status = 'inactive', last_updated = ?
          WHERE id = ?
        `)
        .bind(Date.now(), manifest.id)
        .run()
      console.log('[QRService] Plugin deactivated')
    } catch (error) {
      console.error('[QRService] Error deactivating plugin:', error)
      throw new Error('Failed to deactivate QR generator plugin')
    }
  }

  /**
   * Uninstall the plugin (remove database entry)
   */
  async uninstall(): Promise<void> {
    try {
      await this.db
        .prepare(`DELETE FROM plugins WHERE id = ?`)
        .bind(manifest.id)
        .run()
      console.log('[QRService] Plugin uninstalled')
    } catch (error) {
      console.error('[QRService] Error uninstalling plugin:', error)
      throw new Error('Failed to uninstall QR generator plugin')
    }
  }
}
